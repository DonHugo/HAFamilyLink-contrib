"""Fail-closed POSIX persistence for authentication secrets."""

from __future__ import annotations

import errno
import fcntl
import os
import secrets
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Self

FILE_MODE = 0o600
DIRECTORY_MODE = 0o700

_LOCKS_GUARD = threading.Lock()
_IN_PROCESS_LOCKS: dict[tuple[int, int], threading.RLock] = {}
_PROCESS_LOCK_DEPTH = threading.local()


class SecureFileError(OSError):
    """Raised when a storage path does not satisfy the security contract."""


class SecureFileDurabilityError(SecureFileError):
    """Raised when publication succeeded but directory durability is unknown."""

    def __init__(self, message: str, *, published: bool) -> None:
        super().__init__(message)
        self.published = published


class SecureFileCleanupError(SecureFileError):
    """Raised when a private temporary file could not be removed."""

    def __init__(self, message: str, *, published: bool) -> None:
        super().__init__(message)
        self.published = published


def _inode_lock(identity: tuple[int, int]) -> threading.RLock:
    """Return the process-wide lock shared by handles to one directory inode."""
    with _LOCKS_GUARD:
        return _IN_PROCESS_LOCKS.setdefault(identity, threading.RLock())


class SecureDirectory:
    """Operate on fixed children beneath one retained directory descriptor."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        if self.path == Path(self.path.anchor):
            raise SecureFileError("Storage root cannot be the filesystem root")
        self._state_lock = threading.RLock()
        self._local = threading.local()
        self._directory_fd = self._open_or_create_directory(self.path)
        try:
            opened = os.fstat(self._directory_fd)
            if not stat.S_ISDIR(opened.st_mode):
                raise SecureFileError("Storage root is not a directory")
            os.fchmod(self._directory_fd, DIRECTORY_MODE)
            self._identity = (opened.st_dev, opened.st_ino)
            self._operation_lock = _inode_lock(self._identity)
        except BaseException:
            directory_fd = self._directory_fd
            self._directory_fd = -1
            try:
                os.close(directory_fd)
            except OSError:
                pass
            raise

    @staticmethod
    def _directory_flags() -> int:
        return os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW

    @classmethod
    def _open_or_create_directory(cls, path: Path) -> int:
        """Walk and pin ``path`` without following any component symlink."""
        current_fd: int | None = os.open(os.sep, cls._directory_flags())
        try:
            for component in path.parts[1:]:
                if component in {"", ".", ".."}:
                    raise SecureFileError("Invalid storage root component")
                try:
                    info = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                except FileNotFoundError:
                    created = False
                    try:
                        os.mkdir(component, DIRECTORY_MODE, dir_fd=current_fd)
                        created = True
                    except FileExistsError:
                        pass
                    if created:
                        try:
                            os.fsync(current_fd)
                        except OSError as err:
                            raise SecureFileDurabilityError(
                                "Storage directory was created but parent fsync failed",
                                published=True,
                            ) from err
                    info = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise SecureFileError(
                        f"Storage root component is not a real directory: {component}"
                    )
                next_fd: int | None = None
                try:
                    try:
                        next_fd = os.open(
                            component, cls._directory_flags(), dir_fd=current_fd
                        )
                    except OSError as err:
                        raise SecureFileError(
                            f"Storage root component changed while opening: {component}"
                        ) from err
                    opened = os.fstat(next_fd)
                    if (opened.st_dev, opened.st_ino) != (
                        info.st_dev,
                        info.st_ino,
                    ):
                        raise SecureFileError("Storage root changed while opening")

                    # Relinquish ownership before close: an error may still mean the
                    # kernel closed the descriptor, so retrying could close a reused
                    # descriptor belonging to an unrelated resource.
                    previous_fd = current_fd
                    current_fd = None
                    os.close(previous_fd)
                    current_fd = next_fd
                    next_fd = None
                except BaseException:
                    if next_fd is not None:
                        owned_fd = next_fd
                        next_fd = None
                        try:
                            os.close(owned_fd)
                        except OSError:
                            pass
                    raise
            result = current_fd
            current_fd = None
            return result
        except BaseException:
            if current_fd is not None:
                owned_fd = current_fd
                current_fd = None
                try:
                    os.close(owned_fd)
                except OSError:
                    # Preserve the traversal failure. A failed close may mean the
                    # descriptor was already closed, so retrying cannot be made safe.
                    pass
            raise

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except (OSError, RuntimeError):
            return

    def fileno(self) -> int:
        """Return the retained descriptor, primarily for lifecycle inspection."""
        with self._state_lock:
            self._require_open()
            return self._directory_fd

    def close(self) -> None:
        """Close the retained root descriptor once no operation is active."""
        with self._state_lock:
            if getattr(self._local, "depth", 0):
                raise RuntimeError("Cannot close SecureDirectory during an operation")
            directory_fd = getattr(self, "_directory_fd", -1)
            if directory_fd >= 0:
                self._directory_fd = -1
                os.close(directory_fd)

    def _require_open(self) -> None:
        if self._directory_fd < 0:
            raise SecureFileError("SecureDirectory is closed")

    @contextmanager
    def locked(self) -> Iterator[int]:
        """Serialize a complete cooperating operation and yield a pinned-root dup."""
        depth = getattr(self._local, "depth", 0)
        if depth:
            self._local.depth = depth + 1
            try:
                yield self._local.fd
            finally:
                self._local.depth -= 1
            return

        with self._state_lock:
            self._require_open()
            lock_fd = os.dup(self._directory_fd)

        lock_acquired = False
        file_lock_acquired = False
        process_depth_recorded = False
        process_depths: dict[tuple[int, int], int] | None = None
        try:
            self._operation_lock.acquire()
            lock_acquired = True
            process_depths = getattr(_PROCESS_LOCK_DEPTH, "depths", {})
            process_depth = process_depths.get(self._identity, 0)
            if not process_depth:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                file_lock_acquired = True
            process_depths[self._identity] = process_depth + 1
            _PROCESS_LOCK_DEPTH.depths = process_depths
            process_depth_recorded = True
            self._local.depth = 1
            self._local.fd = lock_fd
            try:
                yield lock_fd
            finally:
                self._local.depth = 0
                del self._local.fd
                remaining = process_depths[self._identity] - 1
                if remaining:
                    process_depths[self._identity] = remaining
                else:
                    del process_depths[self._identity]
                process_depth_recorded = False
                if file_lock_acquired:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    file_lock_acquired = False
        finally:
            try:
                if process_depth_recorded and process_depths is not None:
                    remaining = process_depths[self._identity] - 1
                    if remaining:
                        process_depths[self._identity] = remaining
                    else:
                        del process_depths[self._identity]
                if file_lock_acquired:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                try:
                    os.close(lock_fd)
                finally:
                    if lock_acquired:
                        self._operation_lock.release()

    @staticmethod
    def _validate_name(name: str) -> None:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise ValueError("Secure file name must be one fixed child name")

    @staticmethod
    def _write_all(fd: int, content: bytes) -> None:
        view = memoryview(content)
        while view:
            try:
                written = os.write(fd, view)
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError(errno.EIO, "Short write while persisting secure file")
            view = view[written:]

    @staticmethod
    def _read_all(fd: int, maximum: int) -> bytes:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            try:
                chunk = os.read(fd, min(remaining, 64 * 1024))
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise SecureFileError("Secure file exceeds maximum size")
        return data

    def read(self, name: str, maximum: int) -> tuple[bytes, tuple[int, int]]:
        """Read one bounded regular file without following links."""
        self._validate_name(name)
        with self.locked() as directory_fd:
            return self._read_locked(directory_fd, name, maximum)

    def _read_locked(
        self, directory_fd: int, name: str, maximum: int
    ) -> tuple[bytes, tuple[int, int]]:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
        fd = os.open(name, flags, dir_fd=directory_fd)
        with _OwnedFd(fd):
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SecureFileError(f"Secure path is not a regular file: {name}")
            os.fchmod(fd, FILE_MODE)
            if info.st_size > maximum:
                raise SecureFileError("Secure file exceeds maximum size")
            return self._read_all(fd, maximum), (info.st_dev, info.st_ino)

    def exists_regular(self, name: str) -> bool:
        """Return whether a child is an existing regular file."""
        self._validate_name(name)
        with self.locked() as directory_fd:
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            return stat.S_ISREG(info.st_mode)

    def create_once(
        self,
        name: str,
        content: bytes,
        maximum: int,
        validator: Callable[[bytes], None],
    ) -> tuple[bytes, bool]:
        """Publish content without overwrite, converging on a concurrent winner."""
        self._validate_name(name)
        with self.locked() as directory_fd:
            try:
                existing, _ = self._read_locked(directory_fd, name, maximum)
            except FileNotFoundError:
                pass
            else:
                validator(existing)
                return existing, False

            validator(content)
            temporary = f".{name}.{secrets.token_hex(16)}.tmp"
            fd = self._create_temporary(directory_fd, temporary)
            published = False
            try:
                with _OwnedFd(fd):
                    self._write_all(fd, content)
                    os.fsync(fd)
                try:
                    os.link(
                        temporary,
                        name,
                        src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    published = True
                except FileExistsError:
                    pass
            except BaseException as err:
                self._cleanup_temporary(directory_fd, temporary, False, err)
                raise

            self._cleanup_temporary(directory_fd, temporary, published, None)
            try:
                os.fsync(directory_fd)
            except OSError as err:
                raise SecureFileDurabilityError(
                    "Secure file was published but directory fsync failed",
                    published=published,
                ) from err

            result, _ = self._read_locked(directory_fd, name, maximum)
            validator(result)
            if published and result != content:
                raise SecureFileError("Published secure file changed unexpectedly")
            return result, published

    def replace(self, name: str, content: bytes) -> None:
        """Atomically replace a regular destination with private content."""
        self._validate_name(name)
        with self.locked() as directory_fd:
            self._require_regular_or_missing(directory_fd, name)
            temporary = f".{name}.{secrets.token_hex(16)}.tmp"
            fd = self._create_temporary(directory_fd, temporary)
            published = False
            try:
                with _OwnedFd(fd):
                    self._write_all(fd, content)
                    os.fsync(fd)
                self._require_regular_or_missing(directory_fd, name)
                os.replace(
                    temporary,
                    name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                published = True
            except BaseException as err:
                self._cleanup_temporary(directory_fd, temporary, False, err)
                raise

            try:
                os.fsync(directory_fd)
            except OSError as err:
                raise SecureFileDurabilityError(
                    "Secure file was published but directory fsync failed",
                    published=published,
                ) from err

    @staticmethod
    def _create_temporary(directory_fd: int, temporary: str) -> int:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(temporary, flags, FILE_MODE, dir_fd=directory_fd)
        try:
            identity = os.fstat(fd)
            os.fchmod(fd, FILE_MODE)
        except BaseException as operation_error:
            cleanup_error: OSError | None = None
            unlinked = False
            owned_fd = fd
            fd = -1
            try:
                os.close(owned_fd)
            except OSError as err:
                cleanup_error = err

            try:
                entry = os.stat(temporary, dir_fd=directory_fd, follow_symlinks=False)
                if "identity" not in locals() or (
                    entry.st_dev,
                    entry.st_ino,
                ) != (identity.st_dev, identity.st_ino):
                    raise SecureFileCleanupError(
                        "Private temporary file changed unexpectedly",
                        published=False,
                    )
                os.unlink(temporary, dir_fd=directory_fd)
                unlinked = True
            except SecureFileCleanupError as err:
                if cleanup_error is None:
                    cleanup_error = err
            except OSError as err:
                if cleanup_error is None:
                    cleanup_error = err

            if unlinked:
                try:
                    os.fsync(directory_fd)
                except OSError:
                    durability = SecureFileDurabilityError(
                        "Private temporary cleanup parent fsync failed",
                        published=False,
                    )
                    if cleanup_error is not None:
                        durability.add_note(
                            "A descriptor cleanup error also occurred before the "
                            "temporary unlink was made durable"
                        )
                    raise durability from cleanup_error or operation_error
            if cleanup_error is not None:
                raise SecureFileCleanupError(
                    "Private temporary file cleanup failed", published=False
                ) from cleanup_error
            raise operation_error
        return fd

    @staticmethod
    def _cleanup_temporary(
        directory_fd: int,
        temporary: str,
        published: bool,
        operation_error: BaseException | None,
    ) -> None:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            if published:
                return
            cleanup = SecureFileCleanupError(
                "Private temporary file changed unexpectedly", published=published
            )
            if operation_error is not None:
                raise cleanup from operation_error
            raise cleanup
        except OSError as err:
            cleanup = SecureFileCleanupError(
                "Private temporary file cleanup failed", published=published
            )
            if operation_error is not None:
                raise cleanup from operation_error
            raise cleanup from err

        try:
            os.fsync(directory_fd)
        except OSError as err:
            durability = SecureFileDurabilityError(
                "Private temporary cleanup parent fsync failed",
                published=published,
            )
            if operation_error is not None:
                raise durability from operation_error
            raise durability from err

    @staticmethod
    def _require_regular_or_missing(directory_fd: int, name: str) -> None:
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode):
            raise SecureFileError(f"Secure destination is not a regular file: {name}")

    def unlink(self, name: str) -> None:
        """Unlink the directory entry itself without following it."""
        self._validate_name(name)
        with self.locked() as directory_fd:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError:
                return
            try:
                os.fsync(directory_fd)
            except OSError as err:
                raise SecureFileDurabilityError(
                    "Secure file was unlinked but directory fsync failed",
                    published=True,
                ) from err


class _OwnedFd:
    """Small context manager that closes one owned file descriptor."""

    def __init__(self, fd: int) -> None:
        self.fd = fd

    def __enter__(self) -> int:
        return self.fd

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object,
    ) -> None:
        fd = self.fd
        self.fd = -1
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                if exception_type is None:
                    raise
