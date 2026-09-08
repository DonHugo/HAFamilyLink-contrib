"""Linux/POSIX security contract for auth-service persistence."""

from __future__ import annotations

import importlib
import json
import multiprocessing
import os
import stat
import sys
from pathlib import Path
from threading import Event, Thread, current_thread

import pytest
from app.storage.file_storage import SharedStorage
from app.storage.secure_files import (
    SecureDirectory,
    SecureFileCleanupError,
    SecureFileDurabilityError,
    SecureFileError,
)
from cryptography.fernet import Fernet
from starlette.requests import Request


def _create_storage_key_in_process(root: str, output: object) -> None:
    """Create/read one key in an independent process and return its value."""
    try:
        with SharedStorage(root) as storage:
            output.put((True, storage._encryption_key))
    except BaseException as err:  # pragma: no cover - reported in parent
        output.put((False, repr(err)))


def _hold_directory_lock(
    root: str, ready: object, release: object, output: object
) -> None:
    """Hold a cross-process directory lock until the parent releases it."""
    try:
        with SecureDirectory(root) as files:
            with files.locked():
                ready.set()
                if not release.wait(timeout=10):
                    raise TimeoutError("holder timed out waiting for release")
        output.put(("holder", True, "released"))
    except BaseException as err:  # pragma: no cover - reported in parent
        output.put(("holder", False, repr(err)))


def _wait_for_directory_lock(
    root: str, started: object, acquired: object, output: object
) -> None:
    """Report before and after attempting to acquire a directory lock."""
    try:
        with SecureDirectory(root) as files:
            started.set()
            with files.locked():
                acquired.set()
        output.put(("waiter", True, "acquired"))
    except BaseException as err:  # pragma: no cover - reported in parent
        output.put(("waiter", False, repr(err)))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _load_main(monkeypatch: pytest.MonkeyPatch, root: Path, **environment: str):
    from app import config as app_config

    monkeypatch.setattr(
        app_config, "get_config", lambda: app_config.Config(share_dir=str(root))
    )
    for name in ("API_KEY", "ADDON_MODE", "SUPERVISOR_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    sys.modules.pop("app.main", None)
    return importlib.import_module("app.main")


def test_storage_directory_created_private_under_permissive_umask(
    tmp_path: Path,
) -> None:
    root = tmp_path / "share"
    previous = os.umask(0)
    try:
        SharedStorage(root)
    finally:
        os.umask(previous)

    assert _mode(root) == 0o700
    assert _mode(root / ".key") == 0o600


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_storage_root_rejects_non_directory(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "share"
    if kind == "file":
        root.write_text("not-a-directory")
    else:
        target = tmp_path / "target"
        target.mkdir()
        root.symlink_to(target, target_is_directory=True)

    with pytest.raises(SecureFileError):
        SharedStorage(root)


def test_storage_root_rejects_symlink_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(SecureFileError):
        SecureDirectory(linked_parent / "share")

    assert not (real_parent / "share").exists()


def test_retained_root_fd_never_writes_to_replacement(tmp_path: Path) -> None:
    root = tmp_path / "share"
    files = SecureDirectory(root)
    original = tmp_path / "original"
    root.rename(original)
    root.mkdir()

    files.replace("cookies.enc", b"pinned")

    assert (original / "cookies.enc").read_bytes() == b"pinned"
    assert not (root / "cookies.enc").exists()
    files.close()


def test_close_and_context_manager_release_retained_fd(tmp_path: Path) -> None:
    with SecureDirectory(tmp_path) as files:
        descriptor = files.fileno()
        os.fstat(descriptor)

    with pytest.raises(OSError):
        os.fstat(descriptor)
    with pytest.raises(SecureFileError, match="closed"):
        files.exists_regular("cookies.enc")
    files.close()


def test_close_failure_never_retries_reused_descriptor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failed close relinquishes ownership before an FD number is reused."""
    files = SecureDirectory(tmp_path)
    descriptor = files.fileno()
    real_close = os.close

    def close_then_fail(fd: int) -> None:
        real_close(fd)
        if fd == descriptor:
            raise OSError("injected close failure after ownership loss")

    with monkeypatch.context() as close_patch:
        close_patch.setattr(os, "close", close_then_fail)
        with pytest.raises(OSError, match="injected close failure"):
            files.close()

    source = os.open(os.devnull, os.O_RDONLY)
    try:
        if source != descriptor:
            os.dup2(source, descriptor)
            real_close(source)
        os.fstat(descriptor)

        files.close()
        files.__del__()

        os.fstat(descriptor)
    finally:
        real_close(descriptor)


def test_shared_storage_close_is_idempotent_after_close_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage = SharedStorage(tmp_path)
    descriptor = storage._files.fileno()
    real_close = os.close

    def close_then_fail(fd: int) -> None:
        real_close(fd)
        if fd == descriptor:
            raise OSError("injected storage close failure")

    with monkeypatch.context() as close_patch:
        close_patch.setattr(os, "close", close_then_fail)
        with pytest.raises(OSError, match="injected storage close failure"):
            storage.close()

    storage.close()


def test_existing_valid_key_is_preserved_and_mode_repaired(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    key = Fernet.generate_key()
    key_path = tmp_path / ".key"
    key_path.write_bytes(key)
    key_path.chmod(0o666)

    storage = SharedStorage(tmp_path)

    assert storage._encryption_key == key
    assert key_path.read_bytes() == key
    assert _mode(key_path) == 0o600
    assert _mode(tmp_path) == 0o700


@pytest.mark.parametrize("content", [b"", b"x" * 43, b"x" * 45, b"x" * 44])
def test_invalid_existing_key_is_never_replaced(tmp_path: Path, content: bytes) -> None:
    key_path = tmp_path / ".key"
    key_path.write_bytes(content)

    with pytest.raises(SecureFileError):
        SharedStorage(tmp_path)

    assert key_path.read_bytes() == content


def test_key_rejects_symlink_and_fifo(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(Fernet.generate_key())
    key_path = tmp_path / ".key"
    key_path.symlink_to(target)
    with pytest.raises(OSError):
        SharedStorage(tmp_path)
    assert key_path.is_symlink()
    key_path.unlink()

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    os.mkfifo(key_path)
    with pytest.raises(SecureFileError):
        SharedStorage(tmp_path)
    assert stat.S_ISFIFO(key_path.lstat().st_mode)


def test_concurrent_key_creation_converges(tmp_path: Path) -> None:
    values: list[bytes] = []
    errors: list[BaseException] = []

    def create() -> None:
        try:
            values.append(SharedStorage(tmp_path)._encryption_key)
        except OSError as err:  # pragma: no cover - asserted below
            errors.append(err)

    threads = [Thread(target=create) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    assert len(set(values)) == 1
    assert (tmp_path / ".key").read_bytes() == values[0]
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux flock process contract")
def test_independent_process_key_creation_converges(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "real-share"
    root.mkdir()
    context = multiprocessing.get_context("fork")
    output = context.Queue()
    processes = [
        context.Process(target=_create_storage_key_in_process, args=(str(root), output))
        for _ in range(6)
    ]

    for process in processes:
        process.start()
    results = [output.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(timeout=10)
        assert not process.is_alive()
        assert process.exitcode == 0

    assert all(success for success, _ in results), results
    values = [value for _, value in results]
    assert len(set(values)) == 1
    assert (root / ".key").read_bytes() == values[0]
    assert not list(root.glob(".*.tmp"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux flock process contract")
def test_independent_processes_serialize_directory_lock(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "flock-share"
    root.mkdir()
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    started = context.Event()
    acquired = context.Event()
    output = context.Queue()
    holder = context.Process(
        target=_hold_directory_lock,
        args=(str(root), ready, release, output),
        name="secure-directory-holder",
    )
    waiter = context.Process(
        target=_wait_for_directory_lock,
        args=(str(root), started, acquired, output),
        name="secure-directory-waiter",
    )
    processes = (holder, waiter)

    try:
        holder.start()
        assert ready.wait(timeout=5), "holder did not acquire the directory lock"
        waiter.start()
        assert started.wait(timeout=5), "waiter did not begin its lock operation"
        assert not acquired.wait(timeout=0.25), (
            "waiter acquired flock before the holder released it"
        )

        release.set()
        assert acquired.wait(timeout=5), "waiter did not acquire after holder release"
        results = [output.get(timeout=5) for _ in processes]
    finally:
        release.set()
        for process in processes:
            process.join(timeout=5)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    diagnostics = {
        "results": results if "results" in locals() else [],
        "exitcodes": {process.name: process.exitcode for process in processes},
    }
    assert all(process.exitcode == 0 for process in processes), diagnostics
    assert all(success for _, success, _ in results), diagnostics


@pytest.mark.asyncio
async def test_cookie_schema_is_compatible_with_integration_file_fallback(
    tmp_path: Path,
) -> None:
    storage = SharedStorage(tmp_path)
    cookies = [{"name": "SID", "value": "secret", "domain": ".google.com"}]
    previous = os.umask(0)
    try:
        await storage.save_cookies(cookies)
    finally:
        os.umask(previous)

    encrypted = (tmp_path / "cookies.enc").read_bytes()
    payload = json.loads(Fernet(storage._encryption_key).decrypt(encrypted))
    assert payload["cookies"] == cookies
    assert payload["version"] == "1.0"
    assert "timestamp" in payload
    assert await storage.load_cookies() == cookies
    assert _mode(tmp_path / "cookies.enc") == 0o600
    assert not list(tmp_path.glob(".cookies.enc.*.tmp"))

    (tmp_path / "cookies.enc").chmod(0o666)
    assert await storage.load_cookies() == cookies
    assert _mode(tmp_path / "cookies.enc") == 0o600


@pytest.mark.asyncio
async def test_cookie_replace_failure_preserves_old_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage = SharedStorage(tmp_path)
    await storage.save_cookies([{"name": "old"}])
    old = (tmp_path / "cookies.enc").read_bytes()

    def fail_write(*_args: object) -> None:
        raise OSError("fail")

    monkeypatch.setattr(storage._files, "_write_all", fail_write)
    with pytest.raises(OSError):
        await storage.save_cookies([{"name": "new"}])

    assert (tmp_path / "cookies.enc").read_bytes() == old
    assert not list(tmp_path.glob(".cookies.enc.*.tmp"))


@pytest.mark.asyncio
async def test_cookie_publish_failure_preserves_old_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage = SharedStorage(tmp_path)
    await storage.save_cookies([{"name": "old"}])
    old = (tmp_path / "cookies.enc").read_bytes()

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError):
        await storage.save_cookies([{"name": "new"}])

    assert (tmp_path / "cookies.enc").read_bytes() == old
    assert not list(tmp_path.glob(".cookies.enc.*.tmp"))


def test_post_publish_directory_fsync_failure_is_distinct(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = SecureDirectory(tmp_path)
    real_fsync = os.fsync

    def fail_directory_fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(SecureFileDurabilityError) as raised:
        files.replace("cookies.enc", b"published")

    assert raised.value.published is True
    assert (tmp_path / "cookies.enc").read_bytes() == b"published"
    assert not list(tmp_path.glob(".cookies.enc.*.tmp"))


def test_create_once_post_publish_fsync_failure_leaves_created_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = SecureDirectory(tmp_path)
    real_fsync = os.fsync

    def fail_directory_fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(SecureFileDurabilityError) as raised:
        files.create_once("api_key", b"key", 10, lambda value: None)

    assert raised.value.published is True
    assert (tmp_path / "api_key").read_bytes() == b"key"
    assert not list(tmp_path.glob(".api_key.*.tmp"))


def test_unlink_directory_fsync_failure_reports_published(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = SecureDirectory(tmp_path)
    files.replace("cookies.enc", b"published")

    def fail_fsync(_fd: int) -> None:
        raise OSError("directory fsync failed")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(SecureFileDurabilityError) as raised:
        files.unlink("cookies.enc")

    assert raised.value.published is True
    assert not (tmp_path / "cookies.enc").exists()
    files.unlink("cookies.enc")


def test_temporary_cleanup_failure_is_reported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = SecureDirectory(tmp_path)
    real_unlink = os.unlink

    def fail_temp_unlink(path: str, *args: object, **kwargs: object) -> None:
        if path.startswith(".cookies.enc."):
            raise PermissionError("cleanup denied")
        real_unlink(path, *args, **kwargs)

    def fail_write(*_args: object) -> None:
        raise OSError("write failed")

    monkeypatch.setattr(os, "unlink", fail_temp_unlink)
    monkeypatch.setattr(files, "_write_all", fail_write)
    with pytest.raises(SecureFileCleanupError) as raised:
        files.replace("cookies.enc", b"new")

    assert raised.value.published is False
    assert isinstance(raised.value.__cause__, OSError)
    assert list(tmp_path.glob(".cookies.enc.*.tmp"))


def test_failed_write_cleanup_fsync_failure_reports_unpublished(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = SecureDirectory(tmp_path)
    operation_error = OSError("write failed")
    real_fsync = os.fsync

    def fail_write(*_args: object) -> None:
        raise operation_error

    def fail_directory_fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("cleanup directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(files, "_write_all", fail_write)
    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(SecureFileDurabilityError) as raised:
        files.replace("cookies.enc", b"new")

    assert raised.value.published is False
    assert raised.value.__cause__ is operation_error
    assert not list(tmp_path.glob(".cookies.enc.*.tmp"))


@pytest.mark.parametrize("failure", ["fstat", "identity-check", "close-current"])
def test_directory_walk_closes_untransferred_next_fd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    root = tmp_path / "share"
    root.mkdir()
    real_open = os.open
    real_fstat = os.fstat
    real_close = os.close
    target_fd: int | None = None
    parent_fd: int | None = None
    closed_fds: list[int] = []
    current_close_failed = False

    def track_open(path: str, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal target_fd, parent_fd
        fd = real_open(path, flags, *args, **kwargs)
        if path == root.name:
            target_fd = fd
            parent_fd = kwargs.get("dir_fd")
        return fd

    def fail_or_mismatch_fstat(fd: int):
        info = real_fstat(fd)
        if fd != target_fd:
            return info
        if failure == "fstat":
            raise OSError("injected next descriptor fstat failure")
        if failure == "identity-check":

            class RaisingIdentity:
                st_dev = info.st_dev

                @property
                def st_ino(self) -> int:
                    raise OSError("injected identity comparison failure")

            return RaisingIdentity()
        return info

    def fail_current_close(fd: int) -> None:
        nonlocal current_close_failed
        if failure == "close-current" and fd == parent_fd and not current_close_failed:
            current_close_failed = True
            real_close(fd)
            raise OSError("injected current descriptor close failure")
        if fd == target_fd:
            closed_fds.append(fd)
        real_close(fd)

    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "fstat", fail_or_mismatch_fstat)
    monkeypatch.setattr(os, "close", fail_current_close)
    with pytest.raises((OSError, SecureFileError)):
        SecureDirectory(root)

    assert target_fd is not None
    assert target_fd in closed_fds


def test_fchmod_failure_closes_and_removes_own_temporary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = SecureDirectory(tmp_path)
    temporary_fd = -1

    def fail_fchmod(fd: int, _mode: int) -> None:
        nonlocal temporary_fd
        temporary_fd = fd
        raise OSError("fchmod failed")

    monkeypatch.setattr(os, "fchmod", fail_fchmod)
    with pytest.raises(OSError, match="fchmod failed"):
        files.replace("cookies.enc", b"new")

    with pytest.raises(OSError):
        os.fstat(temporary_fd)
    assert not list(tmp_path.glob(".cookies.enc.*.tmp"))


def test_created_directory_parent_fsync_failure_is_published(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "new-parent" / "share"

    def fail_fsync(_fd: int) -> None:
        raise OSError("parent fsync failed")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(SecureFileDurabilityError) as raised:
        SecureDirectory(root)

    assert raised.value.published is True
    assert tmp_path.joinpath("new-parent").is_dir()
    assert not root.exists()


@pytest.mark.asyncio
async def test_cookie_symlink_and_fifo_are_rejected(tmp_path: Path) -> None:
    storage = SharedStorage(tmp_path)
    cookie_path = tmp_path / "cookies.enc"
    target = tmp_path / "target"
    target.write_bytes(b"unchanged")
    cookie_path.symlink_to(target)
    assert not await storage.check_exists()
    with pytest.raises(OSError):
        await storage.load_cookies()
    with pytest.raises(SecureFileError):
        await storage.save_cookies([])
    assert target.read_bytes() == b"unchanged"
    await storage.clear_cookies()
    assert not cookie_path.exists()
    assert target.read_bytes() == b"unchanged"

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    os.mkfifo(cookie_path)
    assert not await storage.check_exists()
    with pytest.raises(SecureFileError):
        await storage.load_cookies()


@pytest.mark.asyncio
async def test_oversized_cookie_file_is_rejected(tmp_path: Path) -> None:
    storage = SharedStorage(tmp_path)
    cookie_path = tmp_path / "cookies.enc"
    with cookie_path.open("wb") as output:
        output.truncate(16 * 1024 * 1024 + 1)

    with pytest.raises(SecureFileError):
        await storage.load_cookies()


@pytest.mark.asyncio
async def test_corrupt_cleanup_does_not_delete_replacement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage = SharedStorage(tmp_path)
    cookie_path = tmp_path / "cookies.enc"
    cookie_path.write_bytes(b"invalid-token")

    def unexpected_unlink(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("corrupt-cookie handling must not unlink")

    monkeypatch.setattr(storage._files, "unlink", unexpected_unlink)
    with pytest.raises(FileNotFoundError):
        await storage.load_cookies()

    assert cookie_path.read_bytes() == b"invalid-token"

    replacement = [{"name": "replacement"}]
    await storage.save_cookies(replacement)
    assert await storage.load_cookies() == replacement


def test_separate_instances_serialize_operations(tmp_path: Path) -> None:
    first = SecureDirectory(tmp_path)
    second = SecureDirectory(tmp_path)
    entered = Event()
    release = Event()

    def hold_first_lock() -> None:
        with first.locked():
            entered.set()
            release.wait(timeout=5)

    holder = Thread(target=hold_first_lock)
    holder.start()
    assert entered.wait(timeout=5)

    completed = Event()

    def use_second_instance() -> None:
        second.replace("cookies.enc", b"serialized")
        completed.set()

    waiter = Thread(target=use_second_instance)
    waiter.start()
    assert not completed.wait(timeout=0.1)
    release.set()
    holder.join(timeout=5)
    waiter.join(timeout=5)

    assert completed.is_set()
    assert (tmp_path / "cookies.enc").read_bytes() == b"serialized"
    first.close()
    second.close()


def test_cross_instance_nested_lock_has_no_lock_order_deadlock(tmp_path: Path) -> None:
    first = SecureDirectory(tmp_path)
    second = SecureDirectory(tmp_path)
    first_entered = Event()
    opposing_started = Event()
    nested_entered = Event()
    errors: list[BaseException] = []

    class SignalingLock:
        def __init__(self, lock: object) -> None:
            self._lock = lock

        def acquire(self) -> bool:
            if current_thread().name == "opposing":
                opposing_started.set()
            return self._lock.acquire()

        def release(self) -> None:
            self._lock.release()

    shared_lock = SignalingLock(first._operation_lock)
    first._operation_lock = shared_lock
    second._operation_lock = shared_lock

    def nested_owner() -> None:
        try:
            with first.locked():
                first_entered.set()
                assert opposing_started.wait(timeout=2)
                with second.locked():
                    nested_entered.set()
        except BaseException as err:  # pragma: no cover - asserted below
            errors.append(err)

    def opposing_owner() -> None:
        try:
            assert first_entered.wait(timeout=2)
            with second.locked():
                pass
        except BaseException as err:  # pragma: no cover - asserted below
            errors.append(err)

    nested = Thread(target=nested_owner)
    opposing = Thread(target=opposing_owner, name="opposing")
    nested.start()
    opposing.start()
    nested.join(timeout=5)
    opposing.join(timeout=5)

    assert not nested.is_alive()
    assert not opposing.is_alive()
    assert not errors
    first.close()
    second.close()


def test_addon_api_key_concurrent_creation_converges(tmp_path: Path) -> None:
    files = SecureDirectory(tmp_path)
    values: list[bytes] = []

    def validate(value: bytes) -> None:
        assert value.decode().strip()

    def create() -> None:
        value, _ = files.create_once(
            "api_key", os.urandom(32).hex().encode(), 4096, validate
        )
        values.append(value)

    threads = [Thread(target=create) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(set(values)) == 1
    assert (tmp_path / "api_key").read_bytes() == values[0]


def test_explicit_api_key_takes_precedence_without_persistence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    main = _load_main(monkeypatch, tmp_path, API_KEY="explicit-key", ADDON_MODE="1")
    assert main._COOKIE_API_KEY == "explicit-key"
    assert not (tmp_path / "api_key").exists()


def test_addon_preserves_api_key_and_repairs_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key_path = tmp_path / "api_key"
    key_path.write_text("existing-key", encoding="utf-8")
    key_path.chmod(0o666)

    main = _load_main(monkeypatch, tmp_path, ADDON_MODE="1")

    assert main._COOKIE_API_KEY == "existing-key"
    assert key_path.read_bytes() == b"existing-key"
    assert _mode(key_path) == 0o600


def test_standalone_without_api_key_remains_open_without_persistence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    main = _load_main(monkeypatch, tmp_path)
    assert main._COOKIE_API_KEY is None
    assert not (tmp_path / "api_key").exists()


@pytest.mark.parametrize(
    "content",
    [b"", b" " * 4, b"x" * 4097, b"\xff", "clé".encode(), b"key\ninside"],
)
def test_addon_rejects_invalid_existing_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: bytes
) -> None:
    tmp_path.mkdir(exist_ok=True)
    key_path = tmp_path / "api_key"
    key_path.write_bytes(content)

    with pytest.raises(Exception, match="credential setup failed"):
        _load_main(monkeypatch, tmp_path, ADDON_MODE="1")
    assert key_path.read_bytes() == content


@pytest.mark.parametrize("value", ["clé", "key\ninside", "\x7fkey", "x" * 4097])
def test_rejects_invalid_environment_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    with pytest.raises(Exception, match="credential setup failed"):
        _load_main(monkeypatch, tmp_path, API_KEY=value)


def test_valid_ascii_punctuation_api_key_is_compatible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = "Az09-._~!$&'()*+,;=:@/?[]{}"
    main = _load_main(monkeypatch, tmp_path, API_KEY=key)
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/auth/start",
            "query_string": b"",
            "headers": [(b"x-api-key", key.encode("ascii"))],
        }
    )

    assert main._verify_api_key(request) is None


@pytest.mark.parametrize("key", ["clé", "key\ninside", "\x7fkey"])
def test_request_unicode_and_controls_return_403(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, key: str
) -> None:
    main = _load_main(monkeypatch, tmp_path, API_KEY="expected-key")
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/auth/start",
            "query_string": f"api_key={key}".encode("utf-8"),
            "headers": [],
        }
    )

    with pytest.raises(Exception) as raised:
        main._verify_api_key(request)
    assert raised.value.status_code == 403


def test_addon_rejects_api_key_symlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "target"
    target.write_text("target-key", encoding="utf-8")
    key_path = tmp_path / "api_key"
    key_path.symlink_to(target)

    with pytest.raises(Exception, match="credential setup failed"):
        _load_main(monkeypatch, tmp_path, ADDON_MODE="1")

    assert key_path.is_symlink()
    assert target.read_text(encoding="utf-8") == "target-key"


def test_file_and_directory_fsync_are_used(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[int] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        calls.append(stat.S_IFMT(os.fstat(fd).st_mode))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", record)
    files = SecureDirectory(tmp_path)
    files.replace("cookies.enc", b"ciphertext")

    assert stat.S_IFREG in calls
    assert stat.S_IFDIR in calls


def test_complete_write_retries_interrupts_and_short_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    files = SecureDirectory(tmp_path)
    real_write = os.write
    calls = 0

    def interrupted_short_write(fd: int, content: memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InterruptedError
        return real_write(fd, content[:3])

    monkeypatch.setattr(os, "write", interrupted_short_write)
    files.replace("cookies.enc", b"complete-ciphertext")

    assert (tmp_path / "cookies.enc").read_bytes() == b"complete-ciphertext"
    assert calls > 2
