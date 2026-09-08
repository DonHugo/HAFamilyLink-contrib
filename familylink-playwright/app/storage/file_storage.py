"""File-based storage for cookies with encryption."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Self

from cryptography.fernet import Fernet, InvalidToken

from app.privacy import get_privacy_logger
from app.storage.secure_files import SecureDirectory, SecureFileError

_LOGGER = get_privacy_logger(__name__)
_KEY_SIZE = 44
_COOKIE_MAX_SIZE = 16 * 1024 * 1024


class SharedStorage:
    """Manages cookie storage in Home Assistant shared directory."""

    def __init__(self, share_dir: str = "/share/familylink"):
        """Initialize storage manager."""
        self.share_dir = Path(share_dir)
        self.storage_path = self.share_dir / "cookies.enc"
        self.key_file = self.share_dir / ".key"
        self._files = SecureDirectory(self.share_dir)
        try:
            self._encryption_key = self._get_encryption_key()
        except BaseException:
            try:
                self._files.close()
            except OSError:
                pass
            raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Release the retained storage directory descriptor."""
        self._files.close()

    def _get_encryption_key(self) -> bytes:
        """Get or create encryption key."""

        def validate(key: bytes) -> None:
            if len(key) != _KEY_SIZE:
                raise SecureFileError("Encryption key has an invalid size")
            try:
                Fernet(key)
            except (TypeError, ValueError) as err:
                raise SecureFileError("Encryption key is invalid") from err

        key, created = self._files.create_once(
            ".key", Fernet.generate_key(), _KEY_SIZE, validate
        )
        if created:
            _LOGGER.info("Generated new encryption key")
        return key

    async def save_cookies(self, cookies: list[dict[str, Any]]) -> None:
        """Save cookies to encrypted file."""
        try:
            with self._files.locked():
                data = {
                    "cookies": cookies,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0",
                }
                fernet = Fernet(self._encryption_key)
                json_data = json.dumps(data, indent=2)
                encrypted = fernet.encrypt(json_data.encode())
                self._files.replace("cookies.enc", encrypted)

            _LOGGER.info(f"Saved {len(cookies)} cookies to shared storage")

        except Exception as e:
            _LOGGER.error(f"Failed to save cookies: {e}")
            raise

    async def load_cookies(self) -> list[dict[str, Any]]:
        """Load cookies from encrypted file."""
        try:
            with self._files.locked():
                encrypted, _ = self._files.read("cookies.enc", _COOKIE_MAX_SIZE)
                fernet = Fernet(self._encryption_key)
                decrypted = fernet.decrypt(encrypted)
                data = json.loads(decrypted.decode())
                cookies = data.get("cookies", [])

            _LOGGER.info(f"Loaded {len(cookies)} cookies from shared storage")
            return cookies

        except InvalidToken:
            _LOGGER.error(
                "Cookie file is corrupted or encryption key has changed. "
                "It was retained for safe atomic replacement; please re-authenticate."
            )
            raise FileNotFoundError(
                "Cookies are corrupted. Please re-authenticate to replace them."
            )

        except Exception as e:
            _LOGGER.error(f"Failed to load cookies: {e}")
            raise

    async def clear_cookies(self) -> None:
        """Remove stored cookies."""
        with self._files.locked():
            self._files.unlink("cookies.enc")
        _LOGGER.info("Cleared stored cookies")

    async def check_exists(self) -> bool:
        """Check if cookies exist."""
        with self._files.locked():
            return self._files.exists_regular("cookies.enc")
