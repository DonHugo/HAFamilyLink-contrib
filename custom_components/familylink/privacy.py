"""Privacy-safe logging for the Family Link integration."""

from __future__ import annotations

import logging
import re
from typing import Any

_OPERATIONS = (
    "authentication",
    "bedtime",
    "contact restriction",
    "cookie",
    "daily limit",
    "device control",
    "family members",
    "location",
    "ring device",
    "school mode",
    "school time",
    "screen time",
    "setup",
    "strict mode",
    "time bonus",
    "weekly policy",
)
_OPERATION_TOKENS = (
    ("authentication", "authentication"),
    ("bedtime", "bedtime"),
    ("contact restriction", "contact_restriction"),
    ("cookie", "cookie"),
    ("daily limit", "daily_limit"),
    ("device control", "device_control"),
    ("locked device", "device_control"),
    ("family members", "family_members"),
    ("location", "location"),
    ("ring device", "ring_device"),
    ("school mode", "school_mode"),
    ("school time", "school_time"),
    ("screen time", "screen_time"),
    ("setup", "setup"),
    ("strict mode", "strict_mode"),
    ("time bonus", "time_bonus"),
    ("weekly policy", "weekly_policy"),
)
_STATUS_TOKENS = (
    (("fail", "error", "invalid", "denied"), "failed"),
    (("skip", "missing", "not found", "no "), "unavailable"),
    (("success", "created", "loaded", "resolved", "completed"), "succeeded"),
)
_SAFE_HTTP_STATUS_CODES = frozenset(
    {400, 401, 403, 404, 405, 408, 409, 429, 500, 502, 503, 504}
)
_HTTP_STATUS_PATTERN = re.compile(
    r"\b(?:api\s+(?:error|returned\s+status)|http(?:\s+status)?|status(?:\s+code)?)"
    r"\s*[:=]?\s*(\d{3})(?!\d)",
    re.IGNORECASE,
)


class PrivacyLogger:
    """Expose the standard logger surface while emitting safe metadata only."""

    def __init__(self, name: str | logging.Logger) -> None:
        self.__logger = (
            name if isinstance(name, logging.Logger) else logging.getLogger(name)
        )

    @property
    def name(self) -> str:
        """Return the wrapped logger name."""
        return self.__logger.name

    @property
    def level(self) -> int:
        """Return the wrapped logger level."""
        return self.__logger.level

    @property
    def handlers(self) -> list[logging.Handler]:
        """Return the wrapped logger handlers."""
        return self.__logger.handlers

    @property
    def filters(self) -> list[logging.Filter]:
        """Return the wrapped logger filters."""
        return self.__logger.filters

    @property
    def propagate(self) -> bool:
        """Return whether records propagate to ancestor loggers."""
        return self.__logger.propagate

    @propagate.setter
    def propagate(self, value: bool) -> None:
        self.__logger.propagate = value

    def setLevel(self, level: int | str) -> None:  # noqa: N802 - logging API
        """Set the wrapped logger level."""
        self.__logger.setLevel(level)

    def getEffectiveLevel(self) -> int:  # noqa: N802 - logging API
        """Return the effective logging level."""
        return self.__logger.getEffectiveLevel()

    def hasHandlers(self) -> bool:  # noqa: N802 - logging API
        """Return whether this logger or an ancestor has handlers."""
        return self.__logger.hasHandlers()

    def addHandler(self, handler: logging.Handler) -> None:  # noqa: N802
        """Attach a handler without exposing an unsanitized emit path."""
        self.__logger.addHandler(handler)

    def removeHandler(self, handler: logging.Handler) -> None:  # noqa: N802
        """Remove a handler."""
        self.__logger.removeHandler(handler)

    def addFilter(self, filter_: logging.Filter) -> None:  # noqa: N802
        """Attach a filter."""
        self.__logger.addFilter(filter_)

    def removeFilter(self, filter_: logging.Filter) -> None:  # noqa: N802
        """Remove a filter."""
        self.__logger.removeFilter(filter_)

    def __getattr__(self, name: str) -> Any:
        """Delegate read-only Logger compatibility without exposing emit APIs."""
        if name == "disabled":
            return self.__logger.disabled
        if name in {"parent", "root"}:
            related = getattr(self.__logger, name)
            return PrivacyLogger(related)
        raise AttributeError(name)

    def isEnabledFor(self, level: int) -> bool:  # noqa: N802 - logging API
        """Return whether the wrapped logger accepts ``level``."""
        return self.__logger.isEnabledFor(level)

    @staticmethod
    def _message(message: object, level: int) -> str:
        """Reduce a caller message to allow-listed operation/status metadata."""
        text = str(message).lower()
        operation = next(
            (safe for token, safe in _OPERATION_TOKENS if token in text),
            "family_link",
        )
        if level >= logging.ERROR:
            status = "failed"
        else:
            status = next(
                (result for tokens, result in _STATUS_TOKENS if any(token in text for token in tokens)),
                "in_progress",
            )

        match = _HTTP_STATUS_PATTERN.search(text)
        http_status = int(match.group(1)) if match else None
        if http_status not in _SAFE_HTTP_STATUS_CODES:
            http_status = None
        suffix = f" http_status={http_status}" if http_status is not None else ""
        return f"Family Link operation={operation} status={status}{suffix}"

    def log(self, level: int, message: object, *args: Any, **kwargs: Any) -> None:
        """Log at ``level`` without forwarding caller-controlled data."""
        if not self.__logger.isEnabledFor(level):
            return
        self.__logger.log(level, self._message(message, level))

    def event(
        self,
        level: int,
        *,
        operation: str,
        status: str,
        http_status: int | None = None,
    ) -> None:
        """Emit explicitly allow-listed operation metadata."""
        safe_operation = operation if operation in {
            item.replace(" ", "_") for item in _OPERATIONS
        } else "family_link"
        safe_status = status if status in {
            "failed", "in_progress", "succeeded", "unavailable"
        } else "in_progress"
        suffix = (
            f" http_status={http_status}"
            if http_status in _SAFE_HTTP_STATUS_CODES
            else ""
        )
        self.__logger.log(
            level,
            f"Family Link operation={safe_operation} status={safe_status}{suffix}",
        )

    def debug(self, message: object, *args: Any, **kwargs: Any) -> None:
        self.log(logging.DEBUG, message)

    def info(self, message: object, *args: Any, **kwargs: Any) -> None:
        self.log(logging.INFO, message)

    def warning(self, message: object, *args: Any, **kwargs: Any) -> None:
        self.log(logging.WARNING, message)

    warn = warning

    def error(self, message: object, *args: Any, **kwargs: Any) -> None:
        self.log(logging.ERROR, message)

    def critical(self, message: object, *args: Any, **kwargs: Any) -> None:
        self.log(logging.CRITICAL, message)

    fatal = critical

    def exception(self, message: object, *args: Any, **kwargs: Any) -> None:
        """Log an error without forwarding exception details or traceback."""
        self.log(logging.ERROR, message)


def get_privacy_logger(name: str) -> PrivacyLogger:
    """Return a logger that cannot emit Family Link household data."""
    return PrivacyLogger(name)
