"""Privacy boundaries for the Family Link authentication service."""

from __future__ import annotations

import ast
import asyncio
import importlib
import logging
from pathlib import Path
import sys

import pytest
from fastapi import HTTPException

from app.privacy import PrivacyLogger


def _import_main(monkeypatch, tmp_path):
    """Import the app with storage redirected away from the host filesystem."""
    from app import config as app_config

    config = app_config.Config(share_dir=str(tmp_path))
    monkeypatch.setattr(app_config, "get_config", lambda: config)
    sys.modules.pop("app.main", None)
    return importlib.import_module("app.main")


@pytest.mark.parametrize(
    "method", ["debug", "info", "warning", "error", "critical", "exception"]
)
def test_auth_privacy_logger_redacts_canaries(caplog, method: str) -> None:
    """Auth logs contain only allow-listed metadata at every level."""
    name = f"familylink-auth-test-{method}"
    logger = PrivacyLogger(name)
    canaries = (
        "session-id-canary",
        "cookie-value-canary",
        "api-key-canary",
        "https://accounts.example.invalid/?token=url-canary",
        "payload-canary",
        "exception-canary",
    )

    with caplog.at_level(logging.DEBUG, logger=name):
        try:
            raise RuntimeError(canaries[-1])
        except RuntimeError:
            getattr(logger, method)(
                "Authentication failed for %s at %s",
                canaries[0],
                canaries[3],
                exc_info=True,
                extra={"cookie": canaries[1]},
            )

    assert all(canary not in caplog.text for canary in canaries)
    assert "operation=authentication" in caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize(
    ("message", "operation", "status", "http_status"),
    [
        ("API returned status 403 from url-canary", "auth_service", "in_progress", 403),
        ("HTTP status=200 payload-canary", "auth_service", "in_progress", None),
        ("Authentication completed successfully", "authentication", "succeeded", None),
        ("Failed to load cookies", "cookie", "failed", None),
        ("Authentication timeout", "authentication", "unavailable", None),
    ],
)
def test_auth_privacy_logger_classifies_production_messages(
    caplog, message: str, operation: str, status: str, http_status: int | None
) -> None:
    """Production-style diagnostics retain only safe metadata."""
    name = "familylink-auth-test-production"
    logger = PrivacyLogger(name)

    with caplog.at_level(logging.DEBUG, logger=name):
        logger.info(message)

    assert f"operation={operation}" in caplog.text
    assert f"status={status}" in caplog.text
    assert (f"http_status={http_status}" in caplog.text) is (http_status is not None)
    assert "canary" not in caplog.text


def test_auth_privacy_logger_delegates_is_enabled_for() -> None:
    """The wrapper supports standard logging level guards."""
    logger = PrivacyLogger("familylink-auth-test-level")
    logger.setLevel(logging.ERROR)

    assert not logger.isEnabledFor(logging.WARNING)
    assert logger.isEnabledFor(logging.ERROR)


def test_auth_privacy_logger_does_not_render_disabled_messages() -> None:
    """Disabled auth log calls remain lazily evaluated."""
    logger = PrivacyLogger("familylink-auth-test-lazy")
    logger.setLevel(logging.INFO)

    class UnsafeMessage:
        def __str__(self) -> str:
            raise AssertionError("disabled message was rendered")

    logger.debug(UnsafeMessage())


def test_auth_privacy_logger_supports_standard_configuration() -> None:
    """The wrapper retains common Logger inspection and mutation APIs."""
    logger = PrivacyLogger("familylink-auth-test-compatibility")
    handler = logging.NullHandler()
    filter_ = logging.Filter("familylink-auth-test-compatibility")
    logger.setLevel(logging.WARNING)
    logger.addHandler(handler)
    logger.addFilter(filter_)
    try:
        assert logger.name == "familylink-auth-test-compatibility"
        assert logger.getEffectiveLevel() == logging.WARNING
        assert handler in logger.handlers
        assert filter_ in logger.filters
        assert isinstance(logger.parent, PrivacyLogger)
        assert isinstance(logger.root, PrivacyLogger)
        with pytest.raises(AttributeError):
            logger.handle(logging.LogRecord("x", 20, "", 0, "canary", (), None))
    finally:
        logger.removeFilter(filter_)
        logger.removeHandler(handler)


def test_programmatic_uvicorn_disables_access_log() -> None:
    """The Python launch path must not log request URLs or query strings."""
    main_path = Path(__file__).parents[2] / "familylink-playwright" / "app" / "main.py"
    module = ast.parse(main_path.read_text(encoding="utf-8"))
    uvicorn_calls = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "uvicorn"
        and node.func.attr == "run"
    ]

    assert len(uvicorn_calls) == 1
    keywords = {keyword.arg: keyword.value for keyword in uvicorn_calls[0].keywords}
    assert isinstance(keywords.get("access_log"), ast.Constant)
    assert keywords["access_log"].value is False


@pytest.mark.parametrize(
    "relative_path",
    ["run-standalone.sh", "rootfs/usr/local/bin/run.sh"],
)
def test_shell_uvicorn_disables_access_log(relative_path: str) -> None:
    """Both container and standalone launchers suppress request URLs."""
    launcher = (
        Path(__file__).parents[2] / "familylink-playwright" / relative_path
    ).read_text(encoding="utf-8")
    assert "--no-access-log" in launcher


@pytest.mark.asyncio
async def test_startup_boundary_sanitizes_framework_exception(
    caplog, monkeypatch, tmp_path
) -> None:
    """Startup failures expose neither raw text nor chained tracebacks."""
    main = _import_main(monkeypatch, tmp_path)

    class FailingManager:
        def __init__(self, **kwargs):
            pass

        async def initialize(self):
            raise RuntimeError("startup-canary")

    monkeypatch.setattr(main, "BrowserAuthManager", FailingManager)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(main.AuthServiceStartupError) as raised:
            await main.startup_event()

    assert str(raised.value) == "Authentication service startup failed"
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is not None
    assert raised.value.__suppress_context__
    assert "startup-canary" not in caplog.text


@pytest.mark.asyncio
async def test_storage_endpoint_boundary_sanitizes_failure(
    caplog, monkeypatch, tmp_path
) -> None:
    """Storage failures return a generic response and safe logs."""
    main = _import_main(monkeypatch, tmp_path)

    async def fail_load():
        raise RuntimeError("storage-canary")

    monkeypatch.setattr(main.storage, "load_cookies", fail_load)
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(HTTPException) as raised:
            await main.get_cookies(None)

    assert raised.value.status_code == 500
    assert raised.value.detail == "Failed to load cookies"
    assert raised.value.__suppress_context__
    assert "storage-canary" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("endpoint", "dependency", "detail"),
    [
        ("start_authentication", "browser_manager", "Authentication start failed"),
        ("delete_cookies", "storage", "Failed to delete cookies"),
    ],
)
async def test_mutating_endpoints_sanitize_unexpected_failures(
    caplog, monkeypatch, tmp_path, endpoint: str, dependency: str, detail: str
) -> None:
    """Mutating endpoints expose no dependency exception text or cause."""
    main = _import_main(monkeypatch, tmp_path)
    canary = f"{dependency}-mutation-canary"

    if dependency == "browser_manager":
        manager = type("FailingManager", (), {})()

        async def fail_start():
            raise RuntimeError(canary)

        manager.start_auth_session = fail_start
        monkeypatch.setattr(main, "browser_manager", manager)
        call = main.start_authentication(None)
    else:

        async def fail_clear():
            raise RuntimeError(canary)

        monkeypatch.setattr(main.storage, "clear_cookies", fail_clear)
        call = main.delete_cookies(None)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(HTTPException) as raised:
            await call

    assert raised.value.status_code == 500
    assert raised.value.detail == detail
    assert raised.value.__suppress_context__
    assert canary not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("endpoint", "dependency", "detail"),
    [
        ("check_auth_status", "browser_manager", "Authentication status check failed"),
        ("check_cookies", "storage", "Cookie status check failed"),
    ],
)
async def test_status_endpoints_sanitize_unexpected_failures(
    caplog, monkeypatch, tmp_path, endpoint: str, dependency: str, detail: str
) -> None:
    """Status endpoints expose no dependency exception text or cause."""
    main = _import_main(monkeypatch, tmp_path)
    canary = f"{dependency}-status-canary"

    if dependency == "browser_manager":
        manager = type("FailingManager", (), {})()

        async def fail_status(_session_id: str):
            raise RuntimeError(canary)

        manager.get_session_status = fail_status
        monkeypatch.setattr(main, "browser_manager", manager)
        call = main.check_auth_status("session-canary", None)
    else:
        async def fail_exists():
            raise RuntimeError(canary)

        monkeypatch.setattr(main.storage, "check_exists", fail_exists)
        call = main.check_cookies()

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(HTTPException) as raised:
            await call

    assert raised.value.status_code == 500
    assert raised.value.detail == detail
    assert raised.value.__suppress_context__
    assert canary not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint", ["check_auth_status", "check_cookies"])
async def test_status_endpoints_preserve_deliberate_http_exceptions(
    monkeypatch, tmp_path, endpoint: str
) -> None:
    """Deliberate FastAPI errors retain their status and detail."""
    main = _import_main(monkeypatch, tmp_path)
    expected = HTTPException(status_code=409, detail="stable-detail")

    if endpoint == "check_auth_status":
        manager = type("FailingManager", (), {})()

        async def fail_status(_session_id: str):
            raise expected

        manager.get_session_status = fail_status
        monkeypatch.setattr(main, "browser_manager", manager)
        call = main.check_auth_status("session-canary", None)
    else:
        async def fail_exists():
            raise expected

        monkeypatch.setattr(main.storage, "check_exists", fail_exists)
        call = main.check_cookies()

    with pytest.raises(HTTPException) as raised:
        await call
    assert raised.value is expected


@pytest.mark.asyncio
async def test_shutdown_boundary_sanitizes_framework_exception(
    caplog, monkeypatch, tmp_path
) -> None:
    """Shutdown failures cannot expose cleanup exception text or causes."""
    main = _import_main(monkeypatch, tmp_path)
    manager = type("FailingManager", (), {})()

    async def fail_cleanup():
        raise RuntimeError("shutdown-canary")

    manager.cleanup = fail_cleanup
    monkeypatch.setattr(main, "browser_manager", manager)

    with caplog.at_level(logging.DEBUG), pytest.raises(
        main.AuthServiceShutdownError
    ) as raised:
        await main.shutdown_event()

    assert str(raised.value) == "Authentication service shutdown failed"
    assert raised.value.__suppress_context__
    assert "shutdown-canary" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("browser_fails", [False, True])
async def test_shutdown_storage_failure_is_stable_and_sanitized(
    caplog, monkeypatch, tmp_path, browser_fails: bool
) -> None:
    """Storage-only and dual failures expose one stable shutdown error."""
    main = _import_main(monkeypatch, tmp_path)
    calls: list[str] = []
    browser_canary = "browser-shutdown-secret"
    storage_canary = "storage-shutdown-secret"

    class Manager:
        async def cleanup(self) -> None:
            calls.append("browser")
            if browser_fails:
                raise RuntimeError(browser_canary)

    class Storage:
        def close(self) -> None:
            calls.append("storage")
            raise OSError(storage_canary)

    monkeypatch.setattr(main, "browser_manager", Manager())
    monkeypatch.setattr(main, "storage", Storage())

    with caplog.at_level(logging.DEBUG), pytest.raises(
        main.AuthServiceShutdownError
    ) as raised:
        await main.shutdown_event()

    assert calls == ["browser", "storage"]
    assert str(raised.value) == "Authentication service shutdown failed"
    assert raised.value.__suppress_context__
    assert browser_canary not in caplog.text
    assert storage_canary not in caplog.text
    assert browser_canary not in str(raised.value)
    assert storage_canary not in str(raised.value)


@pytest.mark.asyncio
async def test_successful_shutdown_cleans_browser_and_storage(
    monkeypatch, tmp_path
) -> None:
    main = _import_main(monkeypatch, tmp_path)
    calls: list[str] = []

    class Manager:
        async def cleanup(self) -> None:
            calls.append("browser")

    class Storage:
        def close(self) -> None:
            calls.append("storage")

    monkeypatch.setattr(main, "browser_manager", Manager())
    monkeypatch.setattr(main, "storage", Storage())

    await main.shutdown_event()

    assert calls == ["browser", "storage"]


@pytest.mark.asyncio
async def test_auth_status_exposes_only_stable_error_text(monkeypatch) -> None:
    """The polling API never returns arbitrary browser failure details."""
    from app.auth.browser import BrowserAuthManager

    manager = BrowserAuthManager()

    class FailingPage:
        @property
        def url(self):
            raise RuntimeError("browser-status-canary")

    manager._sessions["session-canary"] = {
        "status": "authenticating",
        "context": object(),
        "page": FailingPage(),
        "cookies": None,
        "created_at": 0,
    }

    async def fail_cleanup(session_id: str) -> None:
        return None

    manager._cleanup_session = fail_cleanup
    manager._auth_timeout = 1
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    await manager._monitor_authentication("session-canary")

    status = await manager.get_session_status("session-canary")
    assert status["status"] == "error"
    assert status["error"] == "Authentication failed"
    assert "browser-status-canary" not in status["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_browser_fallback_storage_always_closes(
    monkeypatch, fails: bool
) -> None:
    """Fallback persistence releases its retained directory descriptor."""
    from app.auth.browser import BrowserAuthManager
    from app.storage import file_storage

    closed = False

    class TrackingStorage:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            nonlocal closed
            closed = True

        async def save_cookies(self, _cookies):
            if fails:
                raise OSError("save failed")

    monkeypatch.setattr(file_storage, "SharedStorage", TrackingStorage)
    manager = BrowserAuthManager(storage=None)

    if fails:
        with pytest.raises(OSError, match="save failed"):
            await manager._save_cookies([{"name": "SID"}])
    else:
        await manager._save_cookies([{"name": "SID"}])

    assert closed
