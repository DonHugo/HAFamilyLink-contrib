"""Privacy boundaries for Family Link entities and logging."""

from __future__ import annotations

import asyncio
import inspect
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import voluptuous as vol
from homeassistant.const import MATCH_ALL
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers.update_coordinator import UpdateFailed

import custom_components.familylink as familylink
from custom_components.familylink import (
    _privacy_safe_handler,
    async_setup_services,
    binary_sensor,
    button,
    device_tracker,
    number,
    select,
    sensor,
    switch,
    time,
)
from custom_components.familylink.coordinator import FamilyLinkDataUpdateCoordinator
from custom_components.familylink.entity import (
    FamilyLinkPrivacyMixin,
    privacy_safe_entity_action,
)
from custom_components.familylink.exceptions import FamilyLinkException
from custom_components.familylink.privacy import PrivacyLogger


ENTITY_MODULES = (
    binary_sensor,
    device_tracker,
    number,
    select,
    sensor,
    switch,
    time,
)
ENTITY_CLASSES_WITH_DYNAMIC_ATTRIBUTES = sorted(
    {
        candidate
        for module in ENTITY_MODULES
        for _, candidate in inspect.getmembers(module, inspect.isclass)
        if candidate.__module__ == module.__name__
        and "extra_state_attributes" in candidate.__dict__
    },
    key=lambda candidate: candidate.__name__,
)


@pytest.mark.parametrize("entity_class", ENTITY_CLASSES_WITH_DYNAMIC_ATTRIBUTES)
def test_dynamic_attributes_are_excluded_from_recorder(entity_class) -> None:
    """Every entity defining dynamic attributes excludes all of them."""
    assert len(ENTITY_CLASSES_WITH_DYNAMIC_ATTRIBUTES) == 25
    assert issubclass(entity_class, FamilyLinkPrivacyMixin)
    assert next(
        cls
        for cls in entity_class.__mro__
        if "_unrecorded_attributes" in cls.__dict__
    ) is FamilyLinkPrivacyMixin
    assert MATCH_ALL in entity_class._unrecorded_attributes


@pytest.mark.parametrize(
    ("method", "level"),
    [
        ("debug", logging.DEBUG),
        ("info", logging.INFO),
        ("warning", logging.WARNING),
        ("error", logging.ERROR),
        ("critical", logging.CRITICAL),
        ("exception", logging.ERROR),
    ],
)
def test_privacy_logger_redacts_all_levels(caplog, method: str, level: int) -> None:
    """Messages, arguments, keyword data, and exceptions never reach logs."""
    name = f"familylink-test-privacy-{method}"
    logger = PrivacyLogger(name)
    canaries = (
        "minor-name-canary",
        "child-id-canary",
        "invalid.example.secret-package",
        "12.345678,98.765432",
        "https://example.invalid/?token=url-canary",
        "payload-canary",
        "cookie-canary",
        "api-key-canary",
        "session-canary",
        "exception-canary",
    )

    with caplog.at_level(logging.DEBUG, logger=name):
        try:
            raise RuntimeError(canaries[-1])
        except RuntimeError:
            getattr(logger, method)(
                "Location request failed for %s at %s payload=%s",
                canaries[0],
                canaries[3],
                canaries,
                exc_info=True,
                extra={"secret": canaries[7]},
            )

    assert all(canary not in caplog.text for canary in canaries)
    assert caplog.records[-1].levelno == level
    assert "operation=location" in caplog.text
    assert "status=failed" in caplog.text
    assert "Traceback" not in caplog.text


@pytest.mark.parametrize(
    ("message", "operation", "status", "http_status"),
    [
        ("API Error 403: payload-canary", "family_link", "failed", 403),
        ("HTTP status=429 payload-canary", "family_link", "in_progress", 429),
        ("API returned status 403 from url-canary", "family_link", "in_progress", 403),
        ("HTTP status 200 payload-canary", "family_link", "in_progress", None),
        ("HTTP status 4030 payload-canary", "family_link", "in_progress", None),
        ("Successfully refreshed authentication", "authentication", "succeeded", None),
        ("No location data returned", "location", "unavailable", None),
        ("Strict mode action started", "strict_mode", "in_progress", None),
        ("Failed to fetch applied time limits", "family_link", "failed", None),
        ("Successfully locked device", "device_control", "succeeded", None),
    ],
)
def test_privacy_logger_classifies_production_messages(
    caplog, message: str, operation: str, status: str, http_status: int | None
) -> None:
    """An HTTP status is retained, while surrounding response data is dropped."""
    logger = PrivacyLogger("familylink-test-http-status")
    with caplog.at_level(logging.DEBUG, logger="familylink-test-http-status"):
        logger.info(message)

    assert f"operation={operation}" in caplog.text
    assert f"status={status}" in caplog.text
    assert (f"http_status={http_status}" in caplog.text) is (http_status is not None)
    assert "payload-canary" not in caplog.text


def test_privacy_logger_delegates_is_enabled_for() -> None:
    """Logging guards continue to honor the wrapped logger's level."""
    logger = PrivacyLogger("familylink-test-level")
    logger.setLevel(logging.WARNING)

    assert not logger.isEnabledFor(logging.INFO)
    assert logger.isEnabledFor(logging.ERROR)


def test_privacy_logger_does_not_render_disabled_messages() -> None:
    """Disabled log calls preserve standard logging's lazy evaluation."""
    logger = PrivacyLogger("familylink-test-lazy")
    logger.setLevel(logging.INFO)

    class UnsafeMessage:
        def __str__(self) -> str:
            raise AssertionError("disabled message was rendered")

    logger.debug(UnsafeMessage())


def test_privacy_logger_supports_standard_logger_configuration() -> None:
    """Frameworks can inspect and configure the wrapped logger safely."""
    logger = PrivacyLogger("familylink-test-compatibility")
    handler = logging.NullHandler()
    filter_ = logging.Filter("familylink-test-compatibility")

    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.addFilter(filter_)
    try:
        assert logger.name == "familylink-test-compatibility"
        assert logger.level == logging.INFO
        assert logger.getEffectiveLevel() == logging.INFO
        assert handler in logger.handlers
        assert filter_ in logger.filters
        assert logger.hasHandlers()
        assert isinstance(logger.parent, PrivacyLogger)
        assert isinstance(logger.root, PrivacyLogger)
        with pytest.raises(AttributeError):
            logger.handle(logging.LogRecord("x", 20, "", 0, "canary", (), None))
    finally:
        logger.removeFilter(filter_)
        logger.removeHandler(handler)


@pytest.mark.asyncio
async def test_coordinator_boundary_sanitizes_update_failure(caplog) -> None:
    """Coordinator failures do not leak details through HA root logging."""
    coordinator = object.__new__(FamilyLinkDataUpdateCoordinator)
    coordinator._auth_notification_sent = False
    coordinator._is_retrying_auth = False
    coordinator._last_known_data = None

    async def fail_fetch():
        raise RuntimeError("coordinator-canary")

    coordinator._async_fetch_data = fail_fetch
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(UpdateFailed) as raised:
            await coordinator._async_update_data()

    assert str(raised.value) == "Family Link update failed"
    assert raised.value.__suppress_context__
    assert "coordinator-canary" not in caplog.text


@pytest.mark.asyncio
async def test_setup_boundary_sanitizes_failure(caplog, monkeypatch) -> None:
    """Config-entry setup exposes a stable exception to HA core logging."""
    coordinator = SimpleNamespace(
        async_load_strict_intents=AsyncMock(side_effect=RuntimeError("setup-canary"))
    )
    monkeypatch.setattr(
        familylink, "FamilyLinkDataUpdateCoordinator", lambda hass, entry: coordinator
    )
    hass = SimpleNamespace()
    entry = SimpleNamespace()

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ConfigEntryNotReady) as raised:
            await familylink.async_setup_entry(hass, entry)

    assert str(raised.value) == "Unable to set up Family Link"
    assert raised.value.__suppress_context__
    assert "setup-canary" not in caplog.text


@pytest.mark.asyncio
async def test_service_boundary_sanitizes_failure(caplog) -> None:
    """Registered HA service handlers expose stable public exceptions only."""
    handlers = {}
    schemas = {}

    class Services:
        def async_register(self, domain, service, handler, **kwargs):
            handlers[service] = handler
            schemas[service] = kwargs["schema"]

    client = SimpleNamespace(async_block_app=AsyncMock(side_effect=RuntimeError(
        "service-canary"
    )))
    coordinator = SimpleNamespace(client=client, async_request_refresh=AsyncMock())
    hass = SimpleNamespace(services=Services(), states=SimpleNamespace(get=lambda _: None))

    await async_setup_services(hass, coordinator)
    call = SimpleNamespace(data={"package_name": "package-canary", "child_id": "id"})
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(HomeAssistantError) as raised:
            await handlers["block_app"](call)

    assert str(raised.value) == "The Family Link service action failed"
    assert raised.value.__suppress_context__
    assert "service-canary" not in caplog.text
    assert "package-canary" not in caplog.text

    with pytest.raises(vol.Invalid):
        schemas["block_app"]({})
    assert client.async_block_app.await_count == 1


@pytest.mark.asyncio
async def test_service_wrapper_preserves_result_and_safe_stable_errors() -> None:
    """The boundary is transparent for results and stable public errors."""
    expected = {"status": "ok"}

    async def returns_result(call):
        return expected

    assert await _privacy_safe_handler(returns_result)(SimpleNamespace()) is expected

    for exception_type, message in (
        (
            FamilyLinkException,
            "Family Link client is not connected. Please re-authenticate via the add-on.",
        ),
        (
            ValueError,
            "device_id is required. Either select an entity or provide device_id manually.",
        ),
    ):

        async def raises_stable(call, error=exception_type(message)):
            raise error from RuntimeError("safe-error-cause-canary")

        with pytest.raises(exception_type, match=f"^{message}$") as raised:
            await _privacy_safe_handler(raises_stable)(SimpleNamespace())
        assert raised.value.__suppress_context__


@pytest.mark.asyncio
async def test_service_wrapper_preserves_unauthorized_and_cancellation() -> None:
    """Authentication and task cancellation keep framework semantics."""
    from homeassistant.exceptions import Unauthorized

    for exception in (Unauthorized(), asyncio.CancelledError()):

        async def raises_special(call, error=exception):
            raise error

        with pytest.raises(type(exception)):
            await _privacy_safe_handler(raises_special)(SimpleNamespace())


ENTITY_ACTION_METHODS = (
    (button.FamilyLinkTimeBonusButton, "async_press"),
    (button.CancelTimeBonusButton, "async_press"),
    (button.RingDeviceButton, "async_press"),
    (switch.FamilyLinkDeviceSwitch, "async_turn_on"),
    (switch.FamilyLinkDeviceSwitch, "async_turn_off"),
    (switch.FamilyLinkBedtimeSwitch, "async_turn_on"),
    (switch.FamilyLinkBedtimeSwitch, "async_turn_off"),
    (switch.FamilyLinkSchoolTimeSwitch, "async_turn_on"),
    (switch.FamilyLinkSchoolTimeSwitch, "async_turn_off"),
    (switch.FamilyLinkDailyLimitSwitch, "async_turn_on"),
    (switch.FamilyLinkDailyLimitSwitch, "async_turn_off"),
    (switch.FamilyLinkStrictModeSwitch, "async_turn_on"),
    (switch.FamilyLinkStrictModeSwitch, "async_turn_off"),
    (select.FamilyLinkContactRestrictionSelect, "async_select_option"),
    (number.FamilyLinkDailyLimitNumber, "async_set_native_value"),
    (time.FamilyLinkBedtimeTime, "async_set_value"),
)


@pytest.mark.parametrize(("entity_class", "method_name"), ENTITY_ACTION_METHODS)
def test_all_entity_mutation_entrypoints_use_privacy_boundary(
    entity_class, method_name: str
) -> None:
    """Every HA-callable entity mutation has the shared async boundary."""
    assert hasattr(entity_class.__dict__[method_name], "__wrapped__")


@pytest.mark.asyncio
async def test_entity_action_boundary_contract() -> None:
    """Entity actions preserve results/framework errors and sanitize failures."""
    expected = {"status": "ok"}

    @privacy_safe_entity_action
    async def action(result):
        if isinstance(result, BaseException):
            raise result
        return result

    assert await action(expected) is expected

    with pytest.raises(HomeAssistantError) as raised:
        await action(RuntimeError("entity-action-canary"))
    assert str(raised.value) == "The Family Link entity action failed"
    assert raised.value.__suppress_context__
    assert "entity-action-canary" not in str(raised.value)

    from homeassistant.exceptions import Unauthorized

    for exception in (Unauthorized(), asyncio.CancelledError()):
        with pytest.raises(type(exception)):
            await action(exception)


def test_live_attributes_and_primary_state_remain_available() -> None:
    """Recorder minimization does not alter current entity data."""
    coordinator = SimpleNamespace(
        last_update_success=True,
        data={
            "children_data": [
                {
                    "child_id": "child-id-canary",
                    "child_name": "minor-name-canary",
                    "screen_time": {
                        "total_seconds": 600,
                        "formatted": "00:10:00",
                        "hours": 0,
                        "minutes": 10,
                        "seconds": 0,
                        "app_breakdown": {},
                    },
                }
            ]
        },
    )
    entity = sensor.FamilyLinkScreenTimeSensor(
        coordinator, "total", "child-id-canary", "minor-name-canary"
    )

    assert entity.native_value == 10.0
    assert entity.extra_state_attributes["child_id"] == "child-id-canary"
    assert entity.extra_state_attributes["child_name"] == "minor-name-canary"
