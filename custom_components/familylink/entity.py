"""Shared entity helpers for the Family Link integration."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Collection
from functools import wraps
from typing import ParamSpec, TypeVar

from homeassistant.const import MATCH_ALL
from homeassistant.exceptions import HomeAssistantError, Unauthorized

_P = ParamSpec("_P")
_ResultT = TypeVar("_ResultT")

ENTITY_ACTION_ERROR = "The Family Link entity action failed"


def async_error_boundary(
    error_message: str,
    *,
    safe_errors: Collection[tuple[type[Exception], str]] = (),
) -> Callable[
    [Callable[_P, Awaitable[_ResultT]]], Callable[_P, Awaitable[_ResultT]]
]:
    """Wrap an async HA entrypoint with a stable public error boundary."""

    def decorate(
        handler: Callable[_P, Awaitable[_ResultT]],
    ) -> Callable[_P, Awaitable[_ResultT]]:
        @wraps(handler)
        async def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _ResultT:
            try:
                return await handler(*args, **kwargs)
            except (Unauthorized, asyncio.CancelledError):
                raise
            except Exception as err:
                for error_type, safe_message in safe_errors:
                    if isinstance(err, error_type) and str(err) == safe_message:
                        raise error_type(safe_message) from None
                raise HomeAssistantError(error_message) from None

        return wrapped

    return decorate


privacy_safe_entity_action = async_error_boundary(ENTITY_ACTION_ERROR)


class FamilyLinkPrivacyMixin:
    """Keep dynamic attributes live while excluding them from Recorder."""

    _unrecorded_attributes = frozenset({MATCH_ALL})
