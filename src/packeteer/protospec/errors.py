"""Errors raised while loading, checking and compiling a protocol spec.

Every one carries a :class:`~packeteer.protospec.spec.Location`, because the
first question about a bad spec is always *where*.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packeteer.protospec.spec import Location

__all__ = ["SpecError"]


class SpecError(Exception):
    """A spec could not be read as a spec.

    Raised for structural faults — a missing required key, a value of the
    wrong shape, a construct spelled in a way the loader cannot interpret.
    Faults that need the spec to be *understood* rather than merely read —
    an unknown enum name, a field referencing one decoded after it — are
    reported by the checker instead, which collects every one rather than
    stopping at the first.

    Attributes:
        message: What is wrong, without the location.
        location: Where in the spec it is.

    """

    def __init__(self, message: str, location: Location | None = None) -> None:
        self.message = message
        self.location = location
        super().__init__(str(location) + ": " + message if location else message)
