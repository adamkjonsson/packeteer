"""The application protocols packeteer ships with, as registry entries.

Importing this package registers DNS, DHCP and HTTP with
:mod:`packeteer.protocols`.  :mod:`packeteer.parse` imports it, so the three
are present whenever a packet is parsed.

Each module here assembles one protocol from parts that already exist: the
encoder and message classes in :mod:`packeteer.generate`, the decoder in
:mod:`packeteer.parse`, and the redaction rules in :mod:`packeteer.sanitise`.
What it owns outright is the packet-spec mapping — ``to_spec`` and
``from_spec`` — the second of which lived in ``packeteer.__main__`` until now,
out of reach of anyone not running the CLI.

**Only the generate-side imports are at module level.**  The decoder,
``to_spec`` and ``sanitise`` are imported inside the functions that use them,
so that importing this package does not drag in the parser: a caller building
packets has no use for it, and it roughly doubles the import cost.

**:mod:`packeteer.generate` does not import this package**, because it cannot:
the modules here import ``packeteer.generate.dns`` and friends at module
level, so an import in the other direction is a cycle.  Anything on the
generate side that needs the registry — :meth:`PacketBuilder.app
<packeteer.generate.builder.PacketBuilder.app>` — imports it inside the method
instead.  The practical consequence is that ``import packeteer.generate``
alone leaves the registry empty; ``import packeteer.parse``, ``import
packeteer.app``, or calling anything that needs it fills it in.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from packeteer import protocols

from . import dhcp, dns, http

if TYPE_CHECKING:
    from packeteer.generate.builder import PacketBuilder

__all__ = ["dns", "dhcp", "http", "apply_app_section", "register_builtins"]


def register_builtins() -> None:
    """Register DNS, DHCP and HTTP, unless they are registered already.

    Called when this package is imported, so importing it is enough.  It is
    idempotent, and skips a name that is already taken rather than raising, so
    a caller who replaced a built-in with
    :func:`~packeteer.protocols.unregister` keeps their replacement.
    """
    for module in (dns, dhcp, http):
        if protocols.for_section(module.PROTOCOL.name) is None:
            protocols.register(module.PROTOCOL)


register_builtins()


def apply_app_section(
    b: PacketBuilder, spec: dict[str, Any], transport: str,
) -> PacketBuilder | None:
    """Encode whichever registered protocol's section *spec* carries.

    The packet-spec counterpart to :func:`packeteer.parse.to_config.update_config`:
    it finds the one section naming a registered protocol, builds the message
    from it, and sets it as the packet payload.

    Args:
        b: The builder to append to.  Its transport layer must already be set.
        spec: One packet's spec — the object holding ``network``,
            ``transport`` and at most one application section.
        transport: ``"tcp"`` or ``"udp"``, which is what lets DNS decide
            whether to add its length prefix.

    Returns:
        *b* with the payload set, or ``None`` when *spec* carries no
        application section, so the caller can fall back to ``payload``.

    Raises:
        ValueError: If *spec* carries more than one application section.  A
            packet has one application payload, and silently preferring
            whichever registered first would make the choice arbitrary as
            well as invisible.

    """
    found = [proto for proto in protocols.registered() if proto.name in spec]
    if not found:
        return None
    if len(found) > 1:
        names = ", ".join(sorted(proto.name for proto in found))
        raise ValueError(
            f"a packet spec may carry at most one application section, "
            f"but this one has {len(found)}: {names}"
        )
    proto = found[0]
    return b.payload(data=proto.encode(proto.from_spec(spec[proto.name]), transport))
