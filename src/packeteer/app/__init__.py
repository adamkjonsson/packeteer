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

from packeteer import protocols

from . import dhcp, dns, http

__all__ = ["dns", "dhcp", "http", "register_builtins"]


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
