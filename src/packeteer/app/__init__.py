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

import struct
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from packeteer import protocols
from packeteer.protocols import AppProtocol

from . import dhcp, dns, http

if TYPE_CHECKING:
    from packeteer.generate.builder import PacketBuilder

__all__ = [
    "dns", "dhcp", "http", "apply_app_section", "protocol_payload_fn",
    "register_builtins",
]


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


#: What a codec raises for a section it cannot build a message from — the
#: same set :mod:`packeteer.conformance` treats as a protocol's own failures.
#: A section is user JSON going through code compiled from a spec, so the
#: failure is bad input rather than a bug, and a traceback is the wrong answer
#: to it — ``AttributeError`` above all, which is what a field of the wrong
#: type produces (``'int' object has no attribute 'encode'``).
_SECTION_ERRORS = (
    ValueError, KeyError, TypeError, AttributeError, IndexError,
    OverflowError, UnicodeDecodeError, struct.error,
)


#: The keys that mark an object as a whole packet spec.  Every packet
#: ``packeteer parse`` writes has a link layer or a network layer, and these
#: are their section names; a protocol may not take any of them as its own
#: name.  Deliberately not the full reserved list: that will grow to cover
#: attribute names (#139) such as ``timestamp``, which a bare section could
#: legitimately use as a field, and a section mistaken for a packet is skipped
#: in silence — the failure mode this whole path exists to remove.
_PACKET_KEYS: frozenset[str] = frozenset({
    "ethernet", "sll", "sll2", "loopback", "arp", "network", "packet_metadata",
})


def _is_packet(element: dict[str, Any]) -> bool:
    """Whether *element* is a whole packet spec rather than a bare section."""
    return bool(element.keys() & _PACKET_KEYS)


def _sections_in(
    proto: AppProtocol, messages: Sequence[dict[str, Any]] | dict[str, Any],
) -> list[dict[str, Any]]:
    """Return the *proto* sections in *messages*, whatever shape they came in.

    Accepts a list of bare sections, the same wrapped under the protocol's
    name, whole packet specs, or a ``packeteer parse`` document (an object
    with a ``"packets"`` list).  A packet that carries no *proto* section —
    an ACK, the handshake — is not a message and is skipped; anything else
    is handed on as a section for the protocol to accept or refuse.
    """
    if isinstance(messages, dict):
        packets = messages.get("packets")
        if not isinstance(packets, list):
            raise ValueError(
                f"expected a JSON array of {proto.name} sections, or a "
                f"'packeteer parse' document with a 'packets' array; got an "
                f"object with keys {', '.join(repr(k) for k in messages)}"
            )
        messages = packets
    out: list[dict[str, Any]] = []
    for index, element in enumerate(messages):
        if not isinstance(element, dict):
            raise ValueError(
                f"message {index}: expected a {proto.name} section (a JSON "
                f"object), got {type(element).__name__}"
            )
        inner = element.get(proto.name)
        if isinstance(inner, dict):
            out.append(inner)
        elif _is_packet(element):
            continue
        else:
            out.append(element)
    return out


def protocol_payload_fn(
    proto: AppProtocol,
    messages: Sequence[dict[str, Any]] | dict[str, Any],
    transport: str,
) -> Callable[[int, str], bytes]:
    """Return a ``payload_fn`` sending *messages* through *proto*, in order.

    The API behind ``packeteer stream --payload <protocol>
    --protocol-messages FILE``.  Each message is encoded once, up front, so a
    section that is not one fails here rather than a hundred packets in.
    The function cycles: ``--packets`` says how long a stream is, and a
    shorter list must not silently shorten it.

    *messages* is a list whose elements are each a bare section, the section
    wrapped under the protocol's name, or a whole packet spec — or it is a
    ``packeteer parse`` document, whose ``"packets"`` are read.  So a parsed
    capture's messages can be replayed through an impaired stream without
    editing the file (#137).  A packet carrying no section of *proto* — an
    ACK, a handshake segment — is not a message and is skipped; an element
    that is neither a packet nor a section is refused by the protocol's
    ``from_spec`` rather than built into a default message, which is the
    outcome this function exists to prevent: a stream of empty messages is
    indistinguishable from a successful one.

    Args:
        proto: The protocol to encode with.
        messages: Its messages, in the order to send them, in any of the
            shapes above.  At least one must carry a section.
        transport: ``"tcp"`` or ``"udp"`` — what the stream carries, which
            is what lets DNS decide about its length prefix.

    Returns:
        ``(packet_index, direction) -> bytes``, the shape the stream
        generators' ``payload_fn`` takes.

    Raises:
        ValueError: If no element carries a section, if an element is not an
            object, if the protocol does not run over *transport*, or if a
            section is not one of *proto* — with the element's index and the
            protocol's own reason.

    Example::

        from packeteer import protocols
        from packeteer.app import protocol_payload_fn
        from packeteer.generate import TCPStreamConfig, generate_tcp_stream

        fn = protocol_payload_fn(protocols.for_section("dns"), sections, "tcp")
        stream = generate_tcp_stream(config=TCPStreamConfig(payload_fn=fn))

    """
    if not proto.carries(transport):
        raise ValueError(
            f"{proto.name!r} is carried over {proto.over}, not {transport}"
        )
    sections = _sections_in(proto, messages)
    if not sections:
        raise ValueError(
            f"no {proto.name} messages: nothing carries a {proto.name!r} "
            f"section, so there is nothing to send"
        )
    encoded: list[bytes] = []
    for index, section in enumerate(sections):
        try:
            encoded.append(proto.encode(proto.from_spec(section), transport))
        except _SECTION_ERRORS as exc:
            raise ValueError(
                f"message {index}: {type(exc).__name__}: {exc}"
            ) from exc

    def payload_fn(index: int, _direction: str) -> bytes:
        return encoded[index % len(encoded)]

    return payload_fn

