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
from typing import TYPE_CHECKING, Any, cast

from packeteer import protocols
from packeteer.protocols import AppProtocol

from . import dhcp, dns, http

if TYPE_CHECKING:
    from packeteer.generate.builder import PacketBuilder
    from packeteer.generate.payloads.base import AppMessage, Direction

__all__ = [
    "dns", "dhcp", "http", "apply_app_section", "protocol_conversation",
    "protocol_messages", "protocol_payload_fn", "register_builtins",
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


#: The ways a message can travel.  ``s2c`` is a reply, from the server.
_DIRECTIONS: tuple[str, ...] = ("c2s", "s2c")

#: The key beside a wrapped section that says which way it travels (#195).
_DIRECTION_KEY = "direction"


def _checked_direction(value: object, index: int, where: str) -> str:
    """Return *value* if it is a direction, or refuse it naming *where*."""
    if value not in _DIRECTIONS:
        raise ValueError(
            f"message {index}: {where} must be 'c2s' or 's2c', not {value!r}"
        )
    return str(value)


def _endpoints(packet: dict[str, Any]) -> tuple[tuple[Any, Any], tuple[Any, Any]] | None:
    """Return a packet's ``(source, destination)`` address and port, if it has them."""
    network, transport = packet.get("network"), packet.get("transport")
    if not isinstance(network, dict) or not isinstance(transport, dict):
        return None
    src = (network.get("src"), transport.get("src_port"))
    dst = (network.get("dst"), transport.get("dst_port"))
    if None in src or None in dst:
        return None
    return src, dst


def _inferred_direction(
    proto: AppProtocol, packet: dict[str, Any],
    clients: dict[frozenset[tuple[Any, Any]], tuple[Any, Any]],
) -> str:
    """Return which way *packet* travels when it does not say.

    ``packeteer parse`` writes no direction, so a parsed capture has to be
    read for it.  The side on one of the protocol's ports is the server.
    When neither side is, or both are, the first endpoint seen sending in
    the flow is the client, which for TCP is whoever sent the SYN.  A packet
    with no addresses goes client to server, as every message did before
    #195.
    """
    ends = _endpoints(packet)
    if ends is None:
        return "c2s"
    src, dst = ends
    if dst[1] in proto.ports and src[1] not in proto.ports:
        return "c2s"
    if src[1] in proto.ports and dst[1] not in proto.ports:
        return "s2c"
    return "c2s" if clients.get(frozenset(ends)) == src else "s2c"


def _directed_sections_in(
    proto: AppProtocol, messages: Sequence[dict[str, Any]] | dict[str, Any],
    *, directed: bool = True,
) -> list[tuple[dict[str, Any], str]]:
    """Return the *proto* sections in *messages*, each with the way it travels.

    Accepts a list of bare sections, the same wrapped under the protocol's
    name, whole packet specs, or a ``packeteer parse`` document (an object
    with a ``"packets"`` list).  A packet that carries no *proto* section —
    an ACK, the handshake — is not a message and is skipped; anything else
    is handed on as a section for the protocol to accept or refuse.

    The direction is a packet's ``packet_metadata.direction``, or inferred
    from its addresses when it has none (:func:`_inferred_direction`); a
    wrapped section's ``"direction"`` key; and ``c2s`` for a bare section.
    A wrapped section may carry nothing else beside it, since a key that is
    read by nothing is a misspelling accepted in silence (#137).  With
    *directed* false the caller takes each message's direction from the
    message itself, so a ``"direction"`` key, which would be ignored, is
    refused instead.
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

    # The first sender in each flow, over every packet and not only those
    # carrying a message: for TCP that is the SYN's sender.
    clients: dict[frozenset[tuple[Any, Any]], tuple[Any, Any]] = {}
    for element in messages:
        if isinstance(element, dict) and _is_packet(element):
            ends = _endpoints(element)
            if ends is not None:
                clients.setdefault(frozenset(ends), ends[0])

    out: list[tuple[dict[str, Any], str]] = []
    for index, element in enumerate(messages):
        if not isinstance(element, dict):
            raise ValueError(
                f"message {index}: expected a {proto.name} section (a JSON "
                f"object), got {type(element).__name__}"
            )
        inner = element.get(proto.name)
        if _is_packet(element):
            if not isinstance(inner, dict):
                continue
            meta = element.get("packet_metadata")
            stated = meta.get(_DIRECTION_KEY) if isinstance(meta, dict) else None
            direction = (
                _inferred_direction(proto, element, clients) if stated is None
                else _checked_direction(stated, index, "packet_metadata.direction")
            )
            out.append((inner, direction))
        elif isinstance(inner, dict):
            allowed = {proto.name, _DIRECTION_KEY} if directed else {proto.name}
            extra = sorted(set(element) - allowed)
            if extra:
                beside = ("only 'direction' may be beside it" if directed else
                          f"nothing may be beside it; a {proto.name} message's "
                          f"direction is part of the message")
                raise ValueError(
                    f"message {index}: unknown key "
                    f"{', '.join(repr(k) for k in extra)} beside the "
                    f"{proto.name!r} section; {beside}"
                )
            direction = _checked_direction(
                element.get(_DIRECTION_KEY, "c2s"), index, "'direction'",
            )
            out.append((inner, direction))
        else:
            out.append((element, "c2s"))
    return out


def _built(
    proto: AppProtocol, sections: Sequence[dict[str, Any]], transport: str,
) -> list[object]:
    """Build each of *sections* as a *proto* message, naming the one that fails."""
    if not proto.carries(transport):
        raise ValueError(
            f"{proto.name!r} is carried over {proto.over}, not {transport}"
        )
    if not sections:
        raise ValueError(
            f"no {proto.name} messages: nothing carries a {proto.name!r} "
            f"section, so there is nothing to send"
        )
    built: list[object] = []
    for index, section in enumerate(sections):
        try:
            built.append(proto.from_spec(section))
        except _SECTION_ERRORS as exc:
            raise ValueError(
                f"message {index}: {type(exc).__name__}: {exc}"
            ) from exc
    return built


def _encoded(
    proto: AppProtocol, built: Sequence[object], transport: str,
) -> list[bytes]:
    """Encode each of *built* for *transport*, naming the one that fails."""
    encoded: list[bytes] = []
    for index, message in enumerate(built):
        try:
            encoded.append(proto.encode(message, transport))
        except _SECTION_ERRORS as exc:
            raise ValueError(
                f"message {index}: {type(exc).__name__}: {exc}"
            ) from exc
    return encoded


def protocol_messages(
    proto: AppProtocol,
    messages: Sequence[dict[str, Any]] | dict[str, Any],
    transport: str,
) -> list[object]:
    """Return the messages *messages* describes, built by *proto*, in order.

    The first half of :func:`protocol_payload_fn`, for a caller that sends
    messages some other way than as one payload per packet — ``stream
    --payload http --protocol-messages FILE``, which hands them to
    :attr:`HTTPRestConfig.messages
    <packeteer.generate.payloads.http.HTTPRestConfig.messages>` so an HTTP
    conversation keeps its two directions and its segmentation (#169).

    *messages* takes every shape :func:`protocol_payload_fn` does, and a
    packet with no section of *proto* is skipped the same way.

    Args:
        proto: The protocol to build with.
        messages: Its messages, in order, in any of the accepted shapes.  At
            least one must carry a section.
        transport: ``"tcp"`` or ``"udp"`` — what will carry them.

    Returns:
        One message object per section, of *proto*'s message types.

    Raises:
        ValueError: If no element carries a section, if an element is not an
            object, if the protocol does not run over *transport*, or if a
            section is not one of *proto* — with the element's index and the
            protocol's own reason.

    Example::

        from packeteer.app import http, protocol_messages
        from packeteer.generate import HTTPRestConfig, generate_http_stream

        msgs = protocol_messages(http.PROTOCOL, sections, "tcp")
        stream = generate_http_stream(
            client_ip="10.0.0.2", server_ip="10.0.0.1",
            config=HTTPRestConfig(messages=msgs),
        )

    """
    sections = _directed_sections_in(proto, messages, directed=False)
    return _built(proto, [section for section, _ in sections], transport)


def protocol_conversation(
    proto: AppProtocol,
    messages: Sequence[dict[str, Any]] | dict[str, Any],
    transport: str,
) -> list[AppMessage]:
    """Return *messages* encoded by *proto*, each with the way it travels.

    The API behind ``packeteer stream --protocol udp|tcp --payload
    <protocol> --protocol-messages FILE``, whose result goes to
    :attr:`UDPStreamConfig.messages
    <packeteer.generate.udp_stream.UDPStreamConfig.messages>` (#195) or
    :attr:`TCPStreamConfig.messages
    <packeteer.generate.tcp_stream.TCPStreamConfig.messages>` (#198) so
    that a reply leaves from the server.  It takes every shape
    :func:`protocol_payload_fn` does.  The direction of each message comes
    from, in order:

    - a whole packet's ``packet_metadata.direction``, as ``stream --json``
      writes it;
    - for a packet without one, such as ``packeteer parse`` writes, its
      addresses: the side on one of the protocol's
      :attr:`~packeteer.protocols.AppProtocol.ports` is the server, and
      otherwise the first sender in the flow is the client;
    - a wrapped section's ``"direction"`` key beside it:
      ``{"dns": {...}, "direction": "s2c"}``;
    - ``"c2s"`` for a bare section.

    Args:
        proto: The protocol to encode with.
        messages: Its messages, in the order to send them, in any of the
            accepted shapes.  At least one must carry a section.
        transport: ``"tcp"`` or ``"udp"`` — what will carry them.

    Returns:
        One :class:`~packeteer.generate.payloads.base.AppMessage` per
        section, labelled with the protocol's name and the message's index,
        such as ``dns[3]``.  :func:`~packeteer.generate.payloads.base.
        render_udp_session` renders the list as it is.

    Raises:
        ValueError: As :func:`protocol_messages`, and if a direction is not
            ``"c2s"`` or ``"s2c"``, or a wrapped section has a key beside it
            other than ``"direction"``.

    Example::

        from packeteer import protocols
        from packeteer.app import protocol_conversation
        from packeteer.generate import UDPStreamConfig, generate_udp_stream

        msgs = protocol_conversation(protocols.for_section("dns"), parsed, "udp")
        stream = generate_udp_stream(
            client_ip="10.0.0.2", server_ip="10.0.0.1", server_port=53,
            num_data_packets=len(msgs), config=UDPStreamConfig(messages=msgs),
        )

    """
    from packeteer.generate.payloads.base import AppMessage

    directed = _directed_sections_in(proto, messages)
    built = _built(proto, [section for section, _ in directed], transport)
    return [
        AppMessage(cast("Direction", direction), data, f"{proto.name}[{index}]")
        for index, ((_, direction), data) in enumerate(
            zip(directed, _encoded(proto, built, transport), strict=True),
        )
    ]


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
            protocol's own reason.  Also if a message travels server to
            client, as :func:`protocol_conversation` reads directions: a
            ``payload_fn`` sends every message from the client, and sending
            a reply that way would be wrong in silence.  Over UDP and TCP,
            :func:`protocol_conversation` and the stream config's
            ``messages`` send it the right way.

    Example::

        from packeteer import protocols
        from packeteer.app import protocol_payload_fn
        from packeteer.generate import TCPStreamConfig, generate_tcp_stream

        fn = protocol_payload_fn(protocols.for_section("dns"), sections, "tcp")
        stream = generate_tcp_stream(config=TCPStreamConfig(payload_fn=fn))

    """
    conversation = protocol_conversation(proto, messages, transport)
    for index, message in enumerate(conversation):
        if message.direction != "c2s":
            raise ValueError(
                f"message {index} travels server to client, and a payload_fn "
                f"sends every message from the client.  Pass "
                f"protocol_conversation's messages to "
                f"TCPStreamConfig.messages or UDPStreamConfig.messages "
                f"instead, which send it the right way, as stream "
                f"--protocol tcp and udp do"
            )
    encoded = [message.data for message in conversation]

    def payload_fn(index: int, _direction: str) -> bytes:
        return encoded[index % len(encoded)]

    return payload_fn

