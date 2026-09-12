"""Registry of the application-layer protocols packeteer can handle.

An **application protocol** is everything packeteer needs in order to treat a
transport payload as something other than opaque bytes: how to decode it, how
to encode it again, how to write it into a packet spec and read it back, and
how to redact it.  :class:`AppProtocol` is that contract, and this module is
where implementations announce themselves.

DNS, DHCP and HTTP are registered by :mod:`packeteer.app`, which is imported
by both :mod:`packeteer.parse` and :mod:`packeteer.generate`, so they are
present whenever either front door is used.  Anything else a caller registers
is treated identically — there is no privileged built-in path.

.. code-block:: python

    from packeteer import protocols

    protocols.register(protocols.AppProtocol(
        name="sensor", over="udp", ports=frozenset({9000}),
        messages=(Reading,),
        decode=decode, encode=encode, to_spec=to_spec, from_spec=from_spec,
    ))

The *name* doubles as the packet-spec section key, so ``"sensor"`` above makes
``packeteer parse`` emit a ``"sensor"`` object beside ``"network"`` and
``"transport"``, and ``packeteer build`` read it back.

**This module imports only the standard library, and must keep doing so.**
Both :mod:`packeteer.generate` and :mod:`packeteer.parse` depend on it, and
:mod:`packeteer.sanitise` and :mod:`packeteer.filter` import nothing from
packeteer at all — a registry that reached for a protocol module would put a
cycle between all four.  It therefore holds *callables*, never modules.
"""
from __future__ import annotations

import importlib.util
import keyword
import os
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "AppProtocol",
    "ProtocolError",
    "register",
    "unregister",
    "registered",
    "for_port",
    "for_section",
    "for_message",
    "load_module",
    "check_name",
    "check_section",
]

# Names a protocol may not take.  A protocol's name is both its packet-spec
# section key and, since #139, an attribute on ParsedPacket and a method on
# PacketBuilder — so it may not be a key that describes a packet's structure
# (its section would be read as that layer), and it may not be a public name
# on either class (``pkt.sensor`` would shadow real API in silence).
#
# The first group is the ``##`` headings in docs/packet-spec/format.md, less
# the three application sections — ``dns``, ``dhcp`` and ``http`` are
# registered names.  The second is every public attribute of ParsedPacket and
# every public method of PacketBuilder.  This module imports only the standard
# library, so the list is literal; ``test_named_accessors.py`` enumerates both
# classes and fails the moment a public name is added without reserving it.
_RESERVED_NAMES: frozenset[str] = frozenset({
    # packet-spec structural keys
    "ah", "arp", "esp", "etherip", "ethernet", "geneve", "gre", "gtpu", "ipip",
    "metadata", "mpls", "network", "packet_metadata", "payload", "pppoe",
    "pseudowire", "sll", "sll2", "transport", "vxlan",
    # ParsedPacket attributes and PacketBuilder methods not already above
    "app", "app_protocol", "build", "datagram_truncated", "fragment",
    "fragment_header", "hop_by_hop_options", "icmp", "icmpv6", "ip", "loopback",
    "payload_offset", "sctp", "source_records", "tcp", "tick_hz", "timestamp",
    "ts_frac", "ts_sec", "tunneled", "udp", "vlan",
})

_TRANSPORTS: frozenset[str] = frozenset({"tcp", "udp"})

# "either" is not a transport a packet can be on; it is a claim on both.
_OVER_VALUES: frozenset[str] = _TRANSPORTS | {"either"}


class ProtocolError(Exception):
    """Raised when a protocol cannot be registered, or is not registered."""


@dataclass(frozen=True)
class AppProtocol:
    """One application-layer protocol packeteer can parse, build and serialise.

    Attributes:
        name: Short identifier.  It is the packet-spec section key —
            ``"dns"`` produces a ``"dns"`` object in a spec — and the
            attribute the decoded message is reached by (``pkt.dns``,
            ``PacketBuilder().dns(msg)``), so it must be a plain Python
            identifier, not start with an underscore, and not be one of the
            structural keys in ``docs/packet-spec/format.md`` or a public
            name on either class.  :func:`register` refuses it otherwise.
        over: Which transport carries it — ``"udp"``, ``"tcp"``, or
            ``"either"`` for a protocol that runs over both, as DNS does.
        ports: Transport ports that identify it.  A port claim is a weak
            signal: :attr:`decode` raising is what settles a collision, so
            claiming a port a peer also uses is survivable.
        messages: Message classes this protocol decodes to and encodes from.
            :func:`for_message` dispatches on them, so they must not be shared
            with another protocol.
        decode: ``(payload, transport) -> message``.  Raises
            :class:`ValueError`, :class:`struct.error` or
            :class:`UnicodeDecodeError` when *payload* is not this protocol
            after all, which leaves the bytes as an opaque payload.
        encode: ``(message, transport) -> payload``.  *transport* is what lets
            DNS add its 2-byte length prefix over TCP (RFC 1035 §4.2.2)
            without a protocol-specific keyword argument.
        to_spec: ``message -> spec section``, the object written under
            :attr:`name` in a packet spec.
        from_spec: ``spec section -> message``, the inverse.  A key it does
            not read is an absent field, so a partial section builds a
            message with defaults — but a **non-empty section none of whose
            keys it reads must raise** rather than build a default message.
            :func:`check_section` is that guard, one call at the top; see
            it for why.
        sanitise: ``(section, replacer, options) -> None``, redacting the
            section in place.  ``None`` means **nothing is redacted**: a
            protocol registered without one flows through
            :func:`packeteer.sanitise.sanitise` untouched.
        redacts_nothing: Declare that :attr:`sanitise` redacts nothing, so
            ``packeteer sanitise`` warns instead of passing the section
            through in silence.  A compiled protocol sets it when its spec
            marks no field ``sensitive:``; a hand-written one can set it to
            say the same thing out loud, which is better than the silence a
            ``None`` *sanitise* buys.

    """

    name:     str
    over:     str
    ports:    frozenset[int]
    messages: tuple[type, ...]

    decode:    Callable[[bytes, str], object]
    encode:    Callable[[object, str], bytes]
    to_spec:   Callable[[object], dict[str, Any]]
    from_spec: Callable[[dict[str, Any]], object]
    sanitise:  Callable[[dict[str, Any], Any, Any], None] | None = None
    redacts_nothing: bool = False

    def carries(self, transport: str) -> bool:
        """Whether this protocol can be carried over *transport*.

        Args:
            transport: ``"tcp"`` or ``"udp"``.

        Returns:
            ``True`` when :attr:`over` is *transport* or ``"either"``.

        """
        return self.over in (transport, "either")


_registry:   dict[str, AppProtocol] = {}
_by_port:    dict[tuple[str, int], AppProtocol] = {}
_by_message: dict[type, AppProtocol] = {}


def _reindex() -> None:
    """Rebuild the port and message lookups from the registry."""
    _by_port.clear()
    _by_message.clear()
    for proto in _registry.values():
        for transport in sorted(_TRANSPORTS):
            if proto.carries(transport):
                for port in proto.ports:
                    _by_port[(transport, port)] = proto
        for message in proto.messages:
            _by_message[message] = proto


def check_name(name: str) -> None:
    """Refuse a name a protocol may not have.

    The rule :func:`register` applies, on its own so it can be asked earlier
    — ``packeteer protocol check`` uses it to refuse a spec whose ``name:``
    would fail at import, and a tool generating protocols can ask before it
    writes anything.  A name is a packet-spec section key and an attribute
    name at once (``pkt.sensor``, ``PacketBuilder().sensor(msg)``), so it has
    to be a plain identifier and must not shadow anything either class has.

    Args:
        name: The candidate :attr:`AppProtocol.name`.

    Raises:
        ProtocolError: If *name* is not a Python identifier, is a keyword,
            starts with an underscore, or is reserved — a packet-spec
            structural key, or a public name on
            :class:`~packeteer.parse.core.ParsedPacket` or
            :class:`~packeteer.generate.builder.PacketBuilder`.  The message
            says which.

    """
    if not name.isidentifier() or keyword.iskeyword(name):
        raise ProtocolError(
            f"protocol name {name!r} is not a Python identifier; it becomes "
            f"an attribute (pkt.{name}) and a builder method, so it must be "
            f"one — letters, digits and underscores, not starting with a digit"
        )
    if name.startswith("_"):
        raise ProtocolError(
            f"protocol name {name!r} starts with an underscore, which marks a "
            f"private attribute; a protocol is public API"
        )
    if name in _RESERVED_NAMES:
        raise ProtocolError(
            f"protocol name {name!r} is reserved: it is a packet-spec key or "
            f"an attribute of ParsedPacket / PacketBuilder, and a protocol by "
            f"that name would be read as that layer or shadow that attribute"
        )


def _check(proto: AppProtocol) -> None:
    """Raise :class:`ProtocolError` if *proto* cannot join the registry."""
    if proto.over not in _OVER_VALUES:
        raise ProtocolError(
            f"protocol {proto.name!r}: over={proto.over!r} is not one of "
            f"{', '.join(sorted(_OVER_VALUES))}"
        )
    check_name(proto.name)
    if proto.name in _registry:
        raise ProtocolError(
            f"protocol {proto.name!r} is already registered; "
            f"call unregister({proto.name!r}) first to replace it"
        )
    for transport in sorted(_TRANSPORTS):
        if not proto.carries(transport):
            continue
        for port in sorted(proto.ports):
            claimed = _by_port.get((transport, port))
            if claimed is not None:
                raise ProtocolError(
                    f"protocol {proto.name!r}: {transport} port {port} is "
                    f"already claimed by {claimed.name!r}"
                )
    for message in proto.messages:
        claimed = _by_message.get(message)
        if claimed is not None:
            raise ProtocolError(
                f"protocol {proto.name!r}: message type "
                f"{message.__name__!r} is already claimed by {claimed.name!r}"
            )


def register(proto: AppProtocol) -> None:
    """Add *proto* to the registry.

    Args:
        proto: The protocol to register.

    Raises:
        ProtocolError: If :attr:`~AppProtocol.over` is not a recognised value;
            if the name is not a plain Python identifier, starts with an
            underscore, or is reserved (a packet-spec structural key, or a
            public name on :class:`~packeteer.parse.core.ParsedPacket` or
            :class:`~packeteer.generate.builder.PacketBuilder`, which the
            name would shadow); or if the name, one of the ports, or one of
            the message types is already claimed.  The message names what
            went wrong.

    """
    _check(proto)
    _registry[proto.name] = proto
    _reindex()


def unregister(name: str) -> None:
    """Remove the protocol registered as *name*.

    The counterpart to :func:`register`, and the way to replace a registered
    protocol — including a built-in, for a caller who wants different
    behaviour on its ports.

    Args:
        name: The registered protocol's :attr:`~AppProtocol.name`.

    Raises:
        ProtocolError: If no protocol is registered under *name*.

    """
    if name not in _registry:
        raise ProtocolError(f"no protocol registered as {name!r}")
    del _registry[name]
    _reindex()


#: Names each loaded path registered, so a path loaded, unregistered and
#: loaded again runs a second time instead of silently doing nothing.
_loaded: dict[str, tuple[str, ...]] = {}


def load_module(path: str | os.PathLike) -> tuple[AppProtocol, ...]:
    """Import a Python file so the protocols it defines register themselves.

    Registration is a side effect of importing, so a protocol module has to be
    imported before it is used.  This does that for a module identified by
    path rather than by import name — a compiled spec someone has just written
    out, most often.

    **A protocol module is code, and running it is running that code.** This
    is no worse than ``import``, since the caller names the file, but it is no
    better either: treat a module someone sends you the way you would treat
    any other Python they send you.  Never take the path from data packeteer
    parsed, only from something the user wrote.

    The module is executed under a name derived from its file name, prefixed
    so it cannot collide with or shadow a real installed module, and is left
    in :data:`sys.modules` so a second call is a no-op rather than a second
    execution.

    Args:
        path: Path to a ``.py`` file.  A compiled protocol module, or any
            module whose import calls :func:`register`.

    Returns:
        The protocols the module registered, in registration order.  Empty
        when it registered none, which is worth checking: a module that
        defines a protocol and never registers it is a silent no-op.  Also
        empty when this path was already loaded and its protocols are still
        registered — but a path whose protocols have since been unregistered
        is executed again, so unregistering and reloading works.

    Raises:
        ProtocolError: If *path* does not exist, cannot be read as a module,
            or raises while executing.  The original exception is chained.

    Example::

        from packeteer import protocols

        added = protocols.load_module("./sensor.py")
        print([p.name for p in added])      # ['sensor']

    """
    resolved = os.fspath(os.path.abspath(path))
    if not os.path.isfile(resolved):
        raise ProtocolError(f"no protocol module at {os.fspath(path)!r}")

    module_name = "packeteer._loaded." + os.path.splitext(
        os.path.basename(resolved))[0]
    if module_name in sys.modules:
        registered_now = {proto.name for proto in registered()}
        if _loaded.get(resolved, ()) and set(_loaded[resolved]) <= registered_now:
            # Already loaded and still registered; executing it again would
            # collide with itself.
            return ()
        # It was loaded and then unregistered, so run it again rather than
        # doing nothing — a no-op here would look like a module that
        # registers nothing, which is a different problem entirely.
        del sys.modules[module_name]

    before = {proto.name for proto in registered()}
    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise ProtocolError(f"cannot load a Python module from {resolved!r}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        del sys.modules[module_name]
        raise ProtocolError(
            f"{os.fspath(path)} failed while being imported "
            f"({type(exc).__name__}: {exc})"
        ) from exc
    added = tuple(p for p in registered() if p.name not in before)
    _loaded[resolved] = tuple(proto.name for proto in added)
    return added


def check_section(
    name: str, section: Mapping[str, Any], known: Iterable[str],
) -> None:
    """Refuse a spec section that is not a section of protocol *name*.

    The guard every ``from_spec`` should open with.  A key ``from_spec`` does
    not read is an absent field, which is the right reading of a *partial*
    section — a spec is edited by hand, and a message with one key set is a
    message with defaults everywhere else.  It is the wrong reading of a
    section in which **nothing** is recognised, because by then the
    difference between "this message has no questions" and "this is not a
    section" has been lost, and what comes out is a default message that is
    indistinguishable from a deliberate one (#137: a generated stream carried
    forty empty DNS headers, and a decoder run over it reported forty
    messages decoded).

    An empty section is allowed through: ``{}`` is an explicit request for a
    default message.

    Args:
        name: The protocol's :attr:`~AppProtocol.name`, for the message.
        section: The object handed to ``from_spec``.
        known: Every key ``from_spec`` reads.

    Raises:
        ValueError: If *section* is non-empty and shares no key with
            *known*.  When *section* carries *name* itself as a key, the
            message says so — that is the shape ``packeteer parse`` writes,
            and the object under that key is what was meant.

    Example::

        _SECTION_KEYS = frozenset({"id", "flags", "questions", "answers"})

        def from_spec(section: dict[str, Any]) -> DNSMessage:
            protocols.check_section("dns", section, _SECTION_KEYS)
            ...

    """
    if not section:
        return
    expected = frozenset(known)
    if section.keys() & expected:
        return
    seen = sorted(section)
    shown = ", ".join(repr(k) for k in seen[:6])
    if len(seen) > 6:
        shown += f", … ({len(seen)} keys)"
    if isinstance(section.get(name), Mapping):
        hint = (
            f"; this looks like a whole packet spec, which is what "
            f"'packeteer parse' writes — the object under {name!r} is the "
            f"section"
        )
    else:
        hint = ""
    raise ValueError(
        f"{name}: not a {name} section — none of its keys ({shown}) is one "
        f"{name} reads ({', '.join(sorted(expected))}){hint}"
    )


def registered() -> tuple[AppProtocol, ...]:
    """Return every registered protocol, in registration order.

    Returns:
        A tuple of :class:`AppProtocol`.  Empty when nothing has registered —
        which is the case until :mod:`packeteer.app` is imported.

    """
    return tuple(_registry.values())


def for_port(port: int, transport: str) -> AppProtocol | None:
    """Return the protocol claiming *port* on *transport*, if any.

    Args:
        port: Transport port number.
        transport: ``"tcp"`` or ``"udp"``.

    Returns:
        The claiming :class:`AppProtocol`, or ``None``.

    """
    return _by_port.get((transport, port))


def for_section(name: str) -> AppProtocol | None:
    """Return the protocol owning the packet-spec section *name*, if any.

    Args:
        name: A packet-spec section key.

    Returns:
        The owning :class:`AppProtocol`, or ``None``.

    """
    return _registry.get(name)


def for_message(obj: object) -> AppProtocol | None:
    """Return the protocol that owns *obj*'s message type, if any.

    Matching is by :func:`isinstance`, so a subclass of a registered message
    type resolves to the same protocol.

    Args:
        obj: A candidate message object.

    Returns:
        The owning :class:`AppProtocol`, or ``None`` when *obj* is not a
        message of any registered protocol.

    """
    proto = _by_message.get(type(obj))
    if proto is not None:
        return proto
    for message, candidate in _by_message.items():
        if isinstance(obj, message):
            return candidate
    return None
