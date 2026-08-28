"""DHCP as an :class:`~packeteer.protocols.AppProtocol`.

:func:`from_spec` moved here from ``packeteer.__main__``.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from packeteer.generate.dhcp import (
    DHCP_OPT_CLIENT_ID,
    DHCP_OPT_DNS_SERVER,
    DHCP_OPT_DOMAIN_NAME,
    DHCP_OPT_HOSTNAME,
    DHCP_OPT_LEASE_TIME,
    DHCP_OPT_MESSAGE_TYPE,
    DHCP_OPT_PARAM_REQUEST_LIST,
    DHCP_OPT_REQUESTED_IP,
    DHCP_OPT_ROUTER,
    DHCP_OPT_SERVER_ID,
    DHCP_OPT_SUBNET_MASK,
    DHCP_OPT_VENDOR_CLASS_ID,
    DHCP_PORT_CLIENT,
    DHCP_PORT_SERVER,
    DHCPMessage,
    DHCPOpt,
    DHCPOptClientID,
    DHCPOptDNSServer,
    DHCPOptDomainName,
    DHCPOptHostname,
    DHCPOptLeaseTime,
    DHCPOptMessageType,
    DHCPOptParamRequestList,
    DHCPOptRaw,
    DHCPOptRequestedIP,
    DHCPOptRouter,
    DHCPOptServerID,
    DHCPOptSubnetMask,
    DHCPOptVendorClassID,
    _build_dhcp_message,
)
from packeteer.protocols import AppProtocol


def encode(msg: object, transport: str = "udp") -> bytes:
    """Encode a :class:`~packeteer.generate.dhcp.DHCPMessage` to wire bytes.

    Args:
        msg: The message to encode.
        transport: Unused — DHCP runs over UDP only.

    Returns:
        The encoded message.

    """
    assert isinstance(msg, DHCPMessage)
    return _build_dhcp_message(msg)


def decode(payload: bytes, transport: str = "udp") -> DHCPMessage:
    """Decode wire bytes into a :class:`~packeteer.generate.dhcp.DHCPMessage`.

    Args:
        payload: UDP payload bytes.
        transport: Unused — DHCP runs over UDP only.

    Returns:
        The decoded message.

    Raises:
        ValueError: If *payload* is not a well-formed DHCP message.

    """
    from packeteer.parse.dhcp import parse_dhcp

    return parse_dhcp(payload)


def to_spec(msg: object) -> dict[str, Any]:
    """Return the ``dhcp`` packet-spec section for *msg*.

    Args:
        msg: The :class:`~packeteer.generate.dhcp.DHCPMessage` to serialise.

    Returns:
        The section, as it appears under ``"dhcp"`` in a packet spec.

    """
    from packeteer.parse.to_config import _apply_dhcp

    config: dict[str, Any] = {}
    _apply_dhcp(config, msg)
    return config["dhcp"]


_OPTION_BUILDERS: dict[int, Callable[[dict[str, Any]], DHCPOpt]] = {  # type: ignore[valid-type]
    DHCP_OPT_MESSAGE_TYPE:       lambda d: DHCPOptMessageType(mtype=d.get("mtype", 1)),
    DHCP_OPT_SUBNET_MASK:        lambda d: DHCPOptSubnetMask(mask=d.get("mask", "255.255.255.0")),
    DHCP_OPT_ROUTER:             lambda d: DHCPOptRouter(routers=d.get("routers", [])),
    DHCP_OPT_DNS_SERVER:         lambda d: DHCPOptDNSServer(servers=d.get("servers", [])),
    DHCP_OPT_HOSTNAME:           lambda d: DHCPOptHostname(hostname=d.get("hostname", "")),
    DHCP_OPT_DOMAIN_NAME:        lambda d: DHCPOptDomainName(domain=d.get("domain", "")),
    DHCP_OPT_REQUESTED_IP:       lambda d: DHCPOptRequestedIP(address=d.get("address", "0.0.0.0")),
    DHCP_OPT_LEASE_TIME:         lambda d: DHCPOptLeaseTime(seconds=d.get("seconds", 86400)),
    DHCP_OPT_SERVER_ID:          lambda d: DHCPOptServerID(address=d.get("address", "0.0.0.0")),
    DHCP_OPT_PARAM_REQUEST_LIST: lambda d: DHCPOptParamRequestList(codes=d.get("codes", [])),
    DHCP_OPT_VENDOR_CLASS_ID: lambda d: DHCPOptVendorClassID(data=bytes.fromhex(d.get("data", ""))),
    DHCP_OPT_CLIENT_ID:          lambda d: DHCPOptClientID(data=bytes.fromhex(d.get("data", ""))),
}


def _option_from_spec(d: dict[str, Any]) -> DHCPOpt:  # type: ignore[valid-type]
    """Build one option from an ``options`` entry of a spec section."""
    code = d.get("code", 0)
    fn = _OPTION_BUILDERS.get(code)
    if fn is not None:
        return fn(d)
    return DHCPOptRaw(code=code, data=bytes.fromhex(d.get("data", "")))


def from_spec(section: dict[str, Any]) -> DHCPMessage:
    """Build a :class:`~packeteer.generate.dhcp.DHCPMessage` from a spec section.

    Args:
        section: The object found under ``"dhcp"`` in a packet spec.

    Returns:
        The message it describes.

    """
    chaddr_hex = section.get("chaddr", "00" * 16)
    chaddr = bytes.fromhex(chaddr_hex).ljust(16, b"\x00")[:16]
    sname_str = section.get("sname", "")
    file_str  = section.get("file", "")
    return DHCPMessage(
        op=section.get("op", 1),
        htype=section.get("htype", 1),
        hlen=section.get("hlen", 6),
        hops=section.get("hops", 0),
        xid=section.get("xid", 0),
        secs=section.get("secs", 0),
        flags=section.get("flags", 0),
        ciaddr=section.get("ciaddr", "0.0.0.0"),
        yiaddr=section.get("yiaddr", "0.0.0.0"),
        siaddr=section.get("siaddr", "0.0.0.0"),
        giaddr=section.get("giaddr", "0.0.0.0"),
        chaddr=chaddr,
        sname=sname_str.encode("ascii")[:64].ljust(64, b"\x00"),
        file=file_str.encode("ascii")[:128].ljust(128, b"\x00"),
        options=[_option_from_spec(o) for o in section.get("options", [])],
    )


def sanitise(section: dict[str, Any], replacer: Any, options: Any) -> None:
    """Redact *section* in place.

    Args:
        section: A ``dhcp`` packet-spec section.
        replacer: The consistent-replacement map for the whole capture.
        options: The :class:`~packeteer.sanitise.SanitiseOptions` in force.

    """
    from packeteer.sanitise import _sanitise_dhcp

    _sanitise_dhcp(section, replacer, options)


PROTOCOL = AppProtocol(
    name="dhcp",
    over="udp",
    ports=frozenset({DHCP_PORT_SERVER, DHCP_PORT_CLIENT}),
    messages=(DHCPMessage,),
    decode=decode,
    encode=encode,
    to_spec=to_spec,
    from_spec=from_spec,
    sanitise=sanitise,
)
