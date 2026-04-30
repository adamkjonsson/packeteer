"""DHCP message parser (RFC 2131 / RFC 2132).

Decodes DHCP messages from wire-format bytes.  The fixed 236-byte header is
unpacked first, followed by the 4-byte magic cookie and a variable-length
options section (type-length-value triples, terminated by option 255).
"""
from __future__ import annotations

import socket
import struct
from typing import Any, Callable

from packeteer.generate.dhcp import (
    DHCP_MAGIC_COOKIE,
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
)

# Minimum valid DHCP message: 236-byte fixed header + 4-byte magic cookie + END.
_DHCP_MIN_LEN = 241


_OPTION_DECODERS: dict[int, Callable[[bytes], Any]] = {
    DHCP_OPT_MESSAGE_TYPE: lambda d: DHCPOptMessageType(mtype=d[0]) if len(d) >= 1 else None,
    DHCP_OPT_SUBNET_MASK: lambda d: (
        DHCPOptSubnetMask(mask=socket.inet_ntoa(d)) if len(d) == 4 else None),
    DHCP_OPT_ROUTER: lambda d: (
        DHCPOptRouter(routers=[socket.inet_ntoa(d[i:i+4]) for i in range(0, len(d), 4)])
        if len(d) >= 4 and len(d) % 4 == 0 else None),
    DHCP_OPT_DNS_SERVER: lambda d: (
        DHCPOptDNSServer(servers=[socket.inet_ntoa(d[i:i+4]) for i in range(0, len(d), 4)])
        if len(d) >= 4 and len(d) % 4 == 0 else None),
    DHCP_OPT_HOSTNAME:    lambda d: DHCPOptHostname(hostname=d.decode("ascii", errors="replace")),
    DHCP_OPT_DOMAIN_NAME: lambda d: DHCPOptDomainName(domain=d.decode("ascii", errors="replace")),
    DHCP_OPT_REQUESTED_IP: lambda d: (
        DHCPOptRequestedIP(address=socket.inet_ntoa(d)) if len(d) == 4 else None),
    DHCP_OPT_LEASE_TIME: lambda d: (
        DHCPOptLeaseTime(seconds=struct.unpack("!I", d)[0]) if len(d) == 4 else None),
    DHCP_OPT_SERVER_ID: lambda d: (
        DHCPOptServerID(address=socket.inet_ntoa(d)) if len(d) == 4 else None),
    DHCP_OPT_PARAM_REQUEST_LIST: lambda d: DHCPOptParamRequestList(codes=list(d)),
    DHCP_OPT_VENDOR_CLASS_ID:    lambda d: DHCPOptVendorClassID(data=bytes(d)),
    DHCP_OPT_CLIENT_ID:          lambda d: DHCPOptClientID(data=bytes(d)),
}


def _decode_option(code: int, data: bytes) -> DHCPOpt:  # type: ignore[valid-type]
    """Decode a single option TLV body into a typed dataclass."""
    fn = _OPTION_DECODERS.get(code)
    result = fn(data) if fn is not None else None
    return result if result is not None else DHCPOptRaw(code=code, data=bytes(data))


def _decode_options(data: bytes) -> list[DHCPOpt]:  # type: ignore[valid-type]
    """Decode the options field (after the magic cookie) into a list."""
    options: list[DHCPOpt] = []  # type: ignore[valid-type]
    pos = 0
    while pos < len(data):
        code = data[pos]
        pos += 1
        if code == 255:  # END
            break
        if code == 0:    # PAD
            continue
        if pos >= len(data):
            break
        length = data[pos]
        pos += 1
        opt_data = data[pos: pos + length]
        pos += length
        options.append(_decode_option(code, opt_data))
    return options


def parse_dhcp(data: bytes) -> DHCPMessage:
    """Parse a DHCP message from a UDP payload.

    Args:
        data: Raw DHCP message bytes.

    Returns:
        A populated :class:`~packeteer.generate.dhcp.DHCPMessage`.

    Raises:
        ValueError: If the message is too short, the magic cookie is missing or
            incorrect, or the fixed header is truncated.

    Example:
        ::

            from packeteer.parse.dhcp import parse_dhcp
            from packeteer.generate.dhcp import _build_dhcp_message, DHCPMessage
            msg = parse_dhcp(_build_dhcp_message(DHCPMessage()))

    """
    if len(data) < _DHCP_MIN_LEN:
        raise ValueError(
            f"DHCP message too short: {len(data)} bytes (minimum {_DHCP_MIN_LEN})"
        )

    (
        op, htype, hlen, hops, xid, secs, flags,
        ciaddr_b, yiaddr_b, siaddr_b, giaddr_b,
    ) = struct.unpack_from("!BBBBIHH4s4s4s4s", data, 0)

    chaddr = data[28:44]
    sname  = data[44:108]
    file_  = data[108:236]

    cookie = data[236:240]
    if cookie != DHCP_MAGIC_COOKIE:
        raise ValueError(
            f"DHCP magic cookie missing or invalid: {cookie.hex()!r}"
        )

    options = _decode_options(data[240:])

    return DHCPMessage(
        op=op, htype=htype, hlen=hlen, hops=hops,
        xid=xid, secs=secs, flags=flags,
        ciaddr=socket.inet_ntoa(ciaddr_b),
        yiaddr=socket.inet_ntoa(yiaddr_b),
        siaddr=socket.inet_ntoa(siaddr_b),
        giaddr=socket.inet_ntoa(giaddr_b),
        chaddr=chaddr,
        sname=sname,
        file=file_,
        options=options,
    )
