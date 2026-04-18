"""DHCP message construction (RFC 2131 / RFC 2132).

This module provides dataclasses for DHCP messages and a wire-format encoder.
DHCP messages are carried over UDP: client sends from port 68 to server port
67; server replies from port 67 to port 68 (unicast) or 255.255.255.255:68
(broadcast).

The fixed-length portion of a DHCP message is 236 bytes (RFC 2131 §2).
Variable-length options follow the 4-byte magic cookie (99.130.83.99).
Options are encoded as type-length-value triples (RFC 2132).

Supported typed option classes cover the most common options.  Unknown or
unsupported options are represented as :class:`DHCPOptRaw`.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Callable

# ── Port and protocol constants ───────────────────────────────────────────────

DHCP_PORT_SERVER: int = 67
DHCP_PORT_CLIENT: int = 68

DHCP_MAGIC_COOKIE: bytes = b"\x63\x82\x53\x63"  # 99.130.83.99 per RFC 2131

# ── op codes ──────────────────────────────────────────────────────────────────

DHCP_OP_REQUEST: int = 1   # BOOTREQUEST
DHCP_OP_REPLY:   int = 2   # BOOTREPLY

# ── DHCP message type values (option 53) ─────────────────────────────────────

DHCP_MSG_DISCOVER: int = 1
DHCP_MSG_OFFER:    int = 2
DHCP_MSG_REQUEST:  int = 3
DHCP_MSG_DECLINE:  int = 4
DHCP_MSG_ACK:      int = 5
DHCP_MSG_NAK:      int = 6
DHCP_MSG_RELEASE:  int = 7
DHCP_MSG_INFORM:   int = 8

# ── Option code constants ─────────────────────────────────────────────────────

DHCP_OPT_SUBNET_MASK:        int = 1
DHCP_OPT_ROUTER:             int = 3
DHCP_OPT_DNS_SERVER:         int = 6
DHCP_OPT_HOSTNAME:           int = 12
DHCP_OPT_DOMAIN_NAME:        int = 15
DHCP_OPT_REQUESTED_IP:       int = 50
DHCP_OPT_LEASE_TIME:         int = 51
DHCP_OPT_MESSAGE_TYPE:       int = 53
DHCP_OPT_SERVER_ID:          int = 54
DHCP_OPT_PARAM_REQUEST_LIST: int = 55
DHCP_OPT_VENDOR_CLASS_ID:    int = 60
DHCP_OPT_CLIENT_ID:          int = 61
DHCP_OPT_END:                int = 255


# ── Typed option dataclasses ──────────────────────────────────────────────────

@dataclass
class DHCPOptMessageType:
    """DHCP Message Type option (code 53).

    Attributes:
        mtype: One of the ``DHCP_MSG_*`` constants.

    """

    mtype: int


@dataclass
class DHCPOptSubnetMask:
    """Subnet Mask option (code 1).

    Attributes:
        mask: IPv4 subnet mask in dotted-decimal notation.

    """

    mask: str


@dataclass
class DHCPOptRouter:
    """Router option (code 3).

    Attributes:
        routers: List of IPv4 router addresses in preference order.

    """

    routers: list[str] = field(default_factory=list)


@dataclass
class DHCPOptDNSServer:
    """Domain Name Server option (code 6).

    Attributes:
        servers: List of IPv4 DNS server addresses in preference order.

    """

    servers: list[str] = field(default_factory=list)


@dataclass
class DHCPOptHostname:
    """Hostname option (code 12).

    Attributes:
        hostname: Client hostname string.

    """

    hostname: str


@dataclass
class DHCPOptDomainName:
    """Domain Name option (code 15).

    Attributes:
        domain: Domain name string.

    """

    domain: str


@dataclass
class DHCPOptRequestedIP:
    """Requested IP Address option (code 50).

    Attributes:
        address: IPv4 address the client is requesting.

    """

    address: str


@dataclass
class DHCPOptLeaseTime:
    """IP Address Lease Time option (code 51).

    Attributes:
        seconds: Requested or offered lease duration in seconds.

    """

    seconds: int


@dataclass
class DHCPOptServerID:
    """Server Identifier option (code 54).

    Attributes:
        address: IPv4 address of the DHCP server.

    """

    address: str


@dataclass
class DHCPOptParamRequestList:
    """Parameter Request List option (code 55).

    Attributes:
        codes: List of option codes the client is requesting.

    """

    codes: list[int] = field(default_factory=list)


@dataclass
class DHCPOptVendorClassID:
    """Vendor Class Identifier option (code 60).

    Attributes:
        data: Opaque vendor class data.

    """

    data: bytes = b""


@dataclass
class DHCPOptClientID:
    """Client Identifier option (code 61).

    Attributes:
        data: Client identifier bytes (typically htype + hardware address).

    """

    data: bytes = b""


@dataclass
class DHCPOptRaw:
    """Raw (unrecognised) DHCP option.

    Attributes:
        code: Option code.
        data: Raw option data bytes (excludes the type and length bytes).

    """

    code: int
    data: bytes = b""


# Type alias for the option union.
DHCPOpt = (
    DHCPOptMessageType | DHCPOptSubnetMask | DHCPOptRouter | DHCPOptDNSServer
    | DHCPOptHostname | DHCPOptDomainName | DHCPOptRequestedIP | DHCPOptLeaseTime
    | DHCPOptServerID | DHCPOptParamRequestList | DHCPOptVendorClassID
    | DHCPOptClientID | DHCPOptRaw
)


# ── DHCPMessage dataclass ─────────────────────────────────────────────────────

@dataclass
class DHCPMessage:
    """A complete DHCP message (RFC 2131).

    Attributes:
        op: Message op code.  1 = BOOTREQUEST, 2 = BOOTREPLY.
        htype: Hardware address type.  1 = Ethernet.
        hlen: Hardware address length in bytes.  6 for Ethernet.
        hops: Relay agent hop count; 0 for client-originating messages.
        xid: 32-bit transaction identifier chosen by the client.
        secs: Seconds since client began address acquisition.
        flags: Flags word.  Set bit 15 (``0x8000``) to request broadcast reply.
        ciaddr: Client IP address (filled by client when it has a valid IP).
        yiaddr: "Your" IP address — the address offered or assigned by the
            server.
        siaddr: IP address of next server to use in bootstrap (may be ``0.0.0.0``).
        giaddr: Relay agent IP address; ``0.0.0.0`` when no relay.
        chaddr: Client hardware address.  Must be exactly 16 bytes; pad with
            zeros beyond the actual address length.
        sname: Optional server host name (64 bytes, null-terminated).
        file: Boot file name (128 bytes, null-terminated).
        options: List of :data:`DHCPOpt` instances.  The END option (255) is
            appended automatically by the encoder.

    """

    op:      int   = DHCP_OP_REQUEST
    htype:   int   = 1
    hlen:    int   = 6
    hops:    int   = 0
    xid:     int   = 0
    secs:    int   = 0
    flags:   int   = 0
    ciaddr:  str   = "0.0.0.0"
    yiaddr:  str   = "0.0.0.0"
    siaddr:  str   = "0.0.0.0"
    giaddr:  str   = "0.0.0.0"
    chaddr:  bytes = field(default_factory=lambda: b"\x00" * 16)
    sname:   bytes = field(default_factory=lambda: b"\x00" * 64)
    file:    bytes = field(default_factory=lambda: b"\x00" * 128)
    options: list[DHCPOpt] = field(default_factory=list)  # type: ignore[assignment]


# ── Wire encoder ──────────────────────────────────────────────────────────────

def _vl(code: int, data: bytes) -> bytes:
    """Prepend a 2-byte type-length header to already-encoded option data."""
    return bytes([code, len(data)]) + data


_OPTION_ENCODERS: dict[type, Callable[[Any], bytes]] = {
    DHCPOptMessageType:      lambda o: bytes([DHCP_OPT_MESSAGE_TYPE, 1, o.mtype]),
    DHCPOptSubnetMask:       lambda o: bytes([DHCP_OPT_SUBNET_MASK, 4]) + socket.inet_aton(o.mask),
    DHCPOptRouter: lambda o: _vl(
        DHCP_OPT_ROUTER, b"".join(socket.inet_aton(r) for r in o.routers)),
    DHCPOptDNSServer: lambda o: _vl(
        DHCP_OPT_DNS_SERVER, b"".join(socket.inet_aton(s) for s in o.servers)),
    DHCPOptHostname:         lambda o: _vl(DHCP_OPT_HOSTNAME, o.hostname.encode("ascii")),
    DHCPOptDomainName:       lambda o: _vl(DHCP_OPT_DOMAIN_NAME, o.domain.encode("ascii")),
    DHCPOptRequestedIP: lambda o: bytes([DHCP_OPT_REQUESTED_IP, 4]) + socket.inet_aton(o.address),
    DHCPOptLeaseTime: lambda o: bytes([DHCP_OPT_LEASE_TIME, 4]) + struct.pack("!I", o.seconds),
    DHCPOptServerID:         lambda o: bytes([DHCP_OPT_SERVER_ID, 4]) + socket.inet_aton(o.address),
    DHCPOptParamRequestList: lambda o: _vl(DHCP_OPT_PARAM_REQUEST_LIST, bytes(o.codes)),
    DHCPOptVendorClassID:    lambda o: _vl(DHCP_OPT_VENDOR_CLASS_ID, o.data),
    DHCPOptClientID:         lambda o: _vl(DHCP_OPT_CLIENT_ID, o.data),
}


def _encode_option(opt: DHCPOpt) -> bytes:  # type: ignore[valid-type]
    """Encode a single DHCP option as type-length-value bytes."""
    fn = _OPTION_ENCODERS.get(type(opt))
    if fn is not None:
        return fn(opt)
    return bytes([opt.code, len(opt.data)]) + opt.data  # type: ignore[union-attr]


def _build_dhcp_message(msg: DHCPMessage) -> bytes:
    r"""Encode a :class:`DHCPMessage` to wire-format bytes.

    Args:
        msg: The DHCP message to encode.

    Returns:
        Wire-format bytes suitable for use as a UDP payload.

    Raises:
        ValueError: If ``chaddr`` is not exactly 16 bytes, or ``sname`` /
            ``file`` exceed their maximum lengths.

    Example:
        ::

            from packeteer.generate.dhcp import (
                DHCPMessage, DHCPOptMessageType, DHCP_MSG_DISCOVER,
                DHCP_OP_REQUEST,
            )
            wire = _build_dhcp_message(DHCPMessage(
                op=DHCP_OP_REQUEST,
                xid=0x12345678,
                chaddr=bytes.fromhex("aabbccddeeff") + b"\x00" * 10,
                options=[DHCPOptMessageType(DHCP_MSG_DISCOVER)],
            ))

    """
    if len(msg.chaddr) != 16:
        raise ValueError(
            f"DHCPMessage.chaddr must be 16 bytes, got {len(msg.chaddr)}"
        )
    sname = msg.sname[:64].ljust(64, b"\x00")
    file_ = msg.file[:128].ljust(128, b"\x00")

    header = struct.pack(
        "!BBBBIHH4s4s4s4s",
        msg.op, msg.htype, msg.hlen, msg.hops,
        msg.xid, msg.secs, msg.flags,
        socket.inet_aton(msg.ciaddr),
        socket.inet_aton(msg.yiaddr),
        socket.inet_aton(msg.siaddr),
        socket.inet_aton(msg.giaddr),
    ) + msg.chaddr + sname + file_

    options = DHCP_MAGIC_COOKIE
    for opt in msg.options:
        options += _encode_option(opt)
    options += bytes([DHCP_OPT_END])

    return header + options
