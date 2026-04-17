"""UDP header construction (RFC 768).

This module builds the 8-byte UDP header and computes the UDP checksum over
the appropriate IPv4 or IPv6 pseudo-header.

Per RFC 768, if the computed checksum is zero it **must** be transmitted as
``0xFFFF`` (all ones) because ``0x0000`` is used by the receiver to indicate
that the sender chose to omit the checksum.  This module always computes and
includes the checksum.

Pseudo-header formats used for checksum calculation:

* **IPv4** (RFC 768, 12 bytes)::

      Source IP (4) | Dest IP (4) | Zero (1) | Protocol=17 (1) | UDP length (2)

* **IPv6** (RFC 8200 §8.1, 40 bytes)::

      Source IP (16) | Dest IP (16) | UDP length (4) | Zeros (3) | Next Header=17 (1)
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from .checksum import ones_complement_checksum


@dataclass
class UDPHeader:
    """Fields of a UDP datagram header.

    Attributes:
        src_port: Source port number (0–65535).
        dst_port: Destination port number (0–65535).

    """

    src_port: int
    dst_port: int


def _pseudo_header_v4(src_ip: str, dst_ip: str, udp_length: int) -> bytes:
    """Build the 12-byte IPv4 UDP pseudo-header for checksum calculation.

    Args:
        src_ip: Source IPv4 address in dotted-decimal notation.
        dst_ip: Destination IPv4 address in dotted-decimal notation.
        udp_length: Total UDP datagram length (header + payload) in bytes.

    Returns:
        12 bytes: src(4) + dst(4) + zero(1) + protocol=17(1) + udp_length(2).

    """
    return (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack('!BBH', 0, 17, udp_length)
    )


def _pseudo_header_v6(src_ip: str, dst_ip: str, udp_length: int) -> bytes:
    """Build the 40-byte IPv6 UDP pseudo-header for checksum calculation.

    Args:
        src_ip: Source IPv6 address in any notation accepted by
            :func:`socket.inet_pton`.
        dst_ip: Destination IPv6 address in the same format.
        udp_length: Total UDP datagram length (header + payload) in bytes.

    Returns:
        40 bytes: src(16) + dst(16) + udp_length(4) + zeros(3) + next_header=17(1).

    """
    return (
        socket.inet_pton(socket.AF_INET6, src_ip)
        + socket.inet_pton(socket.AF_INET6, dst_ip)
        + struct.pack('!I3sB', udp_length, b'\x00\x00\x00', 17)
    )


def _build_udp_header(
    hdr: UDPHeader,
    payload: bytes,
    src_ip: str,
    dst_ip: str,
    ip_version: int = 4,
) -> bytes:
    """Build an 8-byte UDP header with a correct checksum.

    The *length* field is set to ``8 + len(payload)``.  The checksum covers
    the pseudo-header, the UDP header, and *payload*.  If the computed
    checksum is ``0x0000`` it is replaced with ``0xFFFF`` per RFC 768.

    Args:
        hdr: A :class:`UDPHeader` instance with the desired port values.
        payload: Application-layer payload bytes that will follow this UDP
            header.  Included in the checksum but **not** in the returned bytes.
        src_ip: Source IP address (IPv4 dotted-decimal or IPv6 colon-hex).
        dst_ip: Destination IP address in the same format as *src_ip*.
        ip_version: ``4`` for IPv4 pseudo-header (default) or ``6`` for
            IPv6 pseudo-header.

    Returns:
        Exactly 8 bytes representing the UDP header in network byte order,
        with a valid checksum.

    Raises:
        OSError: If *src_ip* or *dst_ip* is not a valid address for the
            specified *ip_version*.

    Example:
        >>> from packeteer.generate.udp import UDPHeader, _build_udp_header
        >>> hdr = UDPHeader(src_port=5000, dst_port=53)
        >>> raw = _build_udp_header(hdr, b"query", "192.168.1.1", "8.8.8.8")
        >>> len(raw)
        8
        >>> import struct; struct.unpack('!H', raw[4:6])[0]  # length field
        13

    """
    udp_length = 8 + len(payload)
    raw = struct.pack('!HHHH', hdr.src_port, hdr.dst_port, udp_length, 0)

    if ip_version == 6:
        pseudo = _pseudo_header_v6(src_ip, dst_ip, udp_length)
    else:
        pseudo = _pseudo_header_v4(src_ip, dst_ip, udp_length)

    checksum = ones_complement_checksum(pseudo + raw + payload)
    # Per RFC 768: a computed zero must be sent as 0xFFFF
    if checksum == 0:
        checksum = 0xFFFF
    return raw[:6] + struct.pack('!H', checksum)
