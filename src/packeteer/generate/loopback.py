"""BSD loopback framing (DLT_NULL and DLT_LOOP).

A capture taken on the loopback interface of macOS or a BSD has no Ethernet
header.  Each packet is prefixed with a four-byte **address family** saying
which protocol follows, and nothing else — there are no addresses at the link
layer, because there is no link.

Two link types use it, differing only in byte order:

======================  =====  ==================================
Link type               Value  Byte order of the family
======================  =====  ==================================
``DLT_NULL``            0      The capturing host's, in practice little-endian
``DLT_LOOP``            108    Network order, always big-endian
======================  =====  ==================================

``AF_INET`` is 2 on every platform, but ``AF_INET6`` is not: 30 on macOS, 28 on
FreeBSD, 24 on OpenBSD and 10 on Linux.  A reader therefore cannot match one
value, and treats any of the known IPv6 families as IPv6 — which is what
libpcap's own readers do.

This matters out of proportion to how exotic it looks: on macOS and the BSDs,
``tcpdump -i lo0`` is the easiest way to capture anything you can send to
yourself, and without this packeteer cannot read a byte of it.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

__all__ = [
    "AF_INET",
    "AF_INET6_VALUES",
    "LoopbackHeader",
]

#: Every platform agrees on this one.
AF_INET: int = 2

#: ``AF_INET6`` by platform — macOS, FreeBSD, OpenBSD, Linux.  A reader accepts
#: any of them, because a capture may come from a host other than this one.
AF_INET6_VALUES: frozenset[int] = frozenset({30, 28, 24, 10})

#: What packeteer writes for IPv6 when a spec does not say.  macOS's value,
#: because macOS is where DLT_NULL captures overwhelmingly come from.
AF_INET6_DEFAULT: int = 30

_HEADER_LEN: int = 4


@dataclass
class LoopbackHeader:
    """The four-byte address family prefixing a loopback capture's packets.

    Attributes:
        family: The address family value — :data:`AF_INET` for IPv4, one of
            :data:`AF_INET6_VALUES` for IPv6.  It varies by the platform that
            captured the file, so it is recorded rather than derived.
        big_endian: Whether the four bytes are in network order.  Always
            ``True`` for ``DLT_LOOP``.  For ``DLT_NULL`` it is the capturing
            host's order, which is little-endian on every platform anyone
            captures loopback traffic on today — so ``False`` is the default
            and the other case is recorded only when a capture shows it.

    """

    family: int | None = AF_INET
    big_endian: bool = False

    @property
    def is_ipv6(self) -> bool:
        """Whether this header introduces an IPv6 packet."""
        return self.family in AF_INET6_VALUES


def _build_loopback_header(hdr: LoopbackHeader) -> bytes:
    """Build the four-byte loopback header.

    Args:
        hdr: The header to encode.

    Returns:
        Four bytes: the address family, in the order *hdr* asks for.

    """
    return struct.pack(">I" if hdr.big_endian else "<I", hdr.family)
