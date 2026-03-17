import struct
from dataclasses import dataclass

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD


@dataclass
class EthernetHeader:
    dst_mac: str
    src_mac: str
    ethertype: int = ETHERTYPE_IPV4


def _parse_mac(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(':', '').replace('-', ''))


def build_ethernet_header(hdr: EthernetHeader) -> bytes:
    """Build a 14-byte Ethernet II header."""
    return struct.pack(
        '!6s6sH',
        _parse_mac(hdr.dst_mac),
        _parse_mac(hdr.src_mac),
        hdr.ethertype,
    )
