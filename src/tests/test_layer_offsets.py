"""Where each header sits in the frame, beyond `payload_offset` (#74).

`payload_offset` closed the gap #71 was raised for and left the per-layer
half for a use case.  One arrived by accident while planning #139: once a
protocol decodes the payload, `payload` is empty and `payload_offset` is
`None`, so a tool that could cite where a TCP payload sat in the file loses
that the moment the payload is a DNS message.  `offsets["app"]` is that
entry; the rest are the headers, keyed by the attribute each is on.
"""
from __future__ import annotations

import struct
import unittest
from dataclasses import fields

from packeteer.generate import PacketBuilder
from packeteer.generate.dns import DNSMessage, DNSQuestion
from packeteer.parse import ParsedPacket, parse_packet
from packeteer.parse.core import _packet_to_spec
from packeteer.pcap import LINKTYPE_LINUX_SLL, LINKTYPE_LOOP, LINKTYPE_RAW

_MACS = {"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"}


def _ip_version_at(frame: bytes, offset: int) -> int:
    return frame[offset] >> 4


def _dst_port_at(frame: bytes, offset: int) -> int:
    return struct.unpack_from("!H", frame, offset + 2)[0]


def _tcp() -> bytes:
    return (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=1).build())


def _arp() -> bytes:
    return (PacketBuilder().ethernet(**_MACS)
            .arp(sender_ip="10.0.0.1", target_ip="10.0.0.2").build())


class TestEachLayer(unittest.TestCase):
    """The value at each offset is the header it claims to be."""

    def test_ethernet_ip_transport(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
                 .tcp(dst_port=443).payload(data=b"x" * 20).build())
        pkt = parse_packet(frame)
        self.assertEqual(pkt.offsets, {"ethernet": 0, "ip": 14, "transport": 34})
        self.assertEqual(_ip_version_at(frame, pkt.offsets["ip"]), 4)
        self.assertEqual(_dst_port_at(frame, pkt.offsets["transport"]), 443)
        self.assertEqual(pkt.payload_offset, 54)

    def test_vlan_moves_ip(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).vlan(vid=7)
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).build())
        pkt = parse_packet(frame)
        self.assertEqual(pkt.offsets["ip"], 18)
        self.assertEqual(_ip_version_at(frame, 18), 4)

    def test_ipv6(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="2001:db8::1", dst="2001:db8::2")
                 .udp(dst_port=9).build())
        pkt = parse_packet(frame)
        self.assertEqual(pkt.offsets["ip"], 14)
        self.assertEqual(_ip_version_at(frame, 14), 6)
        self.assertEqual(pkt.offsets["transport"], 14 + 40)

    def test_raw_ip_has_no_link_entry(self) -> None:
        frame = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).build()
        pkt = parse_packet(frame, link_type=LINKTYPE_RAW)
        self.assertEqual(pkt.offsets, {"ip": 0, "transport": 20})

    def test_sll_and_loopback(self) -> None:
        sll = PacketBuilder().sll().ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).build()
        pkt = parse_packet(sll, link_type=LINKTYPE_LINUX_SLL)
        self.assertEqual(pkt.offsets["sll"], 0)
        self.assertEqual(_ip_version_at(sll, pkt.offsets["ip"]), 4)

        loop = struct.pack(">I", 2) + (PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2")
                                       .udp(dst_port=9).build())
        pkt = parse_packet(loop, link_type=LINKTYPE_LOOP)
        self.assertEqual(pkt.offsets["loopback"], 0)
        self.assertEqual(pkt.offsets["ip"], 4)

    def test_mpls_records_the_first_label(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).mpls(label=100).mpls(label=200)
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).build())
        pkt = parse_packet(frame)
        self.assertEqual(len(pkt.mpls), 2)
        self.assertEqual(pkt.offsets["mpls"], 14)
        self.assertEqual(pkt.offsets["ip"], 14 + 8)

    def test_pppoe(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).pppoe(session_id=1)
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).build())
        pkt = parse_packet(frame)
        self.assertEqual(pkt.offsets["pppoe"], 14)
        self.assertEqual(_ip_version_at(frame, pkt.offsets["ip"]), 4)

    def test_arp(self) -> None:
        frame = _arp()
        pkt = parse_packet(frame)
        self.assertEqual(pkt.offsets, {"ethernet": 0, "arp": 14})
        self.assertEqual(struct.unpack_from("!H", frame, 14)[0], 1, "hardware type Ethernet")

    def test_ah_and_esp(self) -> None:
        ah = (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
              .ah(spi=1).udp(dst_port=9).build())
        pkt = parse_packet(ah)
        self.assertEqual(pkt.offsets["ah"], 34)
        self.assertEqual(_dst_port_at(ah, pkt.offsets["transport"]), 9)

        esp = (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
               .esp(spi=1).payload(data=b"opaque").build())
        pkt = parse_packet(esp)
        self.assertEqual(pkt.offsets["esp"], 34)
        self.assertEqual(struct.unpack_from("!I", esp, 34)[0], 1, "the SPI")


class TestApp(unittest.TestCase):
    """The entry that closes `payload_offset`'s gap."""

    def test_a_decoded_message_has_an_offset_when_payload_offset_does_not(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp(dst_port=53)
                 .dns(DNSMessage(id=0x1234, questions=[DNSQuestion("example.com.")]))
                 .build())
        pkt = parse_packet(frame)
        self.assertIsNotNone(pkt.dns)
        self.assertIsNone(pkt.payload_offset, "the payload was consumed")
        self.assertEqual(pkt.offsets["app"], 42)
        self.assertEqual(struct.unpack_from("!H", frame, 42)[0], 0x1234, "the DNS id")

    def test_absent_when_nothing_decoded(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp(dst_port=9).payload(data=b"x").build())
        pkt = parse_packet(frame)
        self.assertNotIn("app", pkt.offsets)
        self.assertEqual(pkt.payload_offset, 42)

    def test_absent_with_decode_app_false(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp(dst_port=53).dns(DNSMessage(id=1)).build())
        pkt = parse_packet(frame, decode_app=False)
        self.assertNotIn("app", pkt.offsets)
        self.assertEqual(pkt.payload_offset, 42)


class TestPadding(unittest.TestCase):
    """The case that motivated `payload_offset`'s own rule applies here too."""

    def test_offsets_are_unaffected_by_trailing_padding(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp(dst_port=9).payload(data=b"x").build())
        self.assertEqual(len(frame), 60, "padded to the Ethernet minimum")
        pkt = parse_packet(frame)
        self.assertEqual(pkt.offsets, {"ethernet": 0, "ip": 14, "transport": 34})
        self.assertEqual(frame[pkt.payload_offset:][:1], b"x")


class TestTunnels(unittest.TestCase):
    """Inner offsets are relative to the outermost frame, at any depth."""

    def test_gre_with_inner_ethernet(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="1.1.1.1", dst="2.2.2.2").gre()
                 .ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=80)
                 .payload(data=b"hi").build())
        pkt = parse_packet(frame)
        self.assertEqual(pkt.offsets, {"ethernet": 0, "ip": 14, "gre": 34})
        inner = pkt.tunneled
        self.assertEqual(inner.offsets, {"ethernet": 38, "ip": 52, "transport": 72})
        self.assertEqual(_dst_port_at(frame, inner.offsets["transport"]), 80)
        self.assertEqual(frame[inner.payload_offset:], b"hi")

    def test_ipip(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="1.1.1.1", dst="2.2.2.2")
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).build())
        pkt = parse_packet(frame)
        self.assertTrue(pkt.ipip)
        self.assertEqual(pkt.tunneled.offsets["ip"], 34)
        self.assertEqual(_ip_version_at(frame, 34), 4)

    def test_vxlan_and_the_udp_tunnels(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="1.1.1.1", dst="2.2.2.2")
                 .udp(dst_port=4789).vxlan(vni=5)
                 .ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).build())
        pkt = parse_packet(frame)
        self.assertEqual(pkt.offsets["transport"], 34)
        self.assertEqual(pkt.offsets["vxlan"], 42)
        self.assertEqual(pkt.tunneled.offsets["ethernet"], 50)
        self.assertEqual(_ip_version_at(frame, pkt.tunneled.offsets["ip"]), 4)

    def test_two_deep(self) -> None:
        """GRE carrying an IP-in-IP packet: three ParsedPackets, one frame."""
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="1.1.1.1", dst="2.2.2.2").gre()
                 .ip(src="3.3.3.3", dst="4.4.4.4")
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).payload(data=b"deep").build())
        outer = parse_packet(frame)
        middle = outer.tunneled
        inner = middle.tunneled
        self.assertEqual(outer.offsets["gre"], 34)
        self.assertEqual(middle.offsets, {"ip": 38})
        self.assertEqual(inner.offsets, {"ip": 58, "transport": 78})
        self.assertEqual(frame[inner.payload_offset:], b"deep")


class TestTheShape(unittest.TestCase):

    def test_a_key_is_present_exactly_when_the_layer_is(self) -> None:
        frames = [
            _tcp(),
            _arp(),
            (PacketBuilder().ethernet(**_MACS).ip(src="1.1.1.1", dst="2.2.2.2").gre()
             .ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9).build()),
        ]
        layer_fields = {f.name for f in fields(ParsedPacket)} - {
            "app", "app_protocol", "payload", "payload_offset", "offsets", "ipip",
            "tunneled", "datagram_truncated", "ts_sec", "ts_frac", "tick_hz",
            "source_records", "dns", "dhcp", "http",
        }
        for frame in frames:
            pkt = parse_packet(frame)
            while pkt is not None:
                for name in layer_fields:
                    present = getattr(pkt, name) not in (None, [])
                    self.assertEqual(name in pkt.offsets, present, name)
                pkt = pkt.tunneled

    def test_not_in_the_spec(self) -> None:
        self.assertNotIn("offsets", _packet_to_spec(parse_packet(_tcp())))

    def test_empty_on_a_bare_packet(self) -> None:
        self.assertEqual(ParsedPacket().offsets, {})


if __name__ == "__main__":
    unittest.main()
