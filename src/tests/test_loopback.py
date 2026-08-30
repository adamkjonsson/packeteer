"""BSD loopback framing, DLT_NULL and DLT_LOOP (#124).

`tcpdump -i lo0` on macOS and the BSDs produces link type 0, which packeteer
could not read at all — so the easiest traffic in the world to capture,
anything you can send to yourself, was unusable.  On Linux `lo` is `EN10MB`,
which is why this only bites on the platforms where loopback capture is most
convenient.
"""
from __future__ import annotations

import io
import unittest
import warnings

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.generate.loopback import (
    AF_INET,
    AF_INET6_DEFAULT,
    AF_INET6_VALUES,
    LoopbackHeader,
)
from packeteer.parse import iter_packets, parse_packet
from packeteer.parse.core import _packet_to_spec
from packeteer.parse.loopback import packet_parser
from packeteer.pcap import LINKTYPE_LOOP, LINKTYPE_NULL, write_pcap

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD


def _frame(*, family: int | None = None, big_endian: bool = False,
           src: str = "127.0.0.1") -> bytes:
    return (PacketBuilder().loopback(family=family, big_endian=big_endian)
            .ip(src=src, dst=src).udp(src_port=5000, dst_port=9)
            .payload(data=b"hello").build())


class TestTheHeaderItself(unittest.TestCase):

    def test_ipv4_is_family_two_everywhere(self) -> None:
        self.assertEqual(_frame()[:4].hex(), "02000000")

    def test_ipv6_uses_the_platform_value(self) -> None:
        """`AF_INET6` is 30 on macOS, 28 on FreeBSD, 24 on OpenBSD, 10 on Linux."""
        self.assertEqual(_frame(src="::1")[:4],
                         AF_INET6_DEFAULT.to_bytes(4, "little"))

    def test_dlt_loop_is_network_order(self) -> None:
        self.assertEqual(_frame(big_endian=True)[:4].hex(), "00000002")

    def test_a_pinned_family_is_written_verbatim(self) -> None:
        """A capture from another platform keeps that platform's value."""
        self.assertEqual(_frame(family=10, src="::1")[:4].hex(), "0a000000")


class TestParsing(unittest.TestCase):

    def test_families_map_to_ethertypes(self) -> None:
        self.assertEqual(packet_parser(bytes.fromhex("02000000"))[1],
                         _ETHERTYPE_IPV4)
        for family in sorted(AF_INET6_VALUES):
            with self.subTest(family=family):
                raw = family.to_bytes(4, "little")
                self.assertEqual(packet_parser(raw)[1], _ETHERTYPE_IPV6)

    def test_byte_order_is_worked_out_for_dlt_null(self) -> None:
        """Its order is the capturing host's, so a file may be either."""
        little = packet_parser(bytes.fromhex("02000000"))[2]
        big = packet_parser(bytes.fromhex("00000002"))[2]
        self.assertFalse(little.big_endian)
        self.assertTrue(big.big_endian)
        self.assertEqual(little.family, big.family)

    def test_dlt_loop_is_told_rather_than_guessed(self) -> None:
        size, ethertype, header = packet_parser(bytes.fromhex("00000002"),
                                                big_endian=True)
        self.assertEqual((size, ethertype), (4, _ETHERTYPE_IPV4))
        self.assertTrue(header.big_endian)

    def test_an_unknown_family_is_refused(self) -> None:
        self.assertEqual(packet_parser(bytes.fromhex("deadbeef")),
                         (0, None, None))

    def test_a_short_header_is_refused(self) -> None:
        self.assertEqual(packet_parser(b"\x02\x00"), (0, None, None))

    def test_is_ipv6(self) -> None:
        self.assertTrue(LoopbackHeader(family=AF_INET6_DEFAULT).is_ipv6)
        self.assertFalse(LoopbackHeader(family=AF_INET).is_ipv6)


class TestParsedPackets(unittest.TestCase):

    def test_a_loopback_packet_parses_all_the_way_down(self) -> None:
        pkt = parse_packet(_frame(), link_type=LINKTYPE_NULL, decode_app=False)
        self.assertIsNotNone(pkt.loopback)
        self.assertIsNone(pkt.ethernet)
        self.assertEqual(pkt.ip.src, "127.0.0.1")
        self.assertEqual(pkt.transport.dst_port, 9)
        self.assertEqual(pkt.payload, b"hello")

    def test_ipv6_over_loopback(self) -> None:
        pkt = parse_packet(_frame(src="::1"), link_type=LINKTYPE_NULL,
                           decode_app=False)
        self.assertEqual(pkt.ip.src, "::1")
        self.assertTrue(pkt.loopback.is_ipv6)

    def test_dlt_loop(self) -> None:
        pkt = parse_packet(_frame(big_endian=True), link_type=LINKTYPE_LOOP,
                           decode_app=False)
        self.assertTrue(pkt.loopback.big_endian)
        self.assertEqual(pkt.ip.src, "127.0.0.1")


class TestTheSpecSection(unittest.TestCase):
    """Only what a rebuild could not derive, the rule `transport.length` follows."""

    def _section(self, **kwargs: object) -> dict:
        link = LINKTYPE_LOOP if kwargs.get("big_endian") else LINKTYPE_NULL
        pkt = parse_packet(_frame(**kwargs), link_type=link, decode_app=False)
        return _packet_to_spec(pkt)["loopback"]

    def test_a_derivable_family_is_omitted(self) -> None:
        self.assertEqual(self._section(), {})
        self.assertEqual(self._section(src="::1"), {})

    def test_a_foreign_family_is_recorded(self) -> None:
        self.assertEqual(self._section(family=10, src="::1"), {"family": 10})

    def test_network_order_is_recorded(self) -> None:
        self.assertEqual(self._section(big_endian=True), {"big_endian": True})


class TestRoundTrip(unittest.TestCase):
    """The property everything else in packeteer serves."""

    def test_byte_identical_rebuilds(self) -> None:
        cases = {
            "DLT_NULL IPv4": {},
            "DLT_NULL IPv6": {"src": "::1"},
            "DLT_LOOP IPv4": {"big_endian": True},
            "a Linux capture's AF_INET6": {"family": 10, "src": "::1"},
        }
        for label, kwargs in cases.items():
            with self.subTest(case=label):
                link = LINKTYPE_LOOP if kwargs.get("big_endian") else LINKTYPE_NULL
                original = _frame(**kwargs)
                spec = _packet_to_spec(parse_packet(original, link_type=link,
                                                    decode_app=False))
                rebuilt, _ = cli._apply_spec_to_builder(PacketBuilder(), spec, 1)
                self.assertEqual(rebuilt.build(), original)

    def test_no_ethernet_header_is_invented(self) -> None:
        """The link layers are alternatives; a packet has exactly one."""
        spec = _packet_to_spec(parse_packet(_frame(), link_type=LINKTYPE_NULL,
                                            decode_app=False))
        self.assertNotIn("ethernet", spec)
        rebuilt, _ = cli._apply_spec_to_builder(PacketBuilder(), spec, 1)
        self.assertEqual(rebuilt.build()[4:6].hex(), "4500")   # IPv4 straight after

    def test_the_link_type_is_inferred_for_the_output_file(self) -> None:
        null_spec = _packet_to_spec(parse_packet(_frame(), link_type=LINKTYPE_NULL,
                                                 decode_app=False))
        loop_spec = _packet_to_spec(parse_packet(_frame(big_endian=True),
                                                 link_type=LINKTYPE_LOOP,
                                                 decode_app=False))
        self.assertEqual(cli._infer_link_type([null_spec]), LINKTYPE_NULL)
        self.assertEqual(cli._infer_link_type([loop_spec]), LINKTYPE_LOOP)


class TestAWholeCapture(unittest.TestCase):

    def test_a_dlt_null_file_reads_back(self) -> None:
        frames = [(_frame(), i, 0) for i in range(3)]
        buf = io.BytesIO()
        write_pcap(frames, file_object=buf, link_type=LINKTYPE_NULL)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with iter_packets(file_object=io.BytesIO(buf.getvalue()),
                              decode_app=False) as capture:
                packets = list(capture)
        self.assertEqual(len(packets), 3)
        self.assertTrue(all(p.loopback is not None for p in packets))
        self.assertTrue(all(p.ip.src == "127.0.0.1" for p in packets))


if __name__ == "__main__":
    unittest.main()
