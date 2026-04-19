"""Tests for PacketFilter — criteria matching, validation, and CLI integration."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from typing import Any

from packeteer.filter import PacketFilter
from packeteer.generate import PacketBuilder

from packeteer.pcap import write_pcap, LINKTYPE_ETHERNET


# ── helpers ───────────────────────────────────────────────────────────────────

def _pkt(
    proto: str = "tcp",
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    src_port: int = 54321,
    dst_port: int = 80,
) -> dict[str, Any]:
    """Minimal packet spec dict for filter tests."""
    return {
        "network":   {"src": src, "dst": dst, "protocol": proto},
        "transport": {"src_port": src_port, "dst_port": dst_port},
    }


def _dns_pkt() -> dict[str, Any]:
    p = _pkt(proto="udp", src_port=54321, dst_port=53)
    p["dns"] = {"id": 1, "questions": [], "answers": [], "authority": [], "additional": []}
    return p


def _http_pkt() -> dict[str, Any]:
    p = _pkt(proto="tcp", dst_port=80)
    p["http"] = {"type": "request", "method": "GET", "path": "/", "version": "1.1",
                 "headers": {}, "body": ""}
    return p


def _make_pcap(packets: list[bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    write_pcap([(p, 0, i) for i, p in enumerate(packets)],
               file_object=buf, link_type=LINKTYPE_ETHERNET)
    buf.seek(0)
    return buf


# ── PacketFilter validation ───────────────────────────────────────────────────

class TestPacketFilterValidation(unittest.TestCase):
    def test_empty_filter_is_empty(self) -> None:
        assert PacketFilter().is_empty()

    def test_proto_set_not_empty(self) -> None:
        assert not PacketFilter(proto="tcp").is_empty()

    def test_mixed_port_raises(self) -> None:
        with self.assertRaises(ValueError):
            PacketFilter(port=["80", "!443"])

    def test_mixed_src_port_raises(self) -> None:
        with self.assertRaises(ValueError):
            PacketFilter(src_port=["!80", "443"])

    def test_invalid_port_raises(self) -> None:
        with self.assertRaises(ValueError):
            PacketFilter(port=["http"])

    def test_port_out_of_range_raises(self) -> None:
        with self.assertRaises(ValueError):
            PacketFilter(dst_port=["99999"])

    def test_invalid_ip_raises(self) -> None:
        with self.assertRaises(ValueError):
            PacketFilter(src=["not-an-ip"])

    def test_mixed_host_raises(self) -> None:
        with self.assertRaises(ValueError):
            PacketFilter(host=["10.0.0.1", "!10.0.0.2"])

    def test_valid_cidr_ipv4(self) -> None:
        PacketFilter(src=["10.0.0.0/8"])  # should not raise

    def test_valid_cidr_ipv6(self) -> None:
        PacketFilter(dst=["2001:db8::/32"])  # should not raise


# ── proto criterion ───────────────────────────────────────────────────────────

class TestProtoFilter(unittest.TestCase):
    def test_match_proto_tcp(self) -> None:
        f = PacketFilter(proto="tcp")
        assert f.matches(_pkt(proto="tcp"))
        assert not f.matches(_pkt(proto="udp"))

    def test_match_proto_case_insensitive(self) -> None:
        assert PacketFilter(proto="TCP").matches(_pkt(proto="tcp"))

    def test_negate_proto(self) -> None:
        f = PacketFilter(proto="!tcp")
        assert not f.matches(_pkt(proto="tcp"))
        assert f.matches(_pkt(proto="udp"))

    def test_proto_no_network_layer(self) -> None:
        f = PacketFilter(proto="tcp")
        assert not f.matches({"transport": {"src_port": 1, "dst_port": 80}})


# ── port criteria ─────────────────────────────────────────────────────────────

class TestPortFilter(unittest.TestCase):
    def test_port_matches_dst(self) -> None:
        f = PacketFilter(port=["80"])
        assert f.matches(_pkt(dst_port=80))

    def test_port_matches_src(self) -> None:
        f = PacketFilter(port=["54321"])
        assert f.matches(_pkt(src_port=54321))

    def test_port_multi_value(self) -> None:
        f = PacketFilter(port=["80", "443"])
        assert f.matches(_pkt(dst_port=443))
        assert not f.matches(_pkt(src_port=1234, dst_port=9999))

    def test_port_negated(self) -> None:
        f = PacketFilter(port=["!80", "!443"])
        assert not f.matches(_pkt(dst_port=80))
        assert not f.matches(_pkt(src_port=443))
        assert f.matches(_pkt(src_port=1234, dst_port=8080))

    def test_src_port(self) -> None:
        f = PacketFilter(src_port=["54321"])
        assert f.matches(_pkt(src_port=54321))
        assert not f.matches(_pkt(src_port=9999))

    def test_dst_port(self) -> None:
        f = PacketFilter(dst_port=["80"])
        assert f.matches(_pkt(dst_port=80))
        assert not f.matches(_pkt(dst_port=443))

    def test_dst_port_negated(self) -> None:
        f = PacketFilter(dst_port=["!80"])
        assert not f.matches(_pkt(dst_port=80))
        assert f.matches(_pkt(dst_port=443))

    def test_no_transport_layer(self) -> None:
        f = PacketFilter(port=["80"])
        assert not f.matches({"network": {"protocol": "tcp"}})


# ── address criteria ──────────────────────────────────────────────────────────

class TestAddressFilter(unittest.TestCase):
    def test_src_exact(self) -> None:
        f = PacketFilter(src=["10.0.0.1"])
        assert f.matches(_pkt(src="10.0.0.1"))
        assert not f.matches(_pkt(src="10.0.0.2"))

    def test_dst_exact(self) -> None:
        f = PacketFilter(dst=["10.0.0.2"])
        assert f.matches(_pkt(dst="10.0.0.2"))
        assert not f.matches(_pkt(dst="10.0.0.1"))

    def test_src_cidr_ipv4(self) -> None:
        f = PacketFilter(src=["10.0.0.0/24"])
        assert f.matches(_pkt(src="10.0.0.50"))
        assert not f.matches(_pkt(src="10.0.1.1"))

    def test_dst_cidr_ipv6(self) -> None:
        f = PacketFilter(dst=["2001:db8::/32"])
        assert f.matches(_pkt(dst="2001:db8::1"))
        assert not f.matches(_pkt(dst="2001:db9::1"))

    def test_src_negated(self) -> None:
        f = PacketFilter(src=["!10.0.0.1"])
        assert not f.matches(_pkt(src="10.0.0.1"))
        assert f.matches(_pkt(src="192.168.1.1"))

    def test_src_negated_cidr(self) -> None:
        f = PacketFilter(src=["!10.0.0.0/8"])
        assert not f.matches(_pkt(src="10.5.0.1"))
        assert f.matches(_pkt(src="192.168.1.1"))

    def test_host_matches_src(self) -> None:
        f = PacketFilter(host=["10.0.0.1"])
        assert f.matches(_pkt(src="10.0.0.1", dst="10.0.0.2"))

    def test_host_matches_dst(self) -> None:
        f = PacketFilter(host=["10.0.0.2"])
        assert f.matches(_pkt(src="10.0.0.1", dst="10.0.0.2"))

    def test_host_negated_excludes_both(self) -> None:
        f = PacketFilter(host=["!10.0.0.1"])
        assert not f.matches(_pkt(src="10.0.0.1", dst="10.0.0.2"))
        assert not f.matches(_pkt(src="10.0.0.3", dst="10.0.0.1"))
        assert f.matches(_pkt(src="192.168.1.1", dst="192.168.1.2"))

    def test_host_cidr(self) -> None:
        f = PacketFilter(host=["10.0.0.0/8"])
        assert f.matches(_pkt(src="172.16.0.1", dst="10.0.0.1"))
        assert not f.matches(_pkt(src="192.168.1.1", dst="172.16.0.1"))


# ── app criterion ─────────────────────────────────────────────────────────────

class TestAppFilter(unittest.TestCase):
    def test_app_dns_matches(self) -> None:
        f = PacketFilter(app="dns")
        assert f.matches(_dns_pkt())
        assert not f.matches(_pkt())

    def test_app_http_matches(self) -> None:
        f = PacketFilter(app="http")
        assert f.matches(_http_pkt())
        assert not f.matches(_pkt())

    def test_app_negated(self) -> None:
        f = PacketFilter(app="!dns")
        assert not f.matches(_dns_pkt())
        assert f.matches(_pkt())

    def test_app_case_insensitive(self) -> None:
        assert PacketFilter(app="DNS").matches(_dns_pkt())


# ── AND combination ───────────────────────────────────────────────────────────

class TestAndCombination(unittest.TestCase):
    def test_all_criteria_must_match(self) -> None:
        f = PacketFilter(proto="tcp", dst_port=["80"], src=["10.0.0.1"])
        assert f.matches(_pkt(proto="tcp", src="10.0.0.1", dst_port=80))
        assert not f.matches(_pkt(proto="udp", src="10.0.0.1", dst_port=80))
        assert not f.matches(_pkt(proto="tcp", src="10.0.0.2", dst_port=80))
        assert not f.matches(_pkt(proto="tcp", src="10.0.0.1", dst_port=443))

    def test_empty_filter_matches_everything(self) -> None:
        f = PacketFilter()
        assert f.matches(_pkt())
        assert f.matches(_dns_pkt())
        assert f.matches({})


# ── parse_pcap_file integration ───────────────────────────────────────────────

class TestParseWithFilter(unittest.TestCase):
    def _build_raw(
        self, proto: str = "tcp", dst_port: int = 80, src: str = "10.0.0.1",
    ) -> bytes:
        b = PacketBuilder().ethernet().ip(src=src, dst="10.0.0.2")
        if proto == "tcp":
            b = b.tcp(src_port=54321, dst_port=dst_port, flags=0x018)
        else:
            b = b.udp(src_port=54321, dst_port=dst_port)
        return b.build()

    def _parse_with_filter(self, pkts: list[bytes], f: PacketFilter) -> list[dict]:
        from packeteer.parse.core import parse_pcap_file
        buf = _make_pcap(pkts)
        result = json.loads(parse_pcap_file(file_object=buf, packet_filter=f))
        return result["packets"]

    def test_filter_by_proto_keeps_matching(self) -> None:
        tcp_pkt = self._build_raw(proto="tcp", dst_port=80)
        udp_pkt = self._build_raw(proto="udp", dst_port=53)
        kept = self._parse_with_filter([tcp_pkt, udp_pkt], PacketFilter(proto="tcp"))
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["network"]["protocol"], "tcp")

    def test_filter_by_dst_port(self) -> None:
        p80  = self._build_raw(dst_port=80)
        p443 = self._build_raw(dst_port=443)
        kept = self._parse_with_filter([p80, p443], PacketFilter(dst_port=["80"]))
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["transport"]["dst_port"], 80)

    def test_filter_by_src_cidr(self) -> None:
        p1 = self._build_raw(src="10.0.0.1")
        p2 = self._build_raw(src="192.168.1.1")
        kept = self._parse_with_filter([p1, p2], PacketFilter(src=["10.0.0.0/8"]))
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["network"]["src"], "10.0.0.1")

    def test_no_filter_keeps_all(self) -> None:
        pkts = [self._build_raw(dst_port=p) for p in [80, 443, 8080]]
        kept = self._parse_with_filter(pkts, PacketFilter())
        self.assertEqual(len(kept), 3)

    def test_filter_keeps_zero_packets(self) -> None:
        pkts = [self._build_raw(proto="tcp")]
        kept = self._parse_with_filter(pkts, PacketFilter(proto="udp"))
        self.assertEqual(len(kept), 0)


# ── CLI integration ───────────────────────────────────────────────────────────

class TestFilterCLI(unittest.TestCase):
    def _write_pcap(self, packets: list[bytes]) -> str:
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        with open(path, "wb") as f:
            buf = io.BytesIO()
            write_pcap([(p, 0, i) for i, p in enumerate(packets)],
                       file_object=buf, link_type=LINKTYPE_ETHERNET)
            f.write(buf.getvalue())
        return path

    def _run_parse(self, pcap_path: str, extra_args: list[str]) -> list[dict]:
        import packeteer.__main__ as cli
        fd, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            sys.argv = ["packeteer", "parse", pcap_path, "--output", out_path] + extra_args
            cli.main()
            with open(out_path) as f:
                return json.load(f)["packets"]
        finally:
            os.unlink(out_path)

    def setUp(self) -> None:
        tcp80 = PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2") \
                               .tcp(src_port=54321, dst_port=80, flags=0x018).build()
        udp53 = PacketBuilder().ethernet().ip(src="10.0.0.1", dst="8.8.8.8") \
                               .udp(src_port=54321, dst_port=53).build()
        self.pcap_path = self._write_pcap([tcp80, udp53])

    def tearDown(self) -> None:
        os.unlink(self.pcap_path)

    def test_cli_filter_proto(self) -> None:
        kept = self._run_parse(self.pcap_path, ["--proto", "udp"])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["network"]["protocol"], "udp")

    def test_cli_filter_dst_port(self) -> None:
        kept = self._run_parse(self.pcap_path, ["--dst-port", "80"])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["transport"]["dst_port"], 80)

    def test_cli_filter_negated_proto(self) -> None:
        kept = self._run_parse(self.pcap_path, ["--proto", "!tcp"])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["network"]["protocol"], "udp")

    def test_cli_filter_combined(self) -> None:
        kept = self._run_parse(self.pcap_path, ["--proto", "tcp", "--dst-port", "80"])
        self.assertEqual(len(kept), 1)

    def test_cli_invalid_filter_exits(self) -> None:
        with self.assertRaises(SystemExit):
            self._run_parse(self.pcap_path, ["--port", "80,!443"])


if __name__ == "__main__":
    unittest.main()
