"""Tests for replacer.sanitise()."""
import copy
import unittest

from replacer import SanitiseOptions, sanitise

# ── Helpers ───────────────────────────────────────────────────────────────────

def _simple(src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02",
            src_port=12345, dst_port=80,
            payload_data="deadbeef",
            ts_s=1700000000, ts_us=500000) -> dict:
    """Minimal single-packet config."""
    return {
        "packets": [{
            "ethernet": {"src_mac": src_mac, "dst_mac": dst_mac, "enabled": True},
            "network":   {"src": src_ip, "dst": dst_ip, "protocol": "tcp"},
            "transport": {"src_port": src_port, "dst_port": dst_port},
            "payload":   {"data": payload_data},
            "metadata":  {"timestamp_s": ts_s, "timestamp_us": ts_us},
        }]
    }


def _two_packets(src1="10.0.0.1", dst1="10.0.0.2",
                 src2="10.0.0.3", dst2="10.0.0.1") -> dict:
    """Two-packet config; dst2 == src1 to test consistency."""
    return {
        "packets": [
            {
                "ethernet": {"src_mac": "aa:00:00:00:00:01", "dst_mac": "aa:00:00:00:00:02"},
                "network":   {"src": src1, "dst": dst1, "protocol": "udp"},
                "transport": {"src_port": 5000, "dst_port": 53},
            },
            {
                "ethernet": {"src_mac": "aa:00:00:00:00:02", "dst_mac": "aa:00:00:00:00:01"},
                "network":   {"src": src2, "dst": dst2, "protocol": "udp"},
                "transport": {"src_port": 53, "dst_port": 5000},
            },
        ]
    }


def _gre_config() -> dict:
    """Outer IP + GRE + inner IP + TCP."""
    return {
        "packets": [{
            "ethernet": {"src_mac": "aa:00:00:00:00:01", "dst_mac": "aa:00:00:00:00:02"},
            "network":   {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "gre"},
            "gre": {
                "key": 99,
                "network":   {"src": "192.168.1.1", "dst": "192.168.1.2", "protocol": "tcp"},
                "transport": {"src_port": 55000, "dst_port": 443},
                "payload":   {"data": "cafebabe"},
            },
        }]
    }


def _ipip_config() -> dict:
    return {
        "packets": [{
            "ethernet": {"src_mac": "bb:00:00:00:00:01", "dst_mac": "bb:00:00:00:00:02"},
            "network":   {"src": "172.16.0.1", "dst": "172.16.0.2", "protocol": "ipip"},
            "ipip": {
                "network":   {"src": "10.1.1.1", "dst": "10.1.1.2", "protocol": "tcp"},
                "transport": {"src_port": 40000, "dst_port": 22},
            },
        }]
    }


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestSanitiseDefaults(unittest.TestCase):
    """Default options: ips=True, macs=True, ports=False, payload=False."""

    def setUp(self):
        self.cfg = _simple()
        self.out = sanitise(self.cfg)
        self.pkt = self.out["packets"][0]

    # ── IPs ──────────────────────────────────────────────────────────────────

    def test_src_ip_replaced(self):
        self.assertNotEqual(self.pkt["network"]["src"], "10.0.0.1")

    def test_dst_ip_replaced(self):
        self.assertNotEqual(self.pkt["network"]["dst"], "10.0.0.2")

    def test_src_ip_in_rfc5737_range(self):
        import ipaddress
        addr = ipaddress.IPv4Address(self.pkt["network"]["src"])
        doc_nets = [
            ipaddress.IPv4Network("192.0.2.0/24"),
            ipaddress.IPv4Network("198.51.100.0/24"),
            ipaddress.IPv4Network("203.0.113.0/24"),
        ]
        self.assertTrue(any(addr in n for n in doc_nets),
                        f"{addr} not in RFC 5737 documentation ranges")

    # ── MACs ─────────────────────────────────────────────────────────────────

    def test_src_mac_replaced(self):
        self.assertNotEqual(self.pkt["ethernet"]["src_mac"], "aa:bb:cc:dd:ee:01")

    def test_dst_mac_replaced(self):
        self.assertNotEqual(self.pkt["ethernet"]["dst_mac"], "aa:bb:cc:dd:ee:02")

    def test_src_mac_locally_administered(self):
        first_byte = int(self.pkt["ethernet"]["src_mac"].split(":")[0], 16)
        self.assertEqual(first_byte & 0x02, 0x02, "LA bit must be set")
        self.assertEqual(first_byte & 0x01, 0x00, "must be unicast")

    # ── Ports/payload/timestamps untouched ───────────────────────────────────

    def test_ports_unchanged(self):
        self.assertEqual(self.pkt["transport"]["src_port"], 12345)
        self.assertEqual(self.pkt["transport"]["dst_port"], 80)

    def test_payload_unchanged(self):
        self.assertEqual(self.pkt["payload"]["data"], "deadbeef")

    def test_timestamps_unchanged(self):
        self.assertEqual(self.pkt["metadata"]["timestamp_s"], 1700000000)
        self.assertEqual(self.pkt["metadata"]["timestamp_us"], 500000)


class TestConsistency(unittest.TestCase):
    """Same original value must always map to the same synthetic value."""

    def test_ip_consistent_across_packets(self):
        cfg = _two_packets(src1="10.0.0.1", dst1="10.0.0.2",
                           src2="10.0.0.3", dst2="10.0.0.1")
        out = sanitise(cfg)
        p0_src = out["packets"][0]["network"]["src"]  # was 10.0.0.1
        p1_dst = out["packets"][1]["network"]["dst"]  # was 10.0.0.1
        self.assertEqual(p0_src, p1_dst,
                         "Same original IP must map to same synthetic IP")

    def test_mac_consistent_across_packets(self):
        cfg = _two_packets()
        out = sanitise(cfg)
        p0_dst = out["packets"][0]["ethernet"]["dst_mac"]  # aa:00:00:00:00:02
        p1_src = out["packets"][1]["ethernet"]["src_mac"]  # aa:00:00:00:00:02
        self.assertEqual(p0_dst, p1_src,
                         "Same original MAC must map to same synthetic MAC")

    def test_different_ips_map_to_different_synthetics(self):
        out = sanitise(_two_packets())
        addrs = {
            out["packets"][0]["network"]["src"],
            out["packets"][0]["network"]["dst"],
            out["packets"][1]["network"]["src"],
        }
        self.assertEqual(len(addrs), 3, "Three distinct originals → three distinct synthetics")


class TestIPv6(unittest.TestCase):
    def test_ipv6_replaced(self):
        cfg = {
            "packets": [{
                "network": {"src": "2001:db8:1::1", "dst": "2001:db8:2::2", "protocol": "udp"},
                "transport": {"src_port": 1000, "dst_port": 2000},
            }]
        }
        out = sanitise(cfg)
        src = out["packets"][0]["network"]["src"]
        self.assertTrue(src.startswith("2001:db8:"),
                        f"IPv6 replacement {src!r} not in 2001:db8::/32")

    def test_ipv6_consistent(self):
        addr = "fd00::1"
        cfg = {
            "packets": [
                {"network": {"src": addr, "dst": "fd00::2", "protocol": "udp"},
                 "transport": {}},
                {"network": {"src": "fd00::3", "dst": addr, "protocol": "udp"},
                 "transport": {}},
            ]
        }
        out = sanitise(cfg)
        self.assertEqual(out["packets"][0]["network"]["src"],
                         out["packets"][1]["network"]["dst"])


class TestOptionalFields(unittest.TestCase):
    def test_ports_replaced_when_enabled(self):
        out = sanitise(_simple(), SanitiseOptions(ports=True))
        pkt = out["packets"][0]
        self.assertNotEqual(pkt["transport"]["src_port"], 12345)
        self.assertNotEqual(pkt["transport"]["dst_port"], 80)

    def test_ports_consistent(self):
        cfg = _two_packets()
        cfg["packets"][0]["transport"] = {"src_port": 5000, "dst_port": 53}
        cfg["packets"][1]["transport"] = {"src_port": 53,   "dst_port": 5000}
        out = sanitise(cfg, SanitiseOptions(ports=True))
        p0_src = out["packets"][0]["transport"]["src_port"]  # was 5000
        p1_dst = out["packets"][1]["transport"]["dst_port"]  # was 5000
        self.assertEqual(p0_src, p1_dst)

    def test_payload_zeroed(self):
        out = sanitise(_simple(payload_data="deadbeef"),
                       SanitiseOptions(payload=True))
        self.assertEqual(out["packets"][0]["payload"]["data"], "00000000")

    def test_payload_length_preserved(self):
        out = sanitise(_simple(payload_data="0102030405060708"),
                       SanitiseOptions(payload=True))
        zeroed = out["packets"][0]["payload"]["data"]
        self.assertEqual(len(zeroed), 16)
        self.assertEqual(zeroed, "00" * 8)

    def test_timestamps_zeroed(self):
        out = sanitise(_simple(), SanitiseOptions(timestamps=True))
        meta = out["packets"][0]["metadata"]
        self.assertEqual(meta["timestamp_s"], 0)
        self.assertEqual(meta["timestamp_us"], 0)

    def test_timestamp_ns_zeroed(self):
        cfg = {"packets": [{"metadata": {"timestamp_s": 1234, "timestamp_ns": 999}}]}
        out = sanitise(cfg, SanitiseOptions(timestamps=True))
        self.assertEqual(out["packets"][0]["metadata"]["timestamp_ns"], 0)


class TestNoOp(unittest.TestCase):
    def test_no_replacements(self):
        cfg = _simple()
        out = sanitise(cfg, SanitiseOptions(ips=False, macs=False))
        pkt_in  = cfg["packets"][0]
        pkt_out = out["packets"][0]
        self.assertEqual(pkt_out["network"]["src"],       pkt_in["network"]["src"])
        self.assertEqual(pkt_out["network"]["dst"],       pkt_in["network"]["dst"])
        self.assertEqual(pkt_out["ethernet"]["src_mac"],  pkt_in["ethernet"]["src_mac"])
        self.assertEqual(pkt_out["ethernet"]["dst_mac"],  pkt_in["ethernet"]["dst_mac"])


class TestOriginalUnmutated(unittest.TestCase):
    def test_original_not_mutated(self):
        cfg = _simple()
        original = copy.deepcopy(cfg)
        sanitise(cfg)
        self.assertEqual(cfg, original)


class TestTunnelRecursion(unittest.TestCase):
    def test_gre_inner_ips_replaced(self):
        out = sanitise(_gre_config())
        inner = out["packets"][0]["gre"]
        self.assertNotEqual(inner["network"]["src"], "192.168.1.1")
        self.assertNotEqual(inner["network"]["dst"], "192.168.1.2")

    def test_gre_outer_and_inner_same_mapping(self):
        """If inner IP equals outer IP, they must map to the same synthetic."""
        cfg = {
            "packets": [{
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "gre"},
                "gre": {
                    "network": {"src": "10.0.0.1", "dst": "10.0.0.3", "protocol": "tcp"},
                    "transport": {"src_port": 1000, "dst_port": 80},
                },
            }]
        }
        out = sanitise(cfg)
        outer_src = out["packets"][0]["network"]["src"]
        inner_src = out["packets"][0]["gre"]["network"]["src"]
        self.assertEqual(outer_src, inner_src)

    def test_gre_inner_payload_zeroed(self):
        out = sanitise(_gre_config(), SanitiseOptions(payload=True))
        self.assertEqual(out["packets"][0]["gre"]["payload"]["data"], "00000000")

    def test_gre_teb_inner_mac_replaced(self):
        cfg = {
            "packets": [{
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "gre"},
                "gre": {
                    "ethernet": {"src_mac": "cc:00:00:00:00:01", "dst_mac": "cc:00:00:00:00:02"},
                    "network":  {"src": "192.168.0.1", "dst": "192.168.0.2", "protocol": "tcp"},
                    "transport": {"src_port": 1000, "dst_port": 80},
                },
            }]
        }
        out = sanitise(cfg)
        inner_eth = out["packets"][0]["gre"]["ethernet"]
        self.assertNotEqual(inner_eth["src_mac"], "cc:00:00:00:00:01")
        first_byte = int(inner_eth["src_mac"].split(":")[0], 16)
        self.assertEqual(first_byte & 0x02, 0x02)

    def test_ipip_inner_ips_replaced(self):
        out = sanitise(_ipip_config())
        inner = out["packets"][0]["ipip"]
        self.assertNotEqual(inner["network"]["src"], "10.1.1.1")
        self.assertNotEqual(inner["network"]["dst"], "10.1.1.2")


class TestMissingKey(unittest.TestCase):
    def test_raises_on_missing_packets_key(self):
        with self.assertRaises(ValueError):
            sanitise({"file_metadata": {}})


class TestFileMetadataPreserved(unittest.TestCase):
    def test_file_metadata_untouched(self):
        cfg = {
            "file_metadata": {"from_file": "capture.pcap", "nanoseconds": False},
            "packets": [],
        }
        out = sanitise(cfg)
        self.assertEqual(out["file_metadata"], cfg["file_metadata"])


if __name__ == "__main__":
    unittest.main()
