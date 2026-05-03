"""Tests for packeteer.fuzz — spec-level and byte-level mutations."""
from __future__ import annotations

import struct
import unittest

from packeteer.fuzz import (
    ALL_MUTATION_NAMES,
    BYTE_MUTATION_NAMES,
    MUTATION_NAMES,
    FuzzOptions,
    FuzzVariant,
    fuzz,
    fuzz_bytes,
)
from packeteer.generate import PacketBuilder

# ── Helpers ───────────────────────────────────────────────────────────────────

def _tcp_config() -> dict:
    """Single-packet TCP spec with all common numeric fields present."""
    return {
        "packets": [{
            "network": {
                "src": "10.0.0.1", "dst": "10.0.0.2",
                "protocol": "tcp",
                "ttl": 64, "tos": 0, "identification": 1,
                "flags": 0b010, "fragment_offset": 0,
            },
            "transport": {
                "src_port": 12345, "dst_port": 80,
                "flags": 0x002, "window": 65535,
                "seq": 1000, "ack": 0, "urgent_ptr": 0,
            },
            "payload": {"data": "deadbeefcafebabe"},
        }]
    }


def _udp_config() -> dict:
    return {
        "packets": [{
            "network":   {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp",
                          "ttl": 64},
            "transport": {"src_port": 12345, "dst_port": 53},
            "payload":   {"data": "aabbccdd"},
        }]
    }


def _icmp_config() -> dict:
    return {
        "packets": [{
            "network":   {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "icmp"},
            "transport": {"type": 8, "code": 0, "identifier": 1, "sequence": 1},
        }]
    }


def _sctp_config() -> dict:
    return {
        "packets": [{
            "network":   {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "sctp"},
            "transport": {"src_port": 1234, "dst_port": 9999, "verification_tag": 0},
        }]
    }


def _no_payload_config() -> dict:
    return {
        "packets": [{
            "network":   {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp"},
            "transport": {"src_port": 12345, "dst_port": 80, "flags": 0x002},
        }]
    }


def _raw_tcp() -> bytes:
    """Ethernet + IPv4 + TCP raw packet with a 4-byte payload."""
    return (PacketBuilder()
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(src_port=12345, dst_port=80)
            .payload(size=4)
            .build())


def _raw_udp() -> bytes:
    """Ethernet + IPv4 + UDP raw packet with a 4-byte payload."""
    return (PacketBuilder()
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .udp(src_port=12345, dst_port=53)
            .payload(size=4)
            .build())


def _labels(variants: list[FuzzVariant]) -> list[str]:
    return [v.label for v in variants]


def _byte_labels(pairs: list[tuple[str, bytes]]) -> list[str]:
    return [lbl for lbl, _ in pairs]


# ── Constants ─────────────────────────────────────────────────────────────────

class TestConstants(unittest.TestCase):
    def test_mutation_names_count(self) -> None:
        self.assertEqual(len(MUTATION_NAMES), 5)

    def test_byte_mutation_names_count(self) -> None:
        self.assertEqual(len(BYTE_MUTATION_NAMES), 3)

    def test_all_mutation_names_is_concat(self) -> None:
        self.assertEqual(ALL_MUTATION_NAMES, MUTATION_NAMES + BYTE_MUTATION_NAMES)

    def test_known_spec_names(self) -> None:
        for name in ("boundary", "reserved-bits", "tcp-flags", "truncate", "extend"):
            self.assertIn(name, MUTATION_NAMES)

    def test_known_byte_names(self) -> None:
        for name in ("bit-flip", "wrong-checksum", "wrong-length"):
            self.assertIn(name, BYTE_MUTATION_NAMES)


# ── FuzzOptions defaults ──────────────────────────────────────────────────────

class TestFuzzOptions(unittest.TestCase):
    def test_default_mutations_is_all(self) -> None:
        opts = FuzzOptions()
        self.assertEqual(opts.mutations, list(ALL_MUTATION_NAMES))

    def test_default_count(self) -> None:
        self.assertEqual(FuzzOptions().count, 10)

    def test_default_seed_is_none(self) -> None:
        self.assertIsNone(FuzzOptions().seed)

    def test_custom_values(self) -> None:
        opts = FuzzOptions(mutations=["boundary"], count=5, seed=42)
        self.assertEqual(opts.mutations, ["boundary"])
        self.assertEqual(opts.count, 5)
        self.assertEqual(opts.seed, 42)

    def test_default_mutations_independent_instances(self) -> None:
        a = FuzzOptions()
        b = FuzzOptions()
        a.mutations.append("x")
        self.assertNotIn("x", b.mutations)


# ── fuzz() error handling ─────────────────────────────────────────────────────

class TestFuzzErrors(unittest.TestCase):
    def test_missing_packets_key(self) -> None:
        with self.assertRaises(ValueError):
            fuzz({})

    def test_unknown_mutation_name(self) -> None:
        with self.assertRaises(ValueError):
            fuzz(_tcp_config(), FuzzOptions(mutations=["bogus"]))

    def test_error_message_names_the_bad_mutation(self) -> None:
        with self.assertRaises(ValueError, msg="bogus") as ctx:
            fuzz(_tcp_config(), FuzzOptions(mutations=["bogus"]))
        self.assertIn("bogus", str(ctx.exception))


# ── Original config not mutated ───────────────────────────────────────────────

class TestFuzzOriginalUnmutated(unittest.TestCase):
    def test_original_not_mutated(self) -> None:
        import copy
        cfg = _tcp_config()
        original = copy.deepcopy(cfg)
        fuzz(cfg)
        self.assertEqual(cfg, original)

    def test_variant_spec_is_independent(self) -> None:
        cfg = _tcp_config()
        variants = fuzz(cfg, FuzzOptions(mutations=["boundary"]))
        first_spec = variants[0].spec
        first_spec["network"]["ttl"] = 9999
        self.assertNotEqual(cfg["packets"][0]["network"]["ttl"], 9999)


# ── FuzzVariant structure ─────────────────────────────────────────────────────

class TestFuzzVariantShape(unittest.TestCase):
    def setUp(self) -> None:
        self.variants = fuzz(_tcp_config())

    def test_all_items_are_fuzz_variant(self) -> None:
        for v in self.variants:
            self.assertIsInstance(v, FuzzVariant)

    def test_source_idx_zero_for_single_packet(self) -> None:
        for v in self.variants:
            self.assertEqual(v.source_idx, 0)

    def test_mutation_field_is_known_spec_name(self) -> None:
        for v in self.variants:
            self.assertIn(v.mutation, MUTATION_NAMES)

    def test_label_is_non_empty_string(self) -> None:
        for v in self.variants:
            self.assertIsInstance(v.label, str)
            self.assertTrue(v.label)

    def test_spec_is_dict(self) -> None:
        for v in self.variants:
            self.assertIsInstance(v.spec, dict)

    def test_variants_non_empty_for_tcp_config(self) -> None:
        self.assertGreater(len(self.variants), 0)


# ── Boundary mutation ─────────────────────────────────────────────────────────

class TestBoundaryMutation(unittest.TestCase):
    def setUp(self) -> None:
        self.variants = fuzz(_tcp_config(), FuzzOptions(mutations=["boundary"]))

    def test_all_variants_are_boundary(self) -> None:
        for v in self.variants:
            self.assertEqual(v.mutation, "boundary")

    def test_ttl_zero_variant_exists(self) -> None:
        self.assertIn("boundary: network.ttl=0", _labels(self.variants))

    def test_ttl_max_variant_exists(self) -> None:
        self.assertIn("boundary: network.ttl=255", _labels(self.variants))

    def test_ttl_zero_variant_has_correct_value(self) -> None:
        v = next(v for v in self.variants if v.label == "boundary: network.ttl=0")
        self.assertEqual(v.spec["network"]["ttl"], 0)

    def test_dst_port_zero_variant_exists(self) -> None:
        self.assertIn("boundary: transport.dst_port=0", _labels(self.variants))

    def test_dst_port_max_variant_exists(self) -> None:
        self.assertIn("boundary: transport.dst_port=65535", _labels(self.variants))

    def test_tcp_window_boundary_variants(self) -> None:
        labels = _labels(self.variants)
        self.assertIn("boundary: transport.window=0", labels)
        self.assertIn("boundary: transport.window=65535", labels)

    def test_tcp_seq_boundary_variants(self) -> None:
        labels = _labels(self.variants)
        self.assertIn("boundary: transport.seq=0", labels)
        self.assertIn("boundary: transport.seq=4294967295", labels)

    def test_udp_has_port_boundaries_but_no_tcp_fields(self) -> None:
        variants = fuzz(_udp_config(), FuzzOptions(mutations=["boundary"]))
        labels = _labels(variants)
        self.assertIn("boundary: transport.dst_port=0", labels)
        self.assertNotIn("boundary: transport.window=0", labels)

    def test_icmp_boundary_type_code(self) -> None:
        variants = fuzz(_icmp_config(), FuzzOptions(mutations=["boundary"]))
        labels = _labels(variants)
        self.assertIn("boundary: transport.type=0", labels)
        self.assertIn("boundary: transport.type=255", labels)
        self.assertIn("boundary: transport.code=0", labels)

    def test_sctp_verification_tag_boundary(self) -> None:
        variants = fuzz(_sctp_config(), FuzzOptions(mutations=["boundary"]))
        labels = _labels(variants)
        self.assertIn("boundary: transport.verification_tag=0", labels)
        self.assertIn("boundary: transport.verification_tag=4294967295", labels)

    def test_fields_not_in_spec_produce_no_variant(self) -> None:
        cfg = {"packets": [{"network": {"src": "1.2.3.4", "dst": "5.6.7.8",
                                        "protocol": "tcp"}}]}
        variants = fuzz(cfg, FuzzOptions(mutations=["boundary"]))
        for v in variants:
            self.assertNotIn("ttl", v.label)


# ── Reserved-bits mutation ────────────────────────────────────────────────────

class TestReservedBitsMutation(unittest.TestCase):
    def setUp(self) -> None:
        self.variants = fuzz(_tcp_config(), FuzzOptions(mutations=["reserved-bits"]))
        self.labels = _labels(self.variants)

    def test_evil_bit_variant_exists(self) -> None:
        self.assertTrue(any("evil bit" in lbl for lbl in self.labels))

    def test_evil_bit_has_reserved_flag_set(self) -> None:
        v = next(v for v in self.variants if "evil bit" in v.label)
        self.assertEqual(v.spec["network"]["flags"] & 0b100, 0b100)

    def test_df_plus_mf_variant_exists(self) -> None:
        self.assertTrue(any("DF+MF" in lbl for lbl in self.labels))

    def test_df_plus_mf_value(self) -> None:
        v = next(v for v in self.variants if "DF+MF" in v.label)
        self.assertEqual(v.spec["network"]["flags"], 0b011)

    def test_tcp_reserved_nibble_variants(self) -> None:
        self.assertTrue(any("TCP reserved" in lbl for lbl in self.labels))

    def test_tcp_reserved_values(self) -> None:
        reserved_variants = [v for v in self.variants if "TCP reserved" in v.label]
        values = {v.spec["transport"]["reserved"] for v in reserved_variants}
        self.assertIn(1, values)
        self.assertIn(7, values)

    def test_no_evil_bit_variants_without_flags_field(self) -> None:
        cfg = {"packets": [{"network": {"src": "1.2.3.4", "dst": "5.6.7.8",
                                        "protocol": "tcp"},
                            "transport": {"src_port": 1, "dst_port": 2, "flags": 0}}]}
        variants = fuzz(cfg, FuzzOptions(mutations=["reserved-bits"]))
        labels = _labels(variants)
        self.assertFalse(any("evil bit" in lbl for lbl in labels))
        self.assertTrue(any("TCP reserved" in lbl for lbl in labels))


# ── TCP-flags mutation ────────────────────────────────────────────────────────

class TestTCPFlagsMutation(unittest.TestCase):
    def setUp(self) -> None:
        self.variants = fuzz(_tcp_config(), FuzzOptions(mutations=["tcp-flags"]))

    def test_all_variants_are_tcp_flags(self) -> None:
        for v in self.variants:
            self.assertEqual(v.mutation, "tcp-flags")

    def test_syn_fin_variant(self) -> None:
        self.assertTrue(any("SYN+FIN" in lbl for lbl in _labels(self.variants)))
        v = next(v for v in self.variants if "SYN+FIN" in v.label)
        self.assertEqual(v.spec["transport"]["flags"], 0x03)

    def test_null_scan_variant(self) -> None:
        self.assertTrue(any("null" in lbl for lbl in _labels(self.variants)))
        v = next(v for v in self.variants if "null" in v.label)
        self.assertEqual(v.spec["transport"]["flags"], 0x00)

    def test_all_flags_variant(self) -> None:
        self.assertTrue(any("all flags" in lbl for lbl in _labels(self.variants)))
        v = next(v for v in self.variants if "all flags" in v.label)
        self.assertEqual(v.spec["transport"]["flags"], 0xFF)

    def test_no_variants_for_udp(self) -> None:
        variants = fuzz(_udp_config(), FuzzOptions(mutations=["tcp-flags"]))
        self.assertEqual(variants, [])

    def test_no_variants_for_icmp(self) -> None:
        variants = fuzz(_icmp_config(), FuzzOptions(mutations=["tcp-flags"]))
        self.assertEqual(variants, [])

    def test_multiple_combos(self) -> None:
        self.assertGreater(len(self.variants), 3)


# ── Truncate mutation ─────────────────────────────────────────────────────────

class TestTruncateMutation(unittest.TestCase):
    def setUp(self) -> None:
        self.variants = fuzz(_tcp_config(), FuzzOptions(mutations=["truncate"]))
        self.labels = _labels(self.variants)

    def test_payload_removed_variant(self) -> None:
        self.assertTrue(any("removed entirely" in lbl for lbl in self.labels))

    def test_removed_variant_has_no_payload(self) -> None:
        v = next(v for v in self.variants if "removed entirely" in v.label)
        self.assertNotIn("payload", v.spec)

    def test_one_byte_variant(self) -> None:
        self.assertTrue(any("1 byte" in lbl for lbl in self.labels))

    def test_one_byte_variant_has_correct_data(self) -> None:
        v = next(v for v in self.variants if "1 byte" in v.label)
        self.assertEqual(len(v.spec["payload"]["data"]), 2)  # 1 byte = 2 hex chars

    def test_25_percent_variant(self) -> None:
        self.assertTrue(any("25%" in lbl for lbl in self.labels))

    def test_50_percent_variant(self) -> None:
        self.assertTrue(any("50%" in lbl for lbl in self.labels))

    def test_no_variants_without_payload(self) -> None:
        variants = fuzz(_no_payload_config(), FuzzOptions(mutations=["truncate"]))
        self.assertEqual(variants, [])

    def test_no_variants_for_empty_payload(self) -> None:
        cfg = {"packets": [{"network": {"src": "1.2.3.4", "dst": "5.6.7.8",
                                        "protocol": "tcp"},
                            "payload": {"data": ""}}]}
        variants = fuzz(cfg, FuzzOptions(mutations=["truncate"]))
        self.assertEqual(variants, [])


# ── Extend mutation ───────────────────────────────────────────────────────────

class TestExtendMutation(unittest.TestCase):
    def setUp(self) -> None:
        self.variants = fuzz(_tcp_config(), FuzzOptions(mutations=["extend"]))
        self.labels = _labels(self.variants)
        self.original_data = "deadbeefcafebabe"
        self.original_len = len(self.original_data) // 2  # 8 bytes

    def test_zero_byte_extensions_present(self) -> None:
        self.assertTrue(any("+1 zero" in lbl for lbl in self.labels))
        self.assertTrue(any("+512 zero" in lbl for lbl in self.labels))

    def test_random_bytes_extension_present(self) -> None:
        self.assertTrue(any("+16 random" in lbl for lbl in self.labels))

    def test_one_zero_appended_data(self) -> None:
        v = next(v for v in self.variants if "+1 zero" in v.label)
        data = v.spec["payload"]["data"]
        self.assertEqual(data, self.original_data + "00")

    def test_sixteen_random_appended_length(self) -> None:
        v = next(v for v in self.variants if "+16 random" in v.label)
        data = v.spec["payload"]["data"]
        self.assertEqual(len(data) // 2, self.original_len + 16)

    def test_extends_even_without_payload(self) -> None:
        variants = fuzz(_no_payload_config(), FuzzOptions(mutations=["extend"]))
        self.assertGreater(len(variants), 0)

    def test_random_bytes_reproducible_with_seed(self) -> None:
        v1 = fuzz(_tcp_config(), FuzzOptions(mutations=["extend"], seed=1))
        v2 = fuzz(_tcp_config(), FuzzOptions(mutations=["extend"], seed=1))
        rand1 = next(v for v in v1 if "+16 random" in v.label)
        rand2 = next(v for v in v2 if "+16 random" in v.label)
        self.assertEqual(rand1.spec["payload"]["data"], rand2.spec["payload"]["data"])


# ── Selective mutations ───────────────────────────────────────────────────────

class TestSelectiveMutations(unittest.TestCase):
    def test_only_boundary_applied(self) -> None:
        variants = fuzz(_tcp_config(), FuzzOptions(mutations=["boundary"]))
        for v in variants:
            self.assertEqual(v.mutation, "boundary")

    def test_only_tcp_flags_applied(self) -> None:
        variants = fuzz(_tcp_config(), FuzzOptions(mutations=["tcp-flags"]))
        for v in variants:
            self.assertEqual(v.mutation, "tcp-flags")

    def test_two_mutations_applied(self) -> None:
        variants = fuzz(_tcp_config(),
                        FuzzOptions(mutations=["boundary", "tcp-flags"]))
        mutations_seen = {v.mutation for v in variants}
        self.assertIn("boundary", mutations_seen)
        self.assertIn("tcp-flags", mutations_seen)
        self.assertNotIn("truncate", mutations_seen)

    def test_empty_mutations_returns_empty(self) -> None:
        variants = fuzz(_tcp_config(), FuzzOptions(mutations=[]))
        self.assertEqual(variants, [])

    def test_byte_level_names_silently_ignored(self) -> None:
        variants = fuzz(_tcp_config(),
                        FuzzOptions(mutations=["bit-flip", "wrong-checksum"]))
        self.assertEqual(variants, [])


# ── Multiple source packets ───────────────────────────────────────────────────

class TestMultipleSourcePackets(unittest.TestCase):
    def _two_packet_config(self) -> dict:
        pkt0 = _tcp_config()["packets"][0]
        pkt1 = _udp_config()["packets"][0]
        return {"packets": [pkt0, pkt1]}

    def test_source_idx_set_correctly(self) -> None:
        variants = fuzz(self._two_packet_config(),
                        FuzzOptions(mutations=["boundary"]))
        seen = {v.source_idx for v in variants}
        self.assertIn(0, seen)
        self.assertIn(1, seen)

    def test_pkt0_variants_use_tcp_fields(self) -> None:
        variants = fuzz(self._two_packet_config(),
                        FuzzOptions(mutations=["boundary"]))
        pkt0_variants = [v for v in variants if v.source_idx == 0]
        labels = [v.label for v in pkt0_variants]
        self.assertTrue(any("transport.window" in lbl for lbl in labels))

    def test_pkt1_variants_use_udp_fields(self) -> None:
        variants = fuzz(self._two_packet_config(),
                        FuzzOptions(mutations=["boundary"]))
        pkt1_variants = [v for v in variants if v.source_idx == 1]
        labels = [v.label for v in pkt1_variants]
        self.assertFalse(any("transport.window" in lbl for lbl in labels))

    def test_empty_packets_list_returns_empty(self) -> None:
        variants = fuzz({"packets": []})
        self.assertEqual(variants, [])


# ── fuzz_bytes() error handling ───────────────────────────────────────────────

class TestFuzzBytesErrors(unittest.TestCase):
    def test_unknown_mutation_name(self) -> None:
        with self.assertRaises(ValueError):
            fuzz_bytes(b"\x00" * 20, FuzzOptions(mutations=["bogus"]))

    def test_error_names_bad_mutation(self) -> None:
        with self.assertRaises(ValueError, msg="bogus") as ctx:
            fuzz_bytes(b"\x00" * 20, FuzzOptions(mutations=["bogus"]))
        self.assertIn("bogus", str(ctx.exception))


# ── fuzz_bytes() — bit-flip ───────────────────────────────────────────────────

class TestFuzzBytesBitFlip(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = _raw_tcp()

    def test_count_variants_produced(self) -> None:
        pairs = fuzz_bytes(self.raw, FuzzOptions(mutations=["bit-flip"], count=7, seed=0))
        self.assertEqual(len(pairs), 7)

    def test_each_variant_differs_in_exactly_one_bit(self) -> None:
        pairs = fuzz_bytes(self.raw, FuzzOptions(mutations=["bit-flip"], count=5, seed=0))
        for _label, corrupted in pairs:
            diffs = sum(bin(a ^ b).count("1")
                        for a, b in zip(self.raw, corrupted, strict=True))
            self.assertEqual(diffs, 1)

    def test_output_same_length_as_input(self) -> None:
        pairs = fuzz_bytes(self.raw, FuzzOptions(mutations=["bit-flip"], count=3, seed=0))
        for _label, corrupted in pairs:
            self.assertEqual(len(corrupted), len(self.raw))

    def test_labels_contain_bit_flip_prefix(self) -> None:
        pairs = fuzz_bytes(self.raw, FuzzOptions(mutations=["bit-flip"], count=2, seed=0))
        for label, _ in pairs:
            self.assertTrue(label.startswith("bit-flip"))

    def test_reproducible_with_seed(self) -> None:
        opts = FuzzOptions(mutations=["bit-flip"], count=5, seed=99)
        pairs_a = fuzz_bytes(self.raw, opts)
        pairs_b = fuzz_bytes(self.raw, opts)
        self.assertEqual([lbl for lbl, _ in pairs_a], [lbl for lbl, _ in pairs_b])
        for (_, ba), (_, bb) in zip(pairs_a, pairs_b, strict=True):
            self.assertEqual(ba, bb)

    def test_empty_bytes_returns_empty(self) -> None:
        pairs = fuzz_bytes(b"", FuzzOptions(mutations=["bit-flip"]))
        self.assertEqual(pairs, [])


# ── fuzz_bytes() — wrong-checksum ────────────────────────────────────────────

class TestFuzzBytesWrongChecksum(unittest.TestCase):
    _IP_OFF = 14  # standard Ethernet, no VLAN

    def test_ip_checksum_zero_variant_exists(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["wrong-checksum"]))
        self.assertTrue(any("IP checksum=0x0000" in lbl for lbl in _byte_labels(pairs)))

    def test_ip_checksum_ffff_variant_exists(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["wrong-checksum"]))
        self.assertTrue(any("IP checksum=0xffff" in lbl for lbl in _byte_labels(pairs)))

    def test_ip_checksum_zero_bytes_correct(self) -> None:
        raw = _raw_tcp()
        pairs = fuzz_bytes(raw, FuzzOptions(mutations=["wrong-checksum"]))
        corrupted = next(b for lbl, b in pairs if "IP checksum=0x0000" in lbl)
        self.assertEqual(struct.unpack_from("!H", corrupted, self._IP_OFF + 10)[0], 0x0000)

    def test_ip_checksum_ffff_bytes_correct(self) -> None:
        raw = _raw_tcp()
        pairs = fuzz_bytes(raw, FuzzOptions(mutations=["wrong-checksum"]))
        corrupted = next(b for lbl, b in pairs if "IP checksum=0xffff" in lbl)
        self.assertEqual(struct.unpack_from("!H", corrupted, self._IP_OFF + 10)[0], 0xFFFF)

    def test_inverted_ip_checksum_variant_exists(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["wrong-checksum"]))
        self.assertTrue(any("inverted" in lbl for lbl in _byte_labels(pairs)))

    def test_tcp_checksum_variants_exist(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["wrong-checksum"]))
        labels = _byte_labels(pairs)
        self.assertTrue(any("TCP checksum=0x0000" in lbl for lbl in labels))
        self.assertTrue(any("TCP checksum=0xffff" in lbl for lbl in labels))

    def test_udp_checksum_variants_exist(self) -> None:
        pairs = fuzz_bytes(_raw_udp(), FuzzOptions(mutations=["wrong-checksum"]))
        self.assertTrue(any("UDP checksum=0x0000" in lbl
                            for lbl in _byte_labels(pairs)))

    def test_tcp_checksum_zero_at_correct_offset(self) -> None:
        raw = _raw_tcp()
        ihl = (raw[self._IP_OFF] & 0x0F) * 4
        t_off = self._IP_OFF + ihl
        pairs = fuzz_bytes(raw, FuzzOptions(mutations=["wrong-checksum"]))
        corrupted = next(b for lbl, b in pairs if "TCP checksum=0x0000" in lbl)
        self.assertEqual(struct.unpack_from("!H", corrupted, t_off + 16)[0], 0x0000)

    def test_only_ip_checksum_variants_for_non_tcp_udp(self) -> None:
        raw = (PacketBuilder()
               .ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .icmp(type=8, code=0)
               .build())
        pairs = fuzz_bytes(raw, FuzzOptions(mutations=["wrong-checksum"]))
        labels = _byte_labels(pairs)
        self.assertTrue(any("IP checksum" in lbl for lbl in labels))
        self.assertFalse(any("TCP checksum" in lbl for lbl in labels))
        self.assertFalse(any("UDP checksum" in lbl for lbl in labels))

    def test_non_ipv4_frame_returns_empty(self) -> None:
        raw_arp = (b"\xff\xff\xff\xff\xff\xff" + b"\x00" * 6
                   + b"\x08\x06" + b"\x00" * 28)
        pairs = fuzz_bytes(raw_arp, FuzzOptions(mutations=["wrong-checksum"]))
        self.assertEqual(pairs, [])

    def test_too_short_returns_empty(self) -> None:
        pairs = fuzz_bytes(b"\x00" * 10, FuzzOptions(mutations=["wrong-checksum"]))
        self.assertEqual(pairs, [])


# ── fuzz_bytes() — wrong-length ──────────────────────────────────────────────

class TestFuzzBytesWrongLength(unittest.TestCase):
    _IP_OFF = 14

    def test_ip_length_zero_variant_exists(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["wrong-length"]))
        self.assertTrue(any("IP total_length=0" in lbl for lbl in _byte_labels(pairs)))

    def test_ip_length_max_variant_exists(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["wrong-length"]))
        self.assertTrue(any("IP total_length=0xffff" in lbl
                            for lbl in _byte_labels(pairs)))

    def test_ip_length_zero_at_correct_offset(self) -> None:
        raw = _raw_tcp()
        pairs = fuzz_bytes(raw, FuzzOptions(mutations=["wrong-length"]))
        corrupted = next(b for lbl, b in pairs if "IP total_length=0" in lbl)
        self.assertEqual(struct.unpack_from("!H", corrupted, self._IP_OFF + 2)[0], 0)

    def test_ip_length_ffff_at_correct_offset(self) -> None:
        raw = _raw_tcp()
        pairs = fuzz_bytes(raw, FuzzOptions(mutations=["wrong-length"]))
        corrupted = next(b for lbl, b in pairs if "IP total_length=0xffff" in lbl)
        self.assertEqual(struct.unpack_from("!H", corrupted, self._IP_OFF + 2)[0], 0xFFFF)

    def test_off_by_one_variants_exist(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["wrong-length"]))
        labels = _byte_labels(pairs)
        self.assertTrue(any("actual-1" in lbl for lbl in labels))
        self.assertTrue(any("actual+1" in lbl for lbl in labels))

    def test_udp_length_variants_exist(self) -> None:
        pairs = fuzz_bytes(_raw_udp(), FuzzOptions(mutations=["wrong-length"]))
        labels = _byte_labels(pairs)
        self.assertTrue(any("UDP length=0" in lbl for lbl in labels))
        self.assertTrue(any("UDP length=0xffff" in lbl for lbl in labels))
        self.assertTrue(any("UDP length=7" in lbl for lbl in labels))

    def test_udp_length_zero_at_correct_offset(self) -> None:
        raw = _raw_udp()
        ihl = (raw[self._IP_OFF] & 0x0F) * 4
        t_off = self._IP_OFF + ihl
        pairs = fuzz_bytes(raw, FuzzOptions(mutations=["wrong-length"]))
        corrupted = next(b for lbl, b in pairs if "UDP length=0" in lbl)
        self.assertEqual(struct.unpack_from("!H", corrupted, t_off + 4)[0], 0)

    def test_no_udp_variants_for_tcp_packet(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["wrong-length"]))
        self.assertFalse(any("UDP length" in lbl for lbl in _byte_labels(pairs)))

    def test_non_ipv4_frame_returns_empty(self) -> None:
        raw_arp = (b"\xff\xff\xff\xff\xff\xff" + b"\x00" * 6
                   + b"\x08\x06" + b"\x00" * 28)
        pairs = fuzz_bytes(raw_arp, FuzzOptions(mutations=["wrong-length"]))
        self.assertEqual(pairs, [])


# ── fuzz_bytes() — spec names silently ignored ────────────────────────────────

class TestFuzzBytesSpecNamesIgnored(unittest.TestCase):
    def test_boundary_ignored(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["boundary"]))
        self.assertEqual(pairs, [])

    def test_tcp_flags_ignored(self) -> None:
        pairs = fuzz_bytes(_raw_tcp(), FuzzOptions(mutations=["tcp-flags"]))
        self.assertEqual(pairs, [])

    def test_all_spec_names_ignored(self) -> None:
        opts = FuzzOptions(mutations=list(MUTATION_NAMES))
        pairs = fuzz_bytes(_raw_tcp(), opts)
        self.assertEqual(pairs, [])

    def test_mixed_spec_and_byte_names(self) -> None:
        opts = FuzzOptions(mutations=["boundary", "bit-flip"], count=3, seed=0)
        pairs = fuzz_bytes(_raw_tcp(), opts)
        self.assertEqual(len(pairs), 3)
        for label, _ in pairs:
            self.assertTrue(label.startswith("bit-flip"))


# ── fuzz_bytes() — default options ───────────────────────────────────────────

class TestFuzzBytesDefaults(unittest.TestCase):
    def test_default_returns_variants(self) -> None:
        pairs = fuzz_bytes(_raw_tcp())
        self.assertGreater(len(pairs), 0)

    def test_default_includes_all_mutation_families(self) -> None:
        raw = _raw_tcp()
        pairs = fuzz_bytes(raw)
        labels = _byte_labels(pairs)
        self.assertTrue(any("bit-flip" in lbl for lbl in labels))
        self.assertTrue(any("wrong-checksum" in lbl for lbl in labels))
        self.assertTrue(any("wrong-length" in lbl for lbl in labels))


if __name__ == "__main__":
    unittest.main()
