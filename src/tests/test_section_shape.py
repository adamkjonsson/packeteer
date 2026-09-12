"""A section that is not a section is refused, not built into a default (#137).

`--protocol-messages` accepted `{"dns": {...}}` — the shape `packeteer parse`
writes — and built an empty message from it, because every `from_spec` reads
an unknown key as an absent field.  A stream of empty headers then looked like
a successful decoder test.  Two things fix it: the shape `parse` writes is
unwrapped, and a section with no recognised key at all is refused by the
protocol itself, where the conformance suite can insist on it.
"""
from __future__ import annotations

import unittest
from typing import Any

from packeteer import app, conformance, protocols
from packeteer.app import protocol_payload_fn
from packeteer.generate.dns import DNSMessage
from packeteer.protocols import AppProtocol, check_section

_DNS_KEYS = frozenset({"id", "flags", "questions"})


class TestCheckSection(unittest.TestCase):
    """The guard itself."""

    def test_an_empty_section_is_a_default_message(self) -> None:
        check_section("dns", {}, _DNS_KEYS)      # does not raise

    def test_a_partial_section_passes(self) -> None:
        check_section("dns", {"id": 7}, _DNS_KEYS)

    def test_a_partial_section_with_extras_passes(self) -> None:
        """One recognised key is enough; the rest are absent fields."""
        check_section("dns", {"id": 7, "typo": 1}, _DNS_KEYS)

    def test_nothing_recognised_is_refused(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            check_section("dns", {"nonsense": 1}, _DNS_KEYS)
        message = str(ctx.exception)
        self.assertIn("'nonsense'", message)
        self.assertIn("not a dns section", message)
        for key in sorted(_DNS_KEYS):
            self.assertIn(key, message, "the keys it expected are named")

    def test_the_wrapped_shape_is_named_as_such(self) -> None:
        """The shape `parse` writes gets told what was meant."""
        with self.assertRaises(ValueError) as ctx:
            check_section("dns", {"dns": {"id": 1}}, _DNS_KEYS)
        self.assertIn("packeteer parse", str(ctx.exception))
        self.assertIn("object under 'dns'", str(ctx.exception))

    def test_a_name_key_that_is_not_an_object_gets_no_hint(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            check_section("dns", {"dns": 5}, _DNS_KEYS)
        self.assertNotIn("packeteer parse", str(ctx.exception))


class TestTheBuiltInsRefuse(unittest.TestCase):
    """Each shipped `from_spec` opens with the guard."""

    def test_each_refuses_an_unrecognised_section(self) -> None:
        for name in ("dns", "dhcp", "http"):
            with self.subTest(name):
                proto = protocols.for_section(name)
                assert proto is not None
                with self.assertRaises(ValueError):
                    proto.from_spec({"nonsense": 1})

    def test_each_still_builds_a_default_from_nothing(self) -> None:
        for name in ("dns", "dhcp", "http"):
            with self.subTest(name):
                proto = protocols.for_section(name)
                assert proto is not None
                proto.from_spec({})     # does not raise

    def test_the_issues_reproduction(self) -> None:
        """A wrapped `raw` used to become a 12-byte empty header."""
        proto = protocols.for_section("dns")
        assert proto is not None
        with self.assertRaises(ValueError):
            proto.from_spec({"dns": {"raw": "1234"}})
        self.assertEqual(proto.encode(proto.from_spec({"raw": "1234"}), "udp"),
                         bytes.fromhex("1234"))

    def test_every_key_to_spec_writes_is_one_from_spec_reads(self) -> None:
        """Otherwise the guard could fire on packeteer's own output."""
        from packeteer.generate.dhcp import DHCPMessage
        from packeteer.generate.http import HTTPRequest, HTTPResponse

        samples = {
            "dns": [DNSMessage()],
            "dhcp": [DHCPMessage()],
            "http": [HTTPRequest(), HTTPResponse()],
        }
        for name, messages in samples.items():
            module = getattr(app, name)
            for message in messages:
                with self.subTest(name, message=type(message).__name__):
                    written = set(module.to_spec(message))
                    self.assertLessEqual(written, module._SECTION_KEYS)


class TestConformanceInsists(unittest.TestCase):
    """A protocol whose `from_spec` swallows an unknown section fails the contract."""

    def _register(self, from_spec: Any) -> AppProtocol:
        proto = AppProtocol(
            name="swallow", over="udp", ports=frozenset({9873}),
            messages=(bytearray,),
            decode=lambda b, t="udp": bytearray(b),
            encode=lambda m, t="udp": bytes(m),
            to_spec=lambda m: {"data": bytes(m).hex()},
            from_spec=from_spec,
        )
        protocols.register(proto)
        self.addCleanup(protocols.unregister, "swallow")
        return proto

    def test_a_swallowing_from_spec_is_caught(self) -> None:
        proto = self._register(lambda s: bytearray(bytes.fromhex(s.get("data", ""))))
        failures = conformance.check_protocol(proto, [bytearray(b"ab")])
        self.assertTrue(any("no key it reads" in f for f in failures), failures)
        self.assertTrue(any("check_section" in f for f in failures),
                        "the failure says how to fix it")

    def test_a_refusing_from_spec_passes_that_check(self) -> None:
        def from_spec(section: dict[str, Any]) -> bytearray:
            check_section("swallow", section, {"data"})
            return bytearray(bytes.fromhex(section.get("data", "")))

        proto = self._register(from_spec)
        failures = conformance.check_protocol(proto, [bytearray(b"ab")])
        self.assertFalse([f for f in failures if "no key it reads" in f], failures)


class TestProtocolPayloadFn(unittest.TestCase):
    """The API behind `--protocol-messages`, including the unwrap."""

    def setUp(self) -> None:
        proto = protocols.for_section("dns")
        assert proto is not None
        self.dns = proto

    def test_a_bare_section(self) -> None:
        fn = protocol_payload_fn(self.dns, [{"raw": "1234"}], "udp")
        self.assertEqual(fn(0, "c2s"), bytes.fromhex("1234"))

    def test_the_wrapped_shape_is_unwrapped(self) -> None:
        fn = protocol_payload_fn(self.dns, [{"dns": {"raw": "1234"}}], "udp")
        self.assertEqual(fn(0, "c2s"), bytes.fromhex("1234"))

    def test_a_whole_packet_spec_is_unwrapped(self) -> None:
        """What `packeteer parse` writes, element for element."""
        spec = {
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp"},
            "transport": {"src_port": 5000, "dst_port": 53},
            "dns": {"raw": "abcd"},
        }
        fn = protocol_payload_fn(self.dns, [spec], "udp")
        self.assertEqual(fn(0, "c2s"), bytes.fromhex("abcd"))

    def test_a_parse_document_is_read_and_message_less_packets_skipped(self) -> None:
        document = {"metadata": {"link_type": 1}, "packets": [
            {"ethernet": {}, "network": {"protocol": "tcp"}, "transport": {}},
            {"ethernet": {}, "network": {"protocol": "udp"}, "dns": {"raw": "aa"}},
            {"ethernet": {}, "network": {"protocol": "udp"}, "dns": {"raw": "bb"}},
        ]}
        fn = protocol_payload_fn(self.dns, document, "udp")
        self.assertEqual([fn(i, "c2s") for i in range(2)], [b"\xaa", b"\xbb"])

    def test_a_document_with_no_message_at_all_is_refused(self) -> None:
        """Skipping is for packets between messages, not for a file of none."""
        document = {"packets": [{"network": {"protocol": "tcp"}, "transport": {}}]}
        with self.assertRaises(ValueError) as ctx:
            protocol_payload_fn(self.dns, document, "udp")
        self.assertIn("nothing carries a 'dns' section", str(ctx.exception))

    def test_an_object_that_is_not_a_document_is_refused(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            protocol_payload_fn(self.dns, {"metadata": {}}, "udp")
        self.assertIn("'packets'", str(ctx.exception))

    def test_a_bare_section_using_a_layer_name_is_not_mistaken_for_a_packet(self) -> None:
        """A packet is told by link/network keys, not by anything reserved."""
        with self.assertRaises(ValueError) as ctx:
            protocol_payload_fn(self.dns, [{"timestamp": 1, "ip": 2}], "udp")
        self.assertIn("not a dns section", str(ctx.exception))

    def test_the_list_cycles(self) -> None:
        fn = protocol_payload_fn(self.dns, [{"raw": "01"}, {"raw": "02"}], "udp")
        self.assertEqual([fn(i, "c2s") for i in range(5)],
                         [b"\x01", b"\x02", b"\x01", b"\x02", b"\x01"])

    def test_the_transport_reaches_the_encoder(self) -> None:
        fn = protocol_payload_fn(self.dns, [{"raw": "1234"}], "tcp")
        self.assertEqual(fn(0, "c2s"), bytes.fromhex("0002 1234"))

    def test_a_section_that_is_not_one_names_its_index(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            protocol_payload_fn(self.dns, [{"raw": "00"}, {"nonsense": 1}], "udp")
        self.assertIn("message 1", str(ctx.exception))
        self.assertIn("not a dns section", str(ctx.exception))

    def test_an_element_that_is_not_an_object_is_refused(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            protocol_payload_fn(self.dns, [[1, 2]], "udp")
        self.assertIn("message 0", str(ctx.exception))

    def test_an_empty_list_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            protocol_payload_fn(self.dns, [], "udp")

    def test_the_wrong_transport_is_refused(self) -> None:
        dhcp = protocols.for_section("dhcp")
        assert dhcp is not None
        with self.assertRaises(ValueError) as ctx:
            protocol_payload_fn(dhcp, [{}], "tcp")
        self.assertIn("udp", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
