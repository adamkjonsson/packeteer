"""Registry-driven application decode in the parser (#98)."""
from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from packeteer import protocols
from packeteer.generate import PacketBuilder
from packeteer.generate.dns import DNS_TYPE_A, DNSMessage, DNSQuestion
from packeteer.generate.http import HTTPRequest
from packeteer.parse import parse_packet
from packeteer.protocols import AppProtocol

_MACS = {"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"}


@dataclass
class Reading:
    value: int = 0


def _decode(payload: bytes, transport: str) -> object:
    if len(payload) != 2:
        raise ValueError("sensor readings are two bytes")
    return Reading(value=int.from_bytes(payload, "big"))


def _sensor(**overrides: Any) -> AppProtocol:
    fields: dict[str, Any] = {
        "name": "sensor",
        "over": "udp",
        "ports": frozenset({9000}),
        "messages": (Reading,),
        "decode": _decode,
        "encode": lambda m, t: m.value.to_bytes(2, "big"),
        "to_spec": lambda m: {"value": m.value},
        "from_spec": lambda s: Reading(value=s["value"]),
    }
    fields.update(overrides)
    return AppProtocol(**fields)


def _udp(payload: bytes, *, src_port: int = 1234, dst_port: int = 9000) -> bytes:
    return (PacketBuilder().ethernet(**_MACS)
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .udp(src_port=src_port, dst_port=dst_port)
            .payload(data=payload).build())


def _dns_base(tcp: bool) -> PacketBuilder:
    """Return a builder up to the transport layer, on port 53."""
    b = PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
    return b.tcp(dst_port=53) if tcp else b.udp(dst_port=53)


class TestBuiltinsStillLandOnTheirOwnAttributes(unittest.TestCase):
    """`.dns` / `.dhcp` / `.http` are public API and keep working."""

    def test_dns_populates_both_dns_and_app(self) -> None:
        msg = DNSMessage(id=1, questions=[
            DNSQuestion(name="example.com.", qtype=DNS_TYPE_A, qclass=1)])
        frame = (PacketBuilder().ethernet(**_MACS)
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=53)
                 .dns(msg).build())
        pkt = parse_packet(frame)
        self.assertIsNotNone(pkt.dns)
        self.assertIs(pkt.dns, pkt.app)
        self.assertEqual(pkt.app_protocol, "dns")

    def test_http_populates_both_http_and_app(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS)
                 .ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=80)
                 .http(HTTPRequest(headers={"Host": "example.com"})).build())
        pkt = parse_packet(frame)
        self.assertIsNotNone(pkt.http)
        self.assertIs(pkt.http, pkt.app)
        self.assertEqual(pkt.app_protocol, "http")

    def test_a_plain_payload_sets_neither(self) -> None:
        pkt = parse_packet(_udp(b"hello", dst_port=4444))
        self.assertIsNone(pkt.app)
        self.assertIsNone(pkt.app_protocol)
        self.assertEqual(pkt.payload, b"hello")


class TestRegisteredProtocolsDecode(unittest.TestCase):

    def setUp(self) -> None:
        protocols.register(_sensor())
        self.addCleanup(protocols.unregister, "sensor")

    def test_a_registered_protocol_decodes_from_a_frame(self) -> None:
        pkt = parse_packet(_udp(b"\x01\x02"))
        self.assertEqual(pkt.app, Reading(258))
        self.assertEqual(pkt.app_protocol, "sensor")
        self.assertEqual(pkt.payload, b"")

    def test_it_does_not_land_on_a_named_attribute(self) -> None:
        """Only the three built-ins get one; everything else uses `.app`."""
        pkt = parse_packet(_udp(b"\x01\x02"))
        self.assertFalse(hasattr(pkt, "sensor"))

    def test_decode_app_false_skips_it(self) -> None:
        pkt = parse_packet(_udp(b"\x01\x02"), decode_app=False)
        self.assertIsNone(pkt.app)
        self.assertEqual(pkt.payload, b"\x01\x02")

    def test_a_decoder_that_raises_leaves_the_payload_alone(self) -> None:
        """A port claim is weak; rejecting the bytes is how a collision ends."""
        pkt = parse_packet(_udp(b"three"))
        self.assertIsNone(pkt.app)
        self.assertIsNone(pkt.app_protocol)
        self.assertEqual(pkt.payload, b"three")

    def test_the_wrong_transport_does_not_match(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS)
                 .ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=9000)
                 .payload(data=b"\x01\x02").build())
        pkt = parse_packet(frame)
        self.assertIsNone(pkt.app)
        self.assertEqual(pkt.payload, b"\x01\x02")

    def test_source_port_matches_too(self) -> None:
        pkt = parse_packet(_udp(b"\x01\x02", src_port=9000, dst_port=4444))
        self.assertEqual(pkt.app_protocol, "sensor")


class TestDestinationPortWins(unittest.TestCase):
    """Only observable once two protocols are registered — but it will be."""

    def setUp(self) -> None:
        @dataclass
        class OtherReading:
            raw: bytes = b""

        protocols.register(_sensor())
        protocols.register(_sensor(
            name="other", ports=frozenset({9001}), messages=(OtherReading,),
            decode=lambda payload, transport: OtherReading(raw=payload),
        ))
        self.addCleanup(protocols.unregister, "other")
        self.addCleanup(protocols.unregister, "sensor")

    def test_the_destination_port_decides(self) -> None:
        pkt = parse_packet(_udp(b"\x01\x02", src_port=9001, dst_port=9000))
        self.assertEqual(pkt.app_protocol, "sensor")

    def test_and_the_other_way_round(self) -> None:
        pkt = parse_packet(_udp(b"\x01\x02", src_port=9000, dst_port=9001))
        self.assertEqual(pkt.app_protocol, "other")


class TestTheBuiltinPortsDoNotOverlap(unittest.TestCase):
    """Why collapsing three sequential attempts into one lookup is safe."""

    def test_no_port_is_claimed_by_two_protocols(self) -> None:
        seen: dict[tuple[str, int], str] = {}
        for proto in protocols.registered():
            for transport in ("tcp", "udp"):
                if not proto.carries(transport):
                    continue
                for port in proto.ports:
                    key = (transport, port)
                    self.assertNotIn(key, seen)
                    seen[key] = proto.name


if __name__ == "__main__":
    unittest.main()


class TestRegisteredProtocolsReachTheSpec(unittest.TestCase):
    """Object → packet spec, through the registry rather than an isinstance ladder (#99)."""

    def setUp(self) -> None:
        protocols.register(_sensor())
        self.addCleanup(protocols.unregister, "sensor")

    def test_update_config_writes_a_section_named_after_the_protocol(self) -> None:
        from packeteer.parse.to_config import update_config

        self.assertEqual(update_config({}, Reading(258)), {"sensor": {"value": 258}})

    def test_a_parsed_packet_carries_the_section(self) -> None:
        from packeteer.parse.core import _packet_to_spec

        spec = _packet_to_spec(parse_packet(_udp(b"\x01\x02")))
        self.assertEqual(spec["sensor"], {"value": 258})
        self.assertNotIn("payload", spec)

    def test_an_undecoded_payload_still_becomes_a_payload_section(self) -> None:
        from packeteer.parse.core import _packet_to_spec

        spec = _packet_to_spec(parse_packet(_udp(b"three")))
        self.assertNotIn("sensor", spec)
        self.assertIn("payload", spec)

    def test_an_unregistered_type_still_raises_typeerror(self) -> None:
        from packeteer.parse.to_config import update_config

        with self.assertRaises(TypeError) as ctx:
            update_config({}, object())
        self.assertIn("object", str(ctx.exception))

    def test_headers_are_matched_before_the_registry(self) -> None:
        """A header must never resolve through `for_message`."""
        from packeteer.generate.udp import UDPHeader
        from packeteer.parse.to_config import update_config

        self.assertIn("transport", update_config({}, UDPHeader(1, 2)))
        self.assertIsNone(protocols.for_message(UDPHeader(1, 2)))

    def test_built_ins_still_reach_their_own_sections(self) -> None:
        from packeteer.parse.to_config import update_config

        msg = DNSMessage(id=1, questions=[
            DNSQuestion(name="example.com.", qtype=DNS_TYPE_A, qclass=1)])
        self.assertIn("dns", update_config({}, msg))
        self.assertIn("http", update_config({}, HTTPRequest()))


class TestApplyAppSection(unittest.TestCase):
    """Packet spec → payload, through the registry (#100)."""

    def setUp(self) -> None:
        protocols.register(_sensor())
        self.addCleanup(protocols.unregister, "sensor")

    def _builder(self) -> PacketBuilder:
        return (PacketBuilder().ethernet(**_MACS)
                .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9000))

    def test_no_application_section_returns_none(self) -> None:
        from packeteer.app import apply_app_section

        self.assertIsNone(apply_app_section(self._builder(), {"payload": {}}, "udp"))

    def test_a_registered_section_becomes_the_payload(self) -> None:
        from packeteer.app import apply_app_section

        b = apply_app_section(self._builder(), {"sensor": {"value": 258}}, "udp")
        self.assertIsNotNone(b)
        self.assertEqual(parse_packet(b.build()).app, Reading(258))

    def test_transport_reaches_the_encoder(self) -> None:
        """DNS over TCP needs the 2-byte length prefix; over UDP it must not."""
        from packeteer.app import apply_app_section

        section = {"dns": {"id": 1, "questions": [
            {"name": "example.com.", "qtype": DNS_TYPE_A}]}}
        over_tcp = apply_app_section(
            PacketBuilder().ethernet(**_MACS)
            .ip(src="10.0.0.1", dst="10.0.0.2").tcp(dst_port=53),
            section, "tcp").build()
        over_udp = apply_app_section(
            PacketBuilder().ethernet(**_MACS)
            .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=53),
            section, "udp").build()
        self.assertEqual(len(over_tcp) - len(over_udp), 20 - 8 + 2)

    def test_two_application_sections_is_an_error_naming_both(self) -> None:
        from packeteer.app import apply_app_section

        with self.assertRaises(ValueError) as ctx:
            apply_app_section(self._builder(), {"dns": {}, "http": {}}, "tcp")
        self.assertIn("dns", str(ctx.exception))
        self.assertIn("http", str(ctx.exception))


class TestBuildFromSpec(unittest.TestCase):
    """The CLI path, which had the same ladder twice."""

    def setUp(self) -> None:
        protocols.register(_sensor())
        self.addCleanup(protocols.unregister, "sensor")

    def _spec(self, **extra: Any) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "ethernet": dict(_MACS),
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp"},
            "transport": {"dst_port": 9000},
        }
        spec.update(extra)
        return spec

    def test_a_registered_protocol_builds(self) -> None:
        import packeteer.__main__ as cli

        b, _ = cli._apply_spec_to_builder(
            PacketBuilder(), self._spec(sensor={"value": 258}), 1)
        self.assertEqual(parse_packet(b.build()).app, Reading(258))

    def test_round_trip_through_the_spec(self) -> None:
        import packeteer.__main__ as cli
        from packeteer.parse.core import _packet_to_spec

        original = _udp(b"\x01\x02")
        spec = _packet_to_spec(parse_packet(original))
        b, _ = cli._apply_spec_to_builder(PacketBuilder(), spec, 1)
        self.assertEqual(b.build(), original)

    def test_two_sections_exits_with_a_message(self) -> None:
        import packeteer.__main__ as cli

        spec = self._spec(sensor={"value": 1}, dns={"id": 1})
        with self.assertRaises(SystemExit) as ctx:
            cli._apply_spec_to_builder(PacketBuilder(), spec, 7)
        self.assertEqual(ctx.exception.code, 1)

    def test_no_section_still_falls_back_to_payload(self) -> None:
        import packeteer.__main__ as cli

        # Port 4444 so the payload is not a sensor reading on the way back.
        spec = self._spec(payload={"data": "aabb"})
        spec["transport"] = {"dst_port": 4444}
        b, _ = cli._apply_spec_to_builder(PacketBuilder(), spec, 1)
        self.assertEqual(parse_packet(b.build()).payload, b"\xaa\xbb")


class TestPacketBuilderApp(unittest.TestCase):
    """`PacketBuilder.app` — the generic form of `.dns()` / `.dhcp()` / `.http()` (#102)."""

    def setUp(self) -> None:
        protocols.register(_sensor())
        self.addCleanup(protocols.unregister, "sensor")

    def test_a_registered_protocol_round_trips(self) -> None:
        frame = (PacketBuilder().ethernet(**_MACS)
                 .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9000)
                 .app(Reading(258)).build())
        self.assertEqual(parse_packet(frame).app, Reading(258))

    def test_it_agrees_with_the_named_method(self) -> None:
        msg = DNSMessage(id=1, questions=[
            DNSQuestion(name="example.com.", qtype=DNS_TYPE_A, qclass=1)])
        for transport, tcp in (("udp", False), ("tcp", True)):
            with self.subTest(transport=transport):
                self.assertEqual(_dns_base(tcp).app(msg).build(),
                                 _dns_base(tcp).dns(msg, tcp=tcp).build())

    def test_transport_is_taken_from_the_layer_stack(self) -> None:
        """The TCP encoding carries a 2-byte length prefix the UDP one does not."""
        msg = DNSMessage(id=1, questions=[
            DNSQuestion(name="example.com.", qtype=DNS_TYPE_A, qclass=1)])
        base = PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
        over_udp = len(base.udp(dst_port=53).app(msg)._payload_bytes)
        base = PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
        over_tcp = len(base.tcp(dst_port=53).app(msg)._payload_bytes)
        self.assertEqual(over_tcp - over_udp, 2)

    def test_the_innermost_transport_wins(self) -> None:
        """A tunnelled stack has more than one; the last one added is the one."""
        msg = DNSMessage(id=1)
        b = (PacketBuilder().ethernet(**_MACS)
             .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=4789)
             .vxlan(vni=7).ethernet(**_MACS)
             .ip(src="192.168.1.1", dst="192.168.1.2").tcp(dst_port=53))
        self.assertEqual(b._transport_name(protocols.for_section("dns")), "tcp")
        self.assertEqual(b.app(msg)._payload_bytes[:2], b"\x00\x0c")

    def test_an_unregistered_type_raises_typeerror_naming_it(self) -> None:
        with self.assertRaises(TypeError) as ctx:
            PacketBuilder().ethernet(**_MACS).app(object())
        self.assertIn("object", str(ctx.exception))

    def test_either_transport_with_no_transport_layer_raises(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            PacketBuilder().ethernet(**_MACS).app(DNSMessage())
        self.assertIn("dns", str(ctx.exception))

    def test_a_single_transport_protocol_needs_no_layer_to_infer_from(self) -> None:
        """`over` already answers the question for all but DNS."""
        b = PacketBuilder().ethernet(**_MACS).app(Reading(258))
        self.assertEqual(b._payload_bytes, b"\x01\x02")

    def test_named_methods_are_unchanged(self) -> None:
        """`.dns()` and friends keep their own signatures and are not wrappers."""
        for name in ("dns", "dhcp", "http"):
            with self.subTest(method=name):
                self.assertTrue(callable(getattr(PacketBuilder, name)))


class TestBuilderRegistersLazily(unittest.TestCase):
    """`import packeteer.generate` alone leaves the registry empty until `.app()`."""

    def test_app_works_after_importing_only_generate(self) -> None:
        import pathlib
        import subprocess
        import sys

        src = str(pathlib.Path(protocols.__file__).parent.parent)
        code = f"""
import sys
sys.path.insert(0, {src!r})
from packeteer import protocols
from packeteer.generate import PacketBuilder
from packeteer.generate.dns import DNSMessage
before = len(protocols.registered())
frame = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
         .udp(dst_port=53).app(DNSMessage(id=1)).build())
print(before, len(protocols.registered()), len(frame) > 0)
"""
        out = subprocess.run([sys.executable, "-c", code],
                             capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout.strip(), "0 3 True")
