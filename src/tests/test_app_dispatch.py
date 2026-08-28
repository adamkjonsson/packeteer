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
