"""Redacting the addresses inside ICMP and ICMPv6 payloads (#122).

The bug this covers: `sanitise` had no ICMP handling at all, so a Neighbour
Discovery capture came out with the Ethernet and IPv6 headers replaced and the
*same* addresses still present inside the payload — including a link-layer
option holding the real MAC.  Since an IPv6 link-local address is EUI-64
derived from the MAC, that one option reconstructs the address that was
replaced, which made the output a file that looks sanitised and is not.
"""
from __future__ import annotations

import ipaddress
import unittest
import warnings

from packeteer.generate import PacketBuilder
from packeteer.parse import parse_packet
from packeteer.parse.core import _packet_to_spec
from packeteer.sanitise import PersonalDataWarning, SanitiseOptions, sanitise

_SRC_MAC = "1c:0b:8b:3c:e7:a3"
_DST_MAC = "ca:3c:65:71:19:01"
_SRC_IP = "fe80::1e0b:8bff:fe3c:e7a3"          # EUI-64 of _SRC_MAC
_DST_IP = "fe80::dd:7b47:f062:2217"


def _packed(addr: str) -> bytes:
    return ipaddress.ip_address(addr).packed


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def _spec(payload: bytes, *, icmp_type: int, v6: bool = True,
          identifier: int = 0, sequence: int = 0) -> dict:
    """Return the packet spec for one ICMP packet carrying *payload*."""
    builder = PacketBuilder().ethernet(src_mac=_SRC_MAC, dst_mac=_DST_MAC)
    if v6:
        builder = builder.ip(src=_SRC_IP, dst=_DST_IP).icmpv6(
            type=icmp_type, code=0, identifier=identifier, sequence=sequence)
    else:
        builder = builder.ip(src="192.0.2.1", dst="192.0.2.9").icmp(
            type=icmp_type, code=0, identifier=identifier, sequence=sequence)
    frame = builder.payload(data=payload).build()
    return _packet_to_spec(parse_packet(frame, decode_app=False))


def _clean(spec: dict, **options: bool) -> dict:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return sanitise({"packets": [spec]}, SanitiseOptions(**options))["packets"][0]


def _payload(pkt: dict) -> bytes:
    return bytes.fromhex(pkt["payload"]["data"])


def _nd(target: str, opt_type: int = 1, mac: str = _SRC_MAC) -> bytes:
    """Return a Neighbour Solicitation payload: a target, then an option."""
    return _packed(target) + bytes([opt_type, 1]) + _mac_bytes(mac)


class TestNeighbourDiscovery(unittest.TestCase):

    def setUp(self) -> None:
        self.clean = _clean(_spec(_nd(_DST_IP), icmp_type=135))
        self.body = _payload(self.clean)

    def test_the_target_address_is_replaced(self) -> None:
        self.assertNotEqual(self.body[:16], _packed(_DST_IP))

    def test_the_link_layer_option_is_replaced(self) -> None:
        self.assertNotEqual(self.body[18:24], _mac_bytes(_SRC_MAC))

    def test_the_option_matches_the_ethernet_header(self) -> None:
        """Same replacer, so the capture still reads as coherent traffic."""
        self.assertEqual(self.body[18:24].hex(),
                         self.clean["ethernet"]["src_mac"].replace(":", ""))

    def test_the_target_matches_the_address_used_elsewhere(self) -> None:
        self.assertEqual(str(ipaddress.IPv6Address(self.body[:16])),
                         self.clean["network"]["dst"])

    def test_a_neighbour_advertisement_too(self) -> None:
        body = _payload(_clean(_spec(_nd(_SRC_IP, opt_type=2), icmp_type=136)))
        self.assertNotEqual(body[:16], _packed(_SRC_IP))
        self.assertNotEqual(body[18:24], _mac_bytes(_SRC_MAC))

    def test_the_option_structure_survives(self) -> None:
        """Only the addresses change; type and length are left alone."""
        self.assertEqual(self.body[16], 1)
        self.assertEqual(self.body[17], 1)
        self.assertEqual(len(self.body), 24)


class TestOtherICMPv6Messages(unittest.TestCase):

    def test_a_redirect_replaces_both_addresses(self) -> None:
        body = _payload(_clean(_spec(
            _packed(_DST_IP) + _packed(_SRC_IP), icmp_type=137)))
        self.assertNotEqual(body[:16], _packed(_DST_IP))
        self.assertNotEqual(body[16:32], _packed(_SRC_IP))

    def test_a_router_advertisement_replaces_its_prefix(self) -> None:
        prefix = _packed("2001:470:1f0b:abcd::")
        option = bytes([3, 4, 64, 0]) + b"\x00" * 12 + prefix
        payload = b"\x00" * 8 + option
        body = _payload(_clean(_spec(payload, icmp_type=134)))
        self.assertNotEqual(body[16:32], prefix)

    def test_a_router_solicitation_replaces_its_option(self) -> None:
        payload = bytes([1, 1]) + _mac_bytes(_SRC_MAC)
        body = _payload(_clean(_spec(payload, icmp_type=133)))
        self.assertNotEqual(body[2:8], _mac_bytes(_SRC_MAC))

    def test_an_echo_payload_is_left_alone(self) -> None:
        """It carries data, not addresses; `--payload` is what zeroes it."""
        body = _payload(_clean(_spec(b"abcdefgh", icmp_type=128)))
        self.assertEqual(body, b"abcdefgh")


class TestQuotedPackets(unittest.TestCase):
    """An ICMP error quotes the packet that provoked it, header and all."""

    def _quoted_v6(self) -> bytes:
        return (PacketBuilder()
                .ip(src=_DST_IP, dst=_SRC_IP).udp(src_port=1234, dst_port=53)
                .payload(data=b"q").build())

    def test_an_icmpv6_error_replaces_the_quoted_addresses(self) -> None:
        body = _payload(_clean(_spec(self._quoted_v6(), icmp_type=1)))
        self.assertNotEqual(body[8:24], _packed(_DST_IP))
        self.assertNotEqual(body[24:40], _packed(_SRC_IP))

    def test_the_quoted_addresses_match_the_ones_used_elsewhere(self) -> None:
        clean = _clean(_spec(self._quoted_v6(), icmp_type=1))
        body = _payload(clean)
        self.assertEqual(str(ipaddress.IPv6Address(body[8:24])),
                         clean["network"]["dst"])

    def test_an_icmpv4_error_replaces_the_quoted_addresses(self) -> None:
        quoted = (PacketBuilder()
                  .ip(src="203.0.113.7", dst="198.51.100.4")
                  .udp(dst_port=53).payload(data=b"q").build())
        body = _payload(_clean(_spec(quoted, icmp_type=3, v6=False)))
        self.assertNotEqual(body[12:16], _packed("203.0.113.7"))
        self.assertNotEqual(body[16:20], _packed("198.51.100.4"))

    def test_quoted_ports_change_only_when_asked(self) -> None:
        quoted = self._quoted_v6()
        kept = _payload(_clean(_spec(quoted, icmp_type=1)))
        changed = _payload(_clean(_spec(quoted, icmp_type=1), ports=True))
        self.assertEqual(int.from_bytes(kept[40:42], "big"), 1234)
        self.assertNotEqual(int.from_bytes(changed[40:42], "big"), 1234)


class TestICMPv4Redirect(unittest.TestCase):
    """Its gateway is in the header bytes a spec records as identifier/sequence."""

    def test_the_gateway_is_replaced(self) -> None:
        gateway = int(ipaddress.IPv4Address("203.0.113.254"))
        quoted = (PacketBuilder().ip(src="203.0.113.7", dst="198.51.100.4")
                  .udp(dst_port=53).payload(data=b"q").build())
        clean = _clean(_spec(quoted, icmp_type=5, v6=False,
                             identifier=gateway >> 16, sequence=gateway & 0xFFFF))
        rebuilt = (clean["transport"]["identifier"] << 16) | clean["transport"]["sequence"]
        self.assertNotEqual(rebuilt, gateway)


class TestUnknownTypesAreNotSilent(unittest.TestCase):
    """Silence is what let this bug survive."""

    def test_an_unhandled_type_warns(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            sanitise({"packets": [_spec(b"\x00" * 8, icmp_type=200)]})
        messages = [str(w.message) for w in caught
                    if issubclass(w.category, PersonalDataWarning)]
        self.assertTrue(messages)
        self.assertIn("200", messages[0])

    def test_a_handled_type_does_not_warn(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            sanitise({"packets": [_spec(_nd(_DST_IP), icmp_type=135)]})
        self.assertEqual([w for w in caught
                          if issubclass(w.category, PersonalDataWarning)], [])


class TestOptionsAreRespected(unittest.TestCase):

    def test_macs_false_leaves_the_link_layer_option(self) -> None:
        body = _payload(_clean(_spec(_nd(_DST_IP), icmp_type=135), macs=False))
        self.assertEqual(body[18:24], _mac_bytes(_SRC_MAC))

    def test_ips_false_leaves_the_target(self) -> None:
        body = _payload(_clean(_spec(_nd(_DST_IP), icmp_type=135), ips=False))
        self.assertEqual(body[:16], _packed(_DST_IP))


class TestNothingRealSurvives(unittest.TestCase):
    """The assertion the bug report deserved: scan the whole output."""

    def test_no_original_address_appears_anywhere(self) -> None:
        spec = _spec(_nd(_DST_IP), icmp_type=135)
        clean = _clean(spec)

        secrets = {
            _packed(_SRC_IP), _packed(_DST_IP),
            _mac_bytes(_SRC_MAC), _mac_bytes(_DST_MAC),
        }
        haystack = repr(clean).encode() + _payload(clean)
        leaked = sorted(s.hex() for s in secrets if s in haystack
                        or s.hex() in repr(clean))
        self.assertEqual(leaked, [])

    def test_the_sanitised_spec_still_builds(self) -> None:
        import packeteer.__main__ as cli

        clean = _clean(_spec(_nd(_DST_IP), icmp_type=135))
        builder, _ = cli._apply_spec_to_builder(PacketBuilder(), clean, 1)
        self.assertTrue(builder.build())


if __name__ == "__main__":
    unittest.main()


class TestRestOfHeader(unittest.TestCase):
    """The four bytes after the checksum are type-specific, not id/sequence.

    They are stored as two halves named for what an Echo puts there, which is
    misleading for every other type — a Redirect's gateway address arrives as
    two unrelated-looking numbers.  `rest_of_header` is the honest view, and
    the halves stay the stored fields so older specs still build.
    """

    def test_it_combines_the_two_halves(self) -> None:
        from packeteer.generate.icmpv6 import ICMPv6Header

        self.assertEqual(ICMPv6Header(identifier=0x1234,
                                      sequence=0x5678).rest_of_header,
                         0x12345678)

    def test_setting_it_splits_them(self) -> None:
        from packeteer.generate.icmp import ICMPHeader

        header = ICMPHeader(type=5, code=1)
        header.rest_of_header = int(ipaddress.IPv4Address("192.0.2.254"))
        self.assertEqual((header.identifier, header.sequence), (0xC000, 0x02FE))

    def test_a_redirect_gateway_reads_back_off_the_wire(self) -> None:
        gateway = int(ipaddress.IPv4Address("192.0.2.254"))
        frame = (PacketBuilder()
                 .ethernet(src_mac=_SRC_MAC, dst_mac=_DST_MAC)
                 .ip(src="192.0.2.1", dst="192.0.2.9")
                 .icmp(type=5, code=1, identifier=gateway >> 16,
                       sequence=gateway & 0xFFFF)
                 .payload(data=b"\x45\x00" + b"\x00" * 18).build())
        header = parse_packet(frame, decode_app=False).transport
        self.assertEqual(str(ipaddress.IPv4Address(header.rest_of_header)),
                         "192.0.2.254")

    def test_an_echo_is_unaffected(self) -> None:
        from packeteer.generate.icmpv6 import ICMPv6Header

        echo = ICMPv6Header()
        self.assertEqual((echo.identifier, echo.sequence), (1, 1))

    def test_a_value_too_wide_is_refused(self) -> None:
        from packeteer.generate.icmpv6 import ICMPv6Header

        with self.assertRaises(ValueError):
            ICMPv6Header().rest_of_header = 1 << 32
