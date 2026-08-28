"""The built-in protocols as registry entries (#97).

Every test here asserts the new record agrees with the code path that was
already there, because this change is meant to move code rather than alter it.
"""
from __future__ import annotations

import subprocess
import sys
import unittest

from packeteer import app, protocols
from packeteer.generate.dhcp import (
    DHCP_OPT_MESSAGE_TYPE,
    DHCPMessage,
    DHCPOptHostname,
    DHCPOptMessageType,
    _build_dhcp_message,
)
from packeteer.generate.dns import (
    DNS_CLASS_IN,
    DNS_TYPE_A,
    DNSMessage,
    DNSQuestion,
    DNSRDataA,
    DNSResourceRecord,
    _build_dns_message,
    _build_dns_message_tcp,
)
from packeteer.generate.http import HTTPRequest, HTTPResponse, _build_http_message
from packeteer.parse.dhcp import parse_dhcp
from packeteer.parse.dns import parse_dns_tcp, parse_dns_udp
from packeteer.parse.http import parse_http
from packeteer.parse.to_config import update_config


def _dns_message() -> DNSMessage:
    return DNSMessage(
        id=0x1234,
        questions=[DNSQuestion(name="example.com.", qtype=DNS_TYPE_A)],
        answers=[DNSResourceRecord(
            name="example.com.", rtype=DNS_TYPE_A, rclass=DNS_CLASS_IN, ttl=300,
            rdata=DNSRDataA(address="93.184.216.34"),
        )],
    )


def _dhcp_message() -> DHCPMessage:
    return DHCPMessage(
        op=1, xid=0xDEADBEEF, chaddr=bytes.fromhex("001122334455") + b"\x00" * 10,
        options=[DHCPOptMessageType(mtype=1), DHCPOptHostname(hostname="laptop")],
    )


class TestTheThreeAreRegistered(unittest.TestCase):

    def test_names_ports_and_transports(self) -> None:
        expected = {
            "dns":  ("either", {53, 5353}),
            "dhcp": ("udp",    {67, 68}),
            "http": ("tcp",    {80, 8080}),
        }
        for name, (over, ports) in expected.items():
            with self.subTest(protocol=name):
                proto = protocols.for_section(name)
                self.assertIsNotNone(proto)
                assert proto is not None
                self.assertEqual(proto.over, over)
                self.assertEqual(set(proto.ports), ports)

    def test_message_types_resolve(self) -> None:
        self.assertEqual(protocols.for_message(_dns_message()).name, "dns")
        self.assertEqual(protocols.for_message(_dhcp_message()).name, "dhcp")
        self.assertEqual(protocols.for_message(HTTPRequest()).name, "http")
        self.assertEqual(protocols.for_message(HTTPResponse()).name, "http")

    def test_ports_dispatch_by_transport(self) -> None:
        self.assertEqual(protocols.for_port(53, "udp").name, "dns")
        self.assertEqual(protocols.for_port(53, "tcp").name, "dns")
        self.assertEqual(protocols.for_port(67, "udp").name, "dhcp")
        self.assertIsNone(protocols.for_port(67, "tcp"))
        self.assertEqual(protocols.for_port(80, "tcp").name, "http")
        self.assertIsNone(protocols.for_port(80, "udp"))

    def test_register_builtins_is_idempotent(self) -> None:
        before = protocols.registered()
        app.register_builtins()
        self.assertEqual(protocols.registered(), before)

    def test_all_three_carry_a_sanitiser(self) -> None:
        """A protocol without one flows through `sanitise` untouched."""
        for name in ("dns", "dhcp", "http"):
            with self.subTest(protocol=name):
                self.assertIsNotNone(protocols.for_section(name).sanitise)


class TestEncodeAgreesWithTheExistingEncoder(unittest.TestCase):

    def test_dns_udp(self) -> None:
        msg = _dns_message()
        self.assertEqual(app.dns.encode(msg, "udp"), _build_dns_message(msg))

    def test_dns_tcp_adds_the_length_prefix(self) -> None:
        msg = _dns_message()
        over_tcp = app.dns.encode(msg, "tcp")
        self.assertEqual(over_tcp, _build_dns_message_tcp(msg))
        self.assertEqual(over_tcp[2:], app.dns.encode(msg, "udp"))

    def test_dhcp(self) -> None:
        msg = _dhcp_message()
        self.assertEqual(app.dhcp.encode(msg, "udp"), _build_dhcp_message(msg))

    def test_http(self) -> None:
        msg = HTTPRequest(method="GET", path="/", headers={"Host": "example.com"})
        self.assertEqual(app.http.encode(msg, "tcp"), _build_http_message(msg))


class TestDecodeAgreesWithTheExistingParser(unittest.TestCase):

    def test_dns_udp(self) -> None:
        wire = _build_dns_message(_dns_message())
        self.assertEqual(app.dns.decode(wire, "udp"), parse_dns_udp(wire))

    def test_dns_tcp(self) -> None:
        wire = _build_dns_message_tcp(_dns_message())
        self.assertEqual(app.dns.decode(wire, "tcp"), parse_dns_tcp(wire))

    def test_dhcp(self) -> None:
        wire = _build_dhcp_message(_dhcp_message())
        self.assertEqual(app.dhcp.decode(wire, "udp"), parse_dhcp(wire))

    def test_http(self) -> None:
        wire = _build_http_message(HTTPRequest(headers={"Host": "example.com"}))
        self.assertEqual(app.http.decode(wire, "tcp"), parse_http(wire))

    def test_decode_raises_on_a_payload_that_is_not_ours(self) -> None:
        """What lets the parser leave a mismatched payload as opaque bytes."""
        for module, transport in ((app.dns, "udp"), (app.dhcp, "udp")):
            with (self.subTest(protocol=module.PROTOCOL.name),
                  self.assertRaises((ValueError, IndexError))):
                module.decode(b"\x00", transport)


class TestToSpecAgreesWithUpdateConfig(unittest.TestCase):

    def test_dns(self) -> None:
        msg = _dns_message()
        self.assertEqual(app.dns.to_spec(msg), update_config({}, msg)["dns"])

    def test_dhcp(self) -> None:
        msg = _dhcp_message()
        self.assertEqual(app.dhcp.to_spec(msg), update_config({}, msg)["dhcp"])

    def test_http(self) -> None:
        msg = HTTPResponse(status_code=404, reason="Not Found", body=b"nope")
        self.assertEqual(app.http.to_spec(msg), update_config({}, msg)["http"])


class TestFromSpecRoundTrips(unittest.TestCase):
    """`from_spec` is the half that had no home outside the CLI until now."""

    def test_dns(self) -> None:
        msg = _dns_message()
        self.assertEqual(app.dns.from_spec(app.dns.to_spec(msg)), msg)

    def test_dhcp(self) -> None:
        msg = _dhcp_message()
        rebuilt = app.dhcp.from_spec(app.dhcp.to_spec(msg))
        self.assertEqual(_build_dhcp_message(rebuilt), _build_dhcp_message(msg))

    def test_http_request(self) -> None:
        msg = HTTPRequest(method="POST", path="/x", headers={"A": "b"}, body=b"hi")
        self.assertEqual(app.http.from_spec(app.http.to_spec(msg)), msg)

    def test_http_response(self) -> None:
        msg = HTTPResponse(status_code=500, reason="Boom", body=b"!")
        self.assertEqual(app.http.from_spec(app.http.to_spec(msg)), msg)

    def test_dhcp_unknown_option_survives_as_raw(self) -> None:
        section = {"options": [{"code": 250, "data": "aabb"}]}
        msg = app.dhcp.from_spec(section)
        self.assertEqual(msg.options[0].code, 250)
        self.assertEqual(msg.options[0].data, b"\xaa\xbb")

    def test_dhcp_known_option_is_typed(self) -> None:
        section = {"options": [{"code": DHCP_OPT_MESSAGE_TYPE, "mtype": 3}]}
        msg = app.dhcp.from_spec(section)
        self.assertIsInstance(msg.options[0], DHCPOptMessageType)


class TestTheCLIKeepsNoneOfIt(unittest.TestCase):
    """CLAUDE.md: everything the CLI does must be reachable from the API."""

    def test_main_no_longer_defines_the_spec_builders(self) -> None:
        import packeteer.__main__ as main

        for gone in ("_build_dns_from_spec", "_build_dhcp_from_spec",
                     "_build_http_from_spec", "_build_dns_rdata",
                     "_build_dhcp_option"):
            with self.subTest(name=gone):
                self.assertFalse(hasattr(main, gone))


class TestImportCost(unittest.TestCase):
    """`import packeteer.generate` must not drag in the parser."""

    def _modules_after(self, statement: str) -> set[str]:
        src = str(__import__("pathlib").Path(protocols.__file__).parent.parent)
        code = (f"import sys; sys.path.insert(0, {src!r}); {statement}; "
                "print('\\n'.join(sorted(sys.modules)))")
        out = subprocess.run([sys.executable, "-c", code],
                             capture_output=True, text=True, check=True)
        return set(out.stdout.split())

    def test_generate_does_not_import_parse(self) -> None:
        loaded = self._modules_after("import packeteer.generate")
        self.assertNotIn("packeteer.parse", loaded)

    def test_app_does_not_import_parse(self) -> None:
        loaded = self._modules_after("import packeteer.app")
        self.assertNotIn("packeteer.parse", loaded)

    def test_parse_does_import_app(self) -> None:
        loaded = self._modules_after("import packeteer.parse")
        self.assertIn("packeteer.app", loaded)


if __name__ == "__main__":
    unittest.main()
