"""A registered protocol is reached by its own name on both front doors (#139).

`pkt.dns` was a better API than `pkt.app` — the code after `pkt.app` almost
always checks `app_protocol` anyway — and it was marked legacy.  It is now the
rule: every registered name is an attribute on `ParsedPacket` and a payload
method on `PacketBuilder`, resolved on demand, with the three built-ins kept
as declared, typed fields.  A protocol name is therefore an attribute name,
and `register()` holds it to that.
"""
from __future__ import annotations

import copy
import pickle
import textwrap
import unittest
from dataclasses import dataclass
from typing import Any

from packeteer import protocols
from packeteer.generate import PacketBuilder
from packeteer.generate.dns import DNSMessage, DNSQuestion
from packeteer.parse import ParsedPacket, parse_packet
from packeteer.protocols import AppProtocol, ProtocolError, check_name
from packeteer.protospec import check, loads

_MACS = {"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"}


@dataclass
class Reading:
    value: int = 0


@dataclass
class Other:
    value: int = 0


def _proto(name: str, port: int, message: type) -> AppProtocol:
    return AppProtocol(
        name=name, over="udp", ports=frozenset({port}), messages=(message,),
        decode=lambda p, t: message(value=int.from_bytes(p, "big")),
        encode=lambda m, t: m.value.to_bytes(2, "big"),
        to_spec=lambda m: {"value": m.value},
        from_spec=lambda s: message(value=s["value"]),
    )


class _TwoProtocols(unittest.TestCase):
    """`sensor` on 9000 and `other` on 9001, both UDP."""

    def setUp(self) -> None:
        for name, port, message in (("sensor", 9000, Reading), ("other", 9001, Other)):
            protocols.register(_proto(name, port, message))
            self.addCleanup(protocols.unregister, name)

    def _frame(self, port: int, payload: bytes) -> bytes:
        return (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
                .udp(dst_port=port).payload(data=payload).build())


class TestParsedPacket(_TwoProtocols):

    def test_the_name_resolves_to_the_message(self) -> None:
        pkt = parse_packet(self._frame(9000, b"\x01\x02"))
        self.assertEqual(pkt.sensor, Reading(258))
        self.assertIs(pkt.sensor, pkt.app)

    def test_another_registered_name_is_none(self) -> None:
        """The shape `pkt.dns` has on a DHCP packet."""
        pkt = parse_packet(self._frame(9000, b"\x01\x02"))
        self.assertIsNone(pkt.other)
        self.assertIsNone(pkt.dns)

    def test_on_a_packet_with_no_app_every_name_is_none(self) -> None:
        pkt = parse_packet(self._frame(9, b"\x01\x02"))
        self.assertIsNone(pkt.sensor)
        self.assertIsNone(pkt.other)

    def test_an_unregistered_name_is_an_attribute_error(self) -> None:
        pkt = parse_packet(self._frame(9000, b"\x01\x02"))
        with self.assertRaises(AttributeError) as ctx:
            _ = pkt.snesor
        self.assertIn("no protocol is registered as 'snesor'", str(ctx.exception))
        self.assertFalse(hasattr(pkt, "snesor"))

    def test_a_leading_underscore_never_reaches_the_registry(self) -> None:
        pkt = ParsedPacket()
        with self.assertRaises(AttributeError):
            _ = pkt._sensor
        with self.assertRaises(AttributeError):
            _ = pkt.__deepcopy__

    def test_copy_and_pickle_still_work(self) -> None:
        """Both probe dunders through getattr.

        A lookup that reached the registry for each would be wrong the day a
        protocol name matched one.
        """
        pkt = parse_packet(self._frame(9000, b"\x01\x02"))
        self.assertEqual(copy.deepcopy(pkt).sensor, Reading(258))
        self.assertEqual(pickle.loads(pickle.dumps(pkt)).sensor, Reading(258))

    def test_dir_lists_the_registered_names(self) -> None:
        listed = dir(ParsedPacket())
        self.assertIn("sensor", listed)
        self.assertIn("other", listed)
        self.assertIn("dns", listed)

    def test_the_three_declared_fields_are_untouched(self) -> None:
        """Q1: they stay typed fields, set explicitly, equal to `.app`."""
        frame = (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp(dst_port=53).dns(DNSMessage(id=1, questions=[DNSQuestion("a.")]))
                 .build())
        pkt = parse_packet(frame)
        self.assertIs(pkt.dns, pkt.app)
        self.assertIsNone(pkt.dhcp)
        self.assertIsNone(pkt.http)
        self.assertIsNone(pkt.sensor)


class TestPacketBuilder(_TwoProtocols):

    def _base(self, port: int) -> PacketBuilder:
        return (PacketBuilder().ethernet(**_MACS).ip(src="10.0.0.1", dst="10.0.0.2")
                .udp(dst_port=port))

    def test_the_name_is_a_payload_method(self) -> None:
        frame = self._base(9000).sensor(Reading(258)).build()
        self.assertEqual(parse_packet(frame).sensor, Reading(258))

    def test_it_is_the_same_bytes_as_app(self) -> None:
        self.assertEqual(self._base(9000).sensor(Reading(258)).build(),
                         self._base(9000).app(Reading(258)).build())

    def test_it_chains(self) -> None:
        b = self._base(9000)
        self.assertIs(b.sensor(Reading(1)), b)

    def test_the_wrong_message_is_a_type_error_naming_its_owner(self) -> None:
        """What `.app()` cannot do: check the message belongs to the name."""
        with self.assertRaises(TypeError) as ctx:
            self._base(9000).sensor(Other(1))
        self.assertIn(".sensor() takes a message of 'sensor'", str(ctx.exception))
        self.assertIn("'Other'", str(ctx.exception))
        self.assertIn("message of 'other'", str(ctx.exception))

    def test_a_message_nobody_owns_says_so(self) -> None:
        with self.assertRaises(TypeError) as ctx:
            self._base(9000).sensor(object())
        self.assertIn("no registered protocol owns it", str(ctx.exception))

    def test_an_unregistered_name_is_an_attribute_error(self) -> None:
        with self.assertRaises(AttributeError) as ctx:
            self._base(9000).snesor(Reading(1))
        self.assertIn("no protocol is registered as 'snesor'", str(ctx.exception))

    def test_a_leading_underscore_never_reaches_the_registry(self) -> None:
        with self.assertRaises(AttributeError):
            _ = PacketBuilder()._sensor
        self.assertIsNotNone(copy.copy(PacketBuilder()))

    def test_dir_lists_the_registered_names(self) -> None:
        listed = dir(PacketBuilder())
        self.assertIn("sensor", listed)
        self.assertIn("dhcp", listed)

    def test_the_transport_comes_from_the_stack(self) -> None:
        """`either` needs a transport layer, as with `.app()`."""
        both = type("Both", (Reading,), {})
        proto = _proto("both", 9002, both)
        protocols.register(AppProtocol(**{**proto.__dict__, "over": "either"}))
        self.addCleanup(protocols.unregister, "both")
        with self.assertRaises(ValueError) as ctx:
            PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").both(both(1))
        self.assertIn("either", str(ctx.exception))
        frame = self._base(9002).both(both(1)).build()
        self.assertEqual(parse_packet(frame).both, both(1))


class TestTheNameRule(unittest.TestCase):
    """A name is now an attribute, so it is held to what an attribute can be."""

    def _register(self, name: str) -> None:
        proto = _proto(name, 9010, type("M", (Reading,), {}))
        protocols.register(proto)
        self.addCleanup(protocols.unregister, name)

    def test_a_non_identifier_is_refused(self) -> None:
        for name in ("my-sensor", "9lives", "a.b", "a b", ""):
            with self.subTest(name=name):
                with self.assertRaises(ProtocolError) as ctx:
                    check_name(name)
                self.assertIn("not a Python identifier", str(ctx.exception))

    def test_a_keyword_is_refused(self) -> None:
        with self.assertRaises(ProtocolError):
            check_name("class")

    def test_a_leading_underscore_is_refused(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            check_name("_sensor")
        self.assertIn("underscore", str(ctx.exception))

    def test_a_reserved_name_is_refused(self) -> None:
        for name in ("build", "tcp", "ip", "timestamp", "network", "payload"):
            with self.subTest(name=name):
                with self.assertRaises(ProtocolError) as ctx:
                    check_name(name)
                self.assertIn("reserved", str(ctx.exception))

    def test_register_applies_it(self) -> None:
        with self.assertRaises(ProtocolError):
            self._register("my-sensor")
        with self.assertRaises(ProtocolError):
            self._register("build")
        self._register("acme_sensor")        # a prefix is the convention

    def test_every_public_name_on_both_classes_is_reserved(self) -> None:
        """The list in protocols.py is literal; this is what keeps it honest.

        A builder method or a ParsedPacket attribute added without reserving
        its name would be shadowed by a protocol registered under it — the
        failure this test exists to raise the moment it becomes possible.
        """
        public = {n for n in dir(PacketBuilder) if not n.startswith("_")}
        public |= {n for n in dir(ParsedPacket) if not n.startswith("_")}
        typed = {"dns", "dhcp", "http"}
        self.assertLessEqual(
            public - typed, protocols._RESERVED_NAMES,
            f"not reserved: {sorted(public - typed - protocols._RESERVED_NAMES)}",
        )


class TestCheckRefusesTheNameEarly(unittest.TestCase):
    """A spec that would fail at import fails at `check` instead."""

    def _spec(self, name: str) -> Any:
        return loads(textwrap.dedent(f"""
            name: {name}
            version: "1"
            over: udp
            ports: [9000]
            input: datagram
            entry: M
            units:
              M:
                fields:
                  - {{name: v, bits: 8}}
            """), fmt="yaml")

    def test_a_reserved_name(self) -> None:
        result = check(self._spec("build"))
        self.assertEqual(len(result.errors), 1)
        self.assertIn("reserved", result.errors[0].message)
        self.assertEqual(result.errors[0].location.path, "name")

    def test_a_non_identifier(self) -> None:
        result = check(self._spec("my-sensor"))
        self.assertTrue(any("identifier" in e.message for e in result.errors))

    def test_a_good_name(self) -> None:
        self.assertTrue(check(self._spec("acme_sensor")).ok())


if __name__ == "__main__":
    unittest.main()
