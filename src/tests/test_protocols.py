"""The application-protocol registry (#96)."""
from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from packeteer import protocols
from packeteer.protocols import AppProtocol, ProtocolError


@dataclass
class Reading:
    value: int = 0


@dataclass
class OtherReading:
    value: int = 0


def _encode(msg: object, transport: str) -> bytes:
    assert isinstance(msg, Reading)
    return msg.value.to_bytes(2, "big")


def _decode(payload: bytes, transport: str) -> object:
    if len(payload) != 2:
        raise ValueError("sensor readings are two bytes")
    return Reading(value=int.from_bytes(payload, "big"))


def _to_spec(msg: object) -> dict[str, Any]:
    assert isinstance(msg, Reading)
    return {"value": msg.value}


def _from_spec(section: dict[str, Any]) -> object:
    return Reading(value=section["value"])


def _proto(**overrides: Any) -> AppProtocol:
    """Return a registrable protocol, with *overrides* applied."""
    fields: dict[str, Any] = {
        "name": "sensor",
        "over": "udp",
        "ports": frozenset({9000}),
        "messages": (Reading,),
        "decode": _decode,
        "encode": _encode,
        "to_spec": _to_spec,
        "from_spec": _from_spec,
    }
    fields.update(overrides)
    return AppProtocol(**fields)


class _RegistryTestCase(unittest.TestCase):
    """Restores the registry, so tests cannot leak claims into each other."""

    def setUp(self) -> None:
        self._saved = protocols.registered()
        for proto in self._saved:
            protocols.unregister(proto.name)

    def tearDown(self) -> None:
        for proto in protocols.registered():
            protocols.unregister(proto.name)
        for proto in self._saved:
            protocols.register(proto)


class TestRegistration(_RegistryTestCase):

    def test_registered_is_empty_until_something_registers(self) -> None:
        self.assertEqual(protocols.registered(), ())

    def test_register_then_lookup(self) -> None:
        proto = _proto()
        protocols.register(proto)
        self.assertEqual(protocols.registered(), (proto,))
        self.assertIs(protocols.for_section("sensor"), proto)
        self.assertIs(protocols.for_port(9000, "udp"), proto)
        self.assertIs(protocols.for_message(Reading(1)), proto)

    def test_registration_order_is_preserved(self) -> None:
        first = _proto()
        second = _proto(name="other", ports=frozenset({9001}),
                        messages=(OtherReading,))
        protocols.register(first)
        protocols.register(second)
        self.assertEqual([p.name for p in protocols.registered()],
                         ["sensor", "other"])

    def test_unregister_releases_every_claim(self) -> None:
        protocols.register(_proto())
        protocols.unregister("sensor")
        self.assertEqual(protocols.registered(), ())
        self.assertIsNone(protocols.for_section("sensor"))
        self.assertIsNone(protocols.for_port(9000, "udp"))
        self.assertIsNone(protocols.for_message(Reading(1)))

    def test_unregister_unknown_name_raises(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            protocols.unregister("nothing")
        self.assertIn("nothing", str(ctx.exception))


class TestCollisionsAreRefused(_RegistryTestCase):
    """The four ways register must say no, each naming what collided."""

    def test_reserved_packet_spec_key(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            protocols.register(_proto(name="transport"))
        self.assertIn("reserved", str(ctx.exception))
        self.assertIn("transport", str(ctx.exception))

    def test_duplicate_name(self) -> None:
        protocols.register(_proto())
        with self.assertRaises(ProtocolError) as ctx:
            protocols.register(_proto(ports=frozenset({9999}),
                                      messages=(OtherReading,)))
        self.assertIn("already registered", str(ctx.exception))

    def test_port_already_claimed(self) -> None:
        protocols.register(_proto())
        with self.assertRaises(ProtocolError) as ctx:
            protocols.register(_proto(name="other", messages=(OtherReading,)))
        self.assertIn("9000", str(ctx.exception))
        self.assertIn("sensor", str(ctx.exception))

    def test_message_type_already_claimed(self) -> None:
        protocols.register(_proto())
        with self.assertRaises(ProtocolError) as ctx:
            protocols.register(_proto(name="other", ports=frozenset({9001})))
        self.assertIn("Reading", str(ctx.exception))
        self.assertIn("sensor", str(ctx.exception))

    def test_unknown_over_value(self) -> None:
        with self.assertRaises(ProtocolError) as ctx:
            protocols.register(_proto(over="sctp"))
        self.assertIn("sctp", str(ctx.exception))

    def test_a_refused_registration_leaves_nothing_behind(self) -> None:
        with self.assertRaises(ProtocolError):
            protocols.register(_proto(name="payload"))
        self.assertEqual(protocols.registered(), ())
        self.assertIsNone(protocols.for_port(9000, "udp"))


class TestTransportClaims(_RegistryTestCase):
    """`over` decides which transports a port claim covers."""

    def test_udp_only_does_not_claim_tcp(self) -> None:
        protocols.register(_proto())
        self.assertIsNone(protocols.for_port(9000, "tcp"))

    def test_tcp_only_does_not_claim_udp(self) -> None:
        protocols.register(_proto(over="tcp"))
        self.assertIsNone(protocols.for_port(9000, "udp"))

    def test_either_claims_both(self) -> None:
        proto = _proto(over="either")
        protocols.register(proto)
        self.assertIs(protocols.for_port(9000, "tcp"), proto)
        self.assertIs(protocols.for_port(9000, "udp"), proto)

    def test_the_same_port_on_different_transports_is_not_a_collision(self) -> None:
        udp = _proto()
        tcp = _proto(name="other", over="tcp", messages=(OtherReading,))
        protocols.register(udp)
        protocols.register(tcp)
        self.assertIs(protocols.for_port(9000, "udp"), udp)
        self.assertIs(protocols.for_port(9000, "tcp"), tcp)

    def test_either_collides_with_a_single_transport_claim(self) -> None:
        protocols.register(_proto())
        with self.assertRaises(ProtocolError) as ctx:
            protocols.register(_proto(name="other", over="either",
                                      messages=(OtherReading,)))
        self.assertIn("udp port 9000", str(ctx.exception))

    def test_carries(self) -> None:
        self.assertTrue(_proto(over="either").carries("tcp"))
        self.assertTrue(_proto(over="udp").carries("udp"))
        self.assertFalse(_proto(over="udp").carries("tcp"))


class TestMessageLookup(_RegistryTestCase):

    def test_unknown_object_resolves_to_none(self) -> None:
        protocols.register(_proto())
        self.assertIsNone(protocols.for_message(object()))
        self.assertIsNone(protocols.for_message(b"raw bytes"))

    def test_subclass_of_a_registered_message_resolves(self) -> None:
        @dataclass
        class Derived(Reading):
            pass

        proto = _proto()
        protocols.register(proto)
        self.assertIs(protocols.for_message(Derived(1)), proto)

    def test_a_protocol_may_own_several_message_types(self) -> None:
        proto = _proto(messages=(Reading, OtherReading))
        protocols.register(proto)
        self.assertIs(protocols.for_message(Reading(1)), proto)
        self.assertIs(protocols.for_message(OtherReading(1)), proto)


class TestTheContractRoundTrips(_RegistryTestCase):
    """The four callables are what everything downstream will drive."""

    def setUp(self) -> None:
        super().setUp()
        self.proto = _proto()
        protocols.register(self.proto)

    def test_encode_decode(self) -> None:
        self.assertEqual(self.proto.encode(Reading(258), "udp"), b"\x01\x02")
        self.assertEqual(self.proto.decode(b"\x01\x02", "udp"), Reading(258))

    def test_to_spec_from_spec(self) -> None:
        section = self.proto.to_spec(Reading(7))
        self.assertEqual(section, {"value": 7})
        self.assertEqual(self.proto.from_spec(section), Reading(7))

    def test_decode_raises_for_a_payload_that_is_not_ours(self) -> None:
        """A port claim is a weak signal; raising is how a collision is settled."""
        with self.assertRaises(ValueError):
            self.proto.decode(b"not two bytes", "udp")

    def test_sanitise_defaults_to_none(self) -> None:
        """No sanitiser means nothing is redacted — the documented default."""
        self.assertIsNone(self.proto.sanitise)


class TestRegistryIsImportLight(unittest.TestCase):
    """protocols.py must stay stdlib-only, or sanitise and filter gain a cycle."""

    def test_imports_nothing_from_packeteer(self) -> None:
        import ast
        import pathlib

        tree = ast.parse(pathlib.Path(protocols.__file__).read_text())
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported += [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # level > 0 is a relative import, which is packeteer by
                # definition; module is None only for "from . import x".
                imported.append("." * node.level + (node.module or ""))

        offenders = [name for name in imported
                     if name.startswith((".", "packeteer"))]
        self.assertEqual(offenders, [], "protocols.py must stay stdlib-only")


if __name__ == "__main__":
    unittest.main()
