"""Both ways of making a protocol meet one contract (#120)."""
from __future__ import annotations

import unittest
from pathlib import Path

from packeteer import app, conformance, protocols
from packeteer.generate.dhcp import DHCPMessage, DHCPOptHostname, DHCPOptMessageType
from packeteer.generate.dns import DNSMessage, DNSQuestion
from packeteer.generate.http import HTTPRequest, HTTPResponse
from packeteer.protocols import AppProtocol
from packeteer.protospec import load
from packeteer.protospec.codegen import compile_spec

_EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "protocols"

#: Representative messages for each built-in.  A protocol added without an
#: entry here fails `test_every_registered_protocol_has_samples`, which is how
#: the contract stays enforced rather than merely written down.
_BUILTIN_SAMPLES: dict[str, list[object]] = {
    "dns": [
        DNSMessage(id=1, questions=[DNSQuestion(name="example.com")]),
        DNSMessage(id=2, questions=[DNSQuestion(name="a.example")]),
    ],
    "dhcp": [
        DHCPMessage(options=[DHCPOptMessageType(mtype=3)]),
        DHCPMessage(options=[DHCPOptMessageType(mtype=1),
                             DHCPOptHostname(hostname="box")]),
    ],
    "http": [
        HTTPRequest(method="GET", path="/", headers={"Host": "example"}),
        HTTPResponse(status_code=200, reason="OK",
                     headers={"Content-Length": "0"}),
    ],
}


def _compiled(name: str) -> tuple[AppProtocol, list[object], dict]:
    """Compile an example spec and return its protocol, samples and namespace."""
    namespace: dict = {}
    code = compile_spec(load(str(_EXAMPLES / f"{name}.yaml")))
    exec(compile(code, f"<{name}>", "exec"), namespace)      # noqa: S102
    proto = namespace["PROTOCOL"]
    if name == "sensor":
        samples = [namespace["Reading"](version=1),
                   namespace["Reading"](version=2)]
    else:
        samples = [
            namespace["Message"](header=namespace["Header"](op=1, request_id=7),
                                 body=namespace["Ping"](nonce=42)),
            namespace["Message"](header=namespace["Header"](op=2, request_id=8),
                                 body=namespace["Read"](offset=16, length=4)),
            namespace["Message"](header=namespace["Header"](op=3, request_id=9),
                                 body=namespace["Write"](offset=16, data=b"abc")),
        ]
    return proto, samples, namespace


class TestTheBuiltIns(unittest.TestCase):
    """Hand-written protocols meet the contract."""

    def setUp(self) -> None:
        app.register_builtins()

    def test_each_one_conforms(self) -> None:
        for name, samples in _BUILTIN_SAMPLES.items():
            with self.subTest(protocol=name):
                proto = protocols.for_section(name)
                self.assertIsNotNone(proto, f"{name} should be registered")
                failures = conformance.check_protocol(proto, samples)
                self.assertEqual(failures, [], "\n".join(failures))

    def test_every_registered_protocol_has_samples(self) -> None:
        """Adding a protocol without holding it to the contract must fail.

        The registry is the list; this is what stops a new built-in being
        added beside the others and quietly never checked.
        """
        registered = {p.name for p in protocols.registered()}
        self.assertEqual(
            registered - set(_BUILTIN_SAMPLES), set(),
            "every registered protocol needs sample messages in this file",
        )


class TestTheCompiledExamples(unittest.TestCase):
    """Compiled protocols meet the same contract, checked the same way."""

    def test_sensor_conforms(self) -> None:
        proto, samples, _ = _compiled("sensor")
        self.addCleanup(protocols.unregister, proto.name)
        failures = conformance.check_protocol(proto, samples)
        self.assertEqual(failures, [], "\n".join(failures))

    def test_rpc_conforms(self) -> None:
        """Every switch arm, since each is a different shape on the wire."""
        proto, samples, _ = _compiled("rpc")
        self.addCleanup(protocols.unregister, proto.name)
        failures = conformance.check_protocol(proto, samples)
        self.assertEqual(failures, [], "\n".join(failures))


class TestTheHarnessCatchesThings(unittest.TestCase):
    """A checker nobody has seen fail is a checker nobody knows works."""

    def _register(self, **overrides: object) -> AppProtocol:
        base = {
            "name": "broken", "over": "udp", "ports": frozenset({9871}),
            "messages": (bytearray,),
            "decode": lambda b, t="udp": bytearray(b),
            "encode": lambda m, t="udp": bytes(m),
            "to_spec": lambda m: {"data": bytes(m).hex()},
            "from_spec": lambda s: bytearray(bytes.fromhex(s["data"])),
        }
        proto = AppProtocol(**{**base, **overrides})
        protocols.register(proto)
        self.addCleanup(protocols.unregister, "broken")
        return proto

    def test_a_lossy_decoder_is_caught(self) -> None:
        proto = self._register(decode=lambda b, t="udp": bytearray(b[:1]))
        failures = conformance.check_protocol(proto, [bytearray(b"ab")])
        self.assertTrue(any("not stable" in f for f in failures), failures)

    def test_a_section_that_is_not_json_is_caught(self) -> None:
        proto = self._register(to_spec=lambda m: {"data": object()})
        failures = conformance.check_protocol(proto, [bytearray(b"ab")])
        self.assertTrue(any("not JSON" in f for f in failures), failures)

    def test_a_lossy_spec_round_trip_is_caught(self) -> None:
        proto = self._register(from_spec=lambda s: bytearray(b""))
        failures = conformance.check_protocol(proto, [bytearray(b"ab")])
        self.assertTrue(any("from_spec(to_spec(m)) != m" in f
                            for f in failures), failures)

    def test_a_decoder_accepting_truncated_input_is_caught(self) -> None:
        """The property DHCP failed: a half-built object from a short read."""
        proto = self._register()          # bytearray(b) accepts any prefix
        failures = conformance.check_protocol(proto, [bytearray(b"abcd")])
        self.assertTrue(any("truncated input decoded" in f
                            for f in failures), failures)

    def test_a_sanitiser_that_invents_keys_is_caught(self) -> None:
        def sanitise(section: dict, replacer: object, options: object) -> None:
            section["surprise"] = 1

        proto = self._register(
            sanitise=sanitise,
            decode=lambda b, t="udp": bytearray(b),
        )
        failures = conformance.check_protocol(proto, [bytearray(b"ab")])
        self.assertTrue(any("added keys" in f for f in failures), failures)

    def test_no_samples_is_refused(self) -> None:
        """A contract cannot be checked against nothing."""
        proto = self._register()
        with self.assertRaises(ValueError):
            conformance.check_protocol(proto, [])


class TestCanonicalisation(unittest.TestCase):
    """Normalising is allowed; losing something is not."""

    def setUp(self) -> None:
        app.register_builtins()

    def test_dns_canonicalises_a_name(self) -> None:
        """`example.com` comes back `example.com.`, which is what the wire means."""
        proto = protocols.for_section("dns")
        message = DNSMessage(id=1, questions=[DNSQuestion(name="example.com")])
        self.assertTrue(conformance.canonicalises(proto, message))

    def test_and_that_is_not_a_failure(self) -> None:
        proto = protocols.for_section("dns")
        message = DNSMessage(id=1, questions=[DNSQuestion(name="example.com")])
        self.assertEqual(conformance.check_protocol(proto, [message]), [])


if __name__ == "__main__":
    unittest.main()
