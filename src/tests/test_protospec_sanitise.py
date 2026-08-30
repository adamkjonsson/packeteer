"""A compiled protocol redacts its own sensitive fields (#117)."""
from __future__ import annotations

import unittest
import warnings
from typing import Any

from packeteer import protocols
from packeteer.protospec import loads
from packeteer.protospec.codegen import compile_spec
from packeteer.sanitise import (
    PersonalDataWarning,
    SanitiseOptions,
    _Replacer,
    sanitise,
)

_HEAD = """
name: {name}
version: "1.0"
over: udp
ports: [{port}]
input: datagram
entry: {entry}
units:
"""


def _compile(body: str, *, name: str, port: int, entry: str) -> dict[str, Any]:
    """Compile a spec body and return the generated module's namespace."""
    code = compile_spec(loads(_HEAD.format(name=name, port=port, entry=entry) + body))
    namespace: dict[str, Any] = {}
    exec(compile(code, f"<{name}>", "exec"), namespace)   # noqa: S102
    return namespace


class _CompiledSpec(unittest.TestCase):
    """Compiles a spec for each test and unregisters it afterwards."""

    body = ""
    name = "test_proto"
    port = 9000
    entry = "Msg"

    def setUp(self) -> None:
        self.ns = _compile(self.body, name=self.name, port=self.port,
                           entry=self.entry)
        self.proto = self.ns["PROTOCOL"]
        self.addCleanup(protocols.unregister, self.name)

    def redact(self, section: dict) -> dict:
        self.proto.sanitise(section, _Replacer(), SanitiseOptions())
        return section


class TestAnnotatedFieldsAreRedacted(_CompiledSpec):
    """`sensitive: true` has been in the grammar since #105 and did nothing."""

    body = """
  Msg:
    fields:
      - {name: version, type: {int: {bits: 8}}}
      - {name: owner, type: {string: {size: 12}}, sensitive: true}
      - {name: token, type: {bytes: {size: 4}}, sensitive: true}
      - {name: device_id, type: {int: {bits: 16}}, sensitive: true}
      - {name: reading, type: {int: {bits: 16}}}
"""

    def _section(self) -> dict:
        return {"version": 1, "owner": "alice.smith", "token": "deadbeef",
                "device_id": 4242, "reading": 21}

    def test_a_string_becomes_the_redaction_marker(self) -> None:
        self.assertEqual(self.redact(self._section())["owner"], "[redacted]")

    def test_bytes_are_zeroed_and_keep_their_length(self) -> None:
        """A `size` field elsewhere may derive from it, so length matters."""
        self.assertEqual(self.redact(self._section())["token"], "00000000")

    def test_an_int_becomes_zero(self) -> None:
        self.assertEqual(self.redact(self._section())["device_id"], 0)

    def test_unannotated_fields_are_untouched(self) -> None:
        """Q4: redact what is annotated, and only that."""
        out = self.redact(self._section())
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["reading"], 21)

    def test_the_protocol_does_not_claim_to_redact_nothing(self) -> None:
        self.assertFalse(self.proto.redacts_nothing)


class TestNestedAndRepeatedFields(_CompiledSpec):
    """A sensitive field is followed into nested units and repeated ones."""

    name = "nested_proto"
    port = 9001
    entry = "Outer"
    body = """
  Outer:
    fields:
      - {name: count, type: {int: {bits: 8}}}
      - {name: inner, type: {unit: Inner}}
      - {name: items, type: {unit: Item}, repeat: {count: "count"}}
  Inner:
    fields:
      - {name: secret, type: {string: {size: 8}}, sensitive: true}
      - {name: keep, type: {int: {bits: 8}}}
  Item:
    fields:
      - {name: label, type: {string: {size: 4}}, sensitive: true}
"""

    def test_a_nested_unit_is_followed(self) -> None:
        out = self.redact({"count": 0, "inner": {"secret": "hunter2", "keep": 7},
                           "items": []})
        self.assertEqual(out["inner"]["secret"], "[redacted]")
        self.assertEqual(out["inner"]["keep"], 7, "and only the marked field")

    def test_every_element_of_a_repeated_unit_is_redacted(self) -> None:
        out = self.redact({"count": 2, "inner": {"secret": "x", "keep": 1},
                           "items": [{"label": "abcd"}, {"label": "efgh"}]})
        self.assertEqual([i["label"] for i in out["items"]],
                         ["[redacted]", "[redacted]"])


class TestASpecThatAnnotatesNothing(_CompiledSpec):
    """Q4's answer: silence is the one outcome that must not be available."""

    name = "bare_proto"
    port = 9002
    body = """
  Msg:
    fields:
      - {name: owner, type: {string: {size: 12}}}
"""

    def test_the_protocol_declares_that_it_redacts_nothing(self) -> None:
        self.assertTrue(self.proto.redacts_nothing)

    def test_it_still_has_a_sanitise_callable(self) -> None:
        """It is the declaration, not a missing callable, that says so.

        A compiled protocol always has a sanitiser, so "nobody wrote one" is
        not a failure mode available to it — which is why #117 needed a way
        to say "nobody marked anything" instead.
        """
        self.assertIsNotNone(self.proto.sanitise)

    def test_sanitising_a_capture_warns(self) -> None:
        config = {"packets": [{
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp"},
            "transport": {"src_port": 5, "dst_port": self.port},
            self.name: {"owner": "nothing identifying"},
        }]}
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            sanitise(config)
        messages = [str(w.message) for w in caught
                    if isinstance(w.message, PersonalDataWarning)]
        self.assertTrue(any(self.name in m and "redacts nothing" in m
                            for m in messages), messages)

    def test_the_section_is_passed_through_rather_than_blanked(self) -> None:
        """Redacting everything unmarked would make the protocol useless."""
        config = {"packets": [{
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp"},
            "transport": {"src_port": 5, "dst_port": self.port},
            self.name: {"owner": "keep me"},
        }]}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            out = sanitise(config)
        self.assertEqual(out["packets"][0][self.name]["owner"], "keep me")


class TestAnnotatedSpecsDoNotWarn(_CompiledSpec):
    """The control: the warning must mean something when it appears."""

    name = "quiet_proto"
    port = 9003
    body = """
  Msg:
    fields:
      - {name: owner, type: {string: {size: 12}}, sensitive: true}
"""

    def test_no_redacts_nothing_warning(self) -> None:
        config = {"packets": [{
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp"},
            "transport": {"src_port": 5, "dst_port": self.port},
            self.name: {"owner": "alice"},
        }]}
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            out = sanitise(config)
        self.assertNotIn("redacts nothing",
                         " ".join(str(w.message) for w in caught))
        self.assertEqual(out["packets"][0][self.name]["owner"], "[redacted]")


class TestStringFieldsAreScannedForPII(_CompiledSpec):
    """A name or an email is likelier in a string field than in a payload."""

    name = "scan_proto"
    port = 9004
    body = """
  Msg:
    fields:
      - {name: note, type: {string: {size: 40}}}
"""

    def _sanitise_with(self, note: str) -> list[str]:
        config = {"packets": [{
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "udp"},
            "transport": {"src_port": 5, "dst_port": self.port},
            self.name: {"note": note},
        }]}
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            sanitise(config)
        return [str(w.message) for w in caught]

    def test_an_email_in_a_string_field_is_reported(self) -> None:
        self.assertTrue(any("alice.smith@example.com" in m
                            for m in self._sanitise_with("alice.smith@example.com")))

    def test_an_ordinary_string_is_not(self) -> None:
        """The control: a scanner that fires on anything reports nothing."""
        self.assertFalse(any("Possible" in m
                             for m in self._sanitise_with("reading 21 ok")))


if __name__ == "__main__":
    unittest.main()
