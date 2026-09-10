"""kober's own specs, held to packeteer's loader (#144).

`docs/protocols/format.md` calls this dialect a superset of
[kober](https://github.com/adamkjonsson/zipline-kober)'s.  This is what makes
that a property of two loaders rather than a sentence in two references: the
specs under `kober/` are kober 0.2.0's shipped examples, and each assertion
here is about the *outcome*, not merely that a file parses.

kober vendors packeteer's specs the same way and asserts the same kind of
thing, so the two projects notice each other moving.
"""
from __future__ import annotations

import pathlib
import unittest

from packeteer.protospec import SpecError, check, load

_SPECS = pathlib.Path(__file__).resolve().parent / "kober"


def _constructs(spec: object) -> set[str]:
    """Return the constructs a spec carries that this version cannot compile."""
    return {item.construct for item in spec.unsupported}


class TestKoberDNS(unittest.TestCase):
    """`dns.yaml` loads and is refused only for constructs packeteer lacks."""

    def setUp(self) -> None:
        self.spec = load(_SPECS / "dns.yaml")

    def test_it_loads(self) -> None:
        """Before 0.13.0 this died on `bits:` at the first field."""
        self.assertEqual(self.spec.name, "dns")
        self.assertIn("message", self.spec.units)

    def test_every_field_is_read(self) -> None:
        """A shorthand left unimplemented would show up as a missing field."""
        self.assertEqual(
            [f.name for f in self.spec.units["message"].fields],
            ["id", "flags", "qdcount", "ancount", "nscount", "arcount",
             "questions", "answers", "authority", "additional"],
        )

    def test_an_anonymous_field_survives(self) -> None:
        """`name: null` is kober's reserved-bits spelling, written short."""
        self.assertEqual(
            [f.name for f in self.spec.units["flags"].fields],
            ["qr", "opcode", "aa", "tc", "rd", "ra", None, "rcode"],
        )

    def test_it_reports_exactly_the_constructs_packeteer_lacks(self) -> None:
        """Pinned deliberately: a new one appearing is a dialect change."""
        self.assertEqual(
            _constructs(self.spec),
            {"repeat.until", "unit.args", "unit.params", "pointer"},
        )

    def test_every_error_is_not_supported_yet(self) -> None:
        """Nothing kober wrote is reported as a typo or a fault of its own."""
        errors = [d.message for d in check(self.spec).diagnostics
                  if d.severity == "error"]
        self.assertTrue(errors)
        for message in errors:
            self.assertIn("not supported yet", message, message)

    def test_a_stand_in_is_not_reported_as_a_remaining(self) -> None:
        """The loader stands `bytes: remaining` in for an unsupported construct.

        Reading that as though the author wrote it made `qname` look like a
        field that eats the rest of the message, and produced two errors about
        a `remaining` nobody wrote.
        """
        errors = [d.message for d in check(self.spec).diagnostics]
        self.assertFalse([m for m in errors if "would have no bytes left" in m],
                         errors)


class TestKoberHTTP(unittest.TestCase):
    """`http.yaml` is refused, and the reason is asserted rather than assumed."""

    def setUp(self) -> None:
        self.spec = load(_SPECS / "http.yaml")

    def test_it_loads_even_though_it_cannot_compile(self) -> None:
        self.assertEqual(self.spec.name, "http")

    def test_it_is_refused_for_stream_framing_and_delimiters(self) -> None:
        """Both are out of packeteer's scope by design, not by omission."""
        self.assertEqual(self.spec.input.value, "stream")
        self.assertIn("size.terminated", _constructs(self.spec))

    def test_delimiter_framing_is_named_rather_than_reported_as_a_missing_size(
            self) -> None:
        """Kober writes `delimiter` beside `size`; it is still `terminated`."""
        errors = [d.message for d in check(self.spec).diagnostics]
        self.assertFalse([m for m in errors if "needs a size" in m], errors)

    def test_it_reports_exactly_the_constructs_packeteer_lacks(self) -> None:
        self.assertEqual(
            _constructs(self.spec),
            {"size.terminated", "computed", "select", "repeat.until"},
        )


class TestKoberOnlyKeys(unittest.TestCase):
    """kober's decode-only keys are declined by name, not read as typos (#144)."""

    def _load(self, body: str) -> object:
        from packeteer.protospec import loads
        return loads(body, fmt="yaml")

    def test_unit_confirm_and_reject(self) -> None:
        spec = self._load("""
name: t
version: "1"
entry: m
units:
  m:
    confirm: "magic == 1"
    reject: "magic == 0"
    fields:
      - {name: magic, bits: 16}
""")
        self.assertEqual(_constructs(spec), {"unit.confirm", "unit.reject"})

    def test_field_emit(self) -> None:
        spec = self._load("""
name: t
version: "1"
entry: m
units:
  m:
    fields:
      - {name: magic, bits: 16, emit: none}
""")
        self.assertEqual(_constructs(spec), {"emit"})

    def test_a_real_typo_is_still_an_error(self) -> None:
        """Declining known keys must not loosen anything."""
        with self.assertRaises(SpecError) as ctx:
            self._load("""
name: t
version: "1"
entry: m
units:
  m:
    fields:
      - {name: magic, bits: 16, conditon: "magic == 1"}
""")
        self.assertIn("'conditon'", str(ctx.exception))
