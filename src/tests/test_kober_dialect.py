"""kober's own specs, held to packeteer's loader (#144).

`docs/protocols/format.md` calls this dialect a superset of
[kober](https://github.com/adamkjonsson/zipline-kober)'s.  This is what makes
that a property of two loaders rather than a sentence in two references: the
specs under `kober/` are kober 0.5.0's shipped examples, and each assertion
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
        """Pinned deliberately: a new one appearing is a dialect change.

        kober 0.5.0 added four to 0.2.0's four, each read before it was
        accepted here: `unit.confirm` is the start-line guard that refuses a
        guess after a gap (kober #50); `concat` joins a chunked body's data;
        `transform` inflates a `Content-Encoding` body; and the two switches
        choosing between them dispatch on strings, `framing` and `encoding`.
        """
        self.assertEqual(
            _constructs(self.spec),
            {"size.terminated", "computed", "select", "repeat.until",
             "unit.confirm", "concat", "transform", "switch on a string"},
        )

    def test_it_loads_since_kober_0_5_0_changed_it(self) -> None:
        """0.16.0 refused this file at load, on its first string case (#170, #171)."""
        self.assertIn("content", [f.name for f in self.spec.units["message"].fields])
        self.assertEqual(len(check(self.spec).errors), 19)

    def test_every_finding_is_not_supported_yet(self) -> None:
        """What this directory's README says the test is for (#167).

        Stricter than `dns.yaml`'s version of this test, which holds errors
        only: `dns.yaml` has real integer lengths that nothing derives, and
        its derive warnings are true.  Here every length is a `select` or a
        `computed`, and a warning about one was a stand-in's, not the spec's —
        as were six type errors on expressions that kober types correctly.
        """
        findings = [str(d) for d in check(self.spec).diagnostics
                    if "not supported yet" not in d.message]
        self.assertEqual(findings, [])


class TestTransformAndConcat(unittest.TestCase):
    """kober 0.5.0's two field types, declined by name and still shape-checked (#170)."""

    _HEAD = """
name: t
version: "1"
entry: m
units:
  m:
    fields:
      - {name: n, bits: 8}
      - {name: chunks, unit: chunk, count: n}
      - {name: body, bytes: {size: {expr: n}}}
"""
    _CHUNK = """
  chunk:
    fields:
      - {name: size, bits: 8}
      - {name: data, bytes: {size: {expr: size}}}
"""

    def _load(self, fields: str, extra: str = "") -> object:
        from packeteer.protospec import loads
        return loads(self._HEAD + fields + self._CHUNK + extra, fmt="yaml")

    def _declines(self, spec: object) -> list[str]:
        return [d.message for d in check(spec).diagnostics
                if d.severity == "error"]

    def test_the_issues_spec(self) -> None:
        """Refused at load as unknown keys in 0.16.0; now one message each."""
        spec = self._load("""\
      - {name: joined, concat: chunks.data}
      - name: content
        transform: {from: body, with: gzip, limit: 64}
""")
        self.assertEqual(_constructs(spec), {"concat", "transform"})
        errors = self._declines(spec)
        self.assertEqual(len(errors), 2, errors)
        for message in errors:
            self.assertIn("not supported yet", message)

    def test_either_as_a_switch_case(self) -> None:
        """The 0.5.0 `http.yaml` has both as switch arms."""
        spec = self._load("""\
      - name: content
        switch:
          dispatch: n
          cases:
            1: {concat: chunks.data}
            2: {transform: {from: body, with: deflate, limit: 64}}
          default: {bytes: 1}
""")
        self.assertEqual(_constructs(spec), {"concat", "transform"})
        self.assertEqual(len(self._declines(spec)), 2)

    def test_every_transform_key(self) -> None:
        spec = self._load("""\
      - name: content
        transform:
          from: body
          with: aes-gcm
          limit: 64
          args: {key: "n"}
          type: {unit: document}
          content_type: application/json
""", """
  document:
    fields:
      - {name: v, bits: 8}
""")
        self.assertEqual(_constructs(spec), {"transform"})

    def test_a_unit_a_transform_decodes_as_is_reached(self) -> None:
        """Its `type` names the unit; #167's stand-in remembers that."""
        spec = self._load("""\
      - name: content
        transform: {from: body, with: gzip, limit: 64, type: {unit: document}}
""", """
  document:
    fields:
      - {name: v, bits: 8}
""")
        messages = [d.message for d in check(spec).diagnostics]
        self.assertFalse([m for m in messages if "never referenced" in m], messages)

    def _refused(self, fields: str) -> str:
        with self.assertRaises(SpecError) as ctx:
            self._load(fields)
        return str(ctx.exception)

    def test_a_transform_missing_a_required_key(self) -> None:
        """Declining it must not loosen it: kober requires all three."""
        self.assertIn("needs 'limit'", self._refused("""\
      - {name: content, transform: {from: body, with: gzip}}
"""))

    def test_a_transform_with_an_unknown_key(self) -> None:
        self.assertIn("no key 'lmit'", self._refused("""\
      - {name: content, transform: {from: body, with: gzip, lmit: 64}}
"""))

    def test_a_transform_limit_that_is_not_positive(self) -> None:
        self.assertIn("must be positive", self._refused("""\
      - {name: content, transform: {from: body, with: gzip, limit: 0}}
"""))

    def test_a_concat_that_is_not_repeated_dot_member(self) -> None:
        for path in ("chunks", "chunks.data.more", ".data"):
            with self.subTest(path=path):
                self.assertIn("as 'chunks.data'", self._refused(
                    f"      - {{name: joined, concat: {path}}}\n"))


class TestTheTunnelShape(unittest.TestCase):
    """kober's tunnel example: a sealed payload, then what opens it (#174).

    The shape kober's docs teach for decryption: a header, the payload sized
    `remaining`, then the `transform` that reads it.  The transform reads no
    byte where it stands, so the `remaining` is correct, and packeteer said
    to change it.
    """

    def test_only_its_constructs_are_reported(self) -> None:
        from packeteer.protospec import loads
        spec = loads("""
name: t
version: "1"
entry: datagram
transforms:
  xor: {params: {key: bytes, nonce: bytes}}
params:
  key: {type: bytes, secret: true}
units:
  datagram:
    fields:
      - {name: nonce, bytes: 8}
      - {name: sealed, bytes: {size: {remaining: true}}}
      - name: inner
        transform: {from: sealed, with: xor, limit: 1500, args: {key: key, nonce: nonce}}
""", fmt="yaml")
        self.assertEqual(_constructs(spec), {"params", "transforms", "transform"})
        findings = [str(d) for d in check(spec).diagnostics
                    if "not supported yet" not in d.message]
        self.assertEqual(findings, [])


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

    def test_document_params_and_transforms(self) -> None:
        """The document keys kober 0.5.0 added, each declined once by name (#168).

        A document's ``params`` are values supplied when a decode is set up,
        not the unit parameters the same word means one level down, and the
        note says which.
        """
        spec = self._load("""
name: t
version: "1"
entry: m
params:
  key: {type: bytes, secret: true}
transforms:
  aes-gcm: {params: {key: bytes}}
units:
  m:
    fields:
      - {name: a, bits: 8}
""")
        self.assertEqual(_constructs(spec), {"params", "transforms"})
        notes = {item.construct: item.note for item in spec.unsupported}
        self.assertIn("document parameters", notes["params"])
        messages = [d.message for d in check(spec).diagnostics]
        self.assertEqual(len(messages), 2, messages)

    def test_unit_params_are_still_unit_parameters(self) -> None:
        spec = self._load("""
name: t
version: "1"
entry: m
units:
  m:
    params: [n]
    fields:
      - {name: a, bits: 8}
""")
        self.assertEqual(_constructs(spec), {"unit.params"})
        self.assertIn("unit parameters", spec.unsupported[0].note)

    def test_a_document_emit_is_a_typo(self) -> None:
        """In kober `emit` is on a unit and a field, never on a document (#168).

        Declining it said kober would take it, and kober refuses it too.
        """
        with self.assertRaises(SpecError) as ctx:
            self._load("""
name: t
version: "1"
entry: m
emit: field
units:
  m:
    fields:
      - {name: a, bits: 8}
""")
        self.assertIn("no key 'emit'", str(ctx.exception))

    def test_a_unit_emit_is_still_declined(self) -> None:
        spec = self._load("""
name: t
version: "1"
entry: m
units:
  m:
    emit: field
    fields:
      - {name: a, bits: 8}
""")
        self.assertEqual(_constructs(spec), {"unit.emit"})

    def test_the_long_enum_form(self) -> None:
        """The long `{doc, members}` enum, which neither vendored spec writes (#166).

        Invisible until someone documents an enum, which is what the form is
        for; 0.16.0 read `doc` and `members` as two enum values.
        """
        spec = self._load("""
name: t
version: "1"
entry: m
enums:
  opcode:
    doc: RFC 1035 §4.1.1.
    members: {0: query, 1: iquery}
units:
  m:
    fields:
      - {name: op, int: {bits: 4, enum: opcode}}
""")
        self.assertEqual(dict(spec.enums["opcode"].members), {0: "query", 1: "iquery"})
        self.assertEqual(check(spec).diagnostics, ())

    def test_a_count_written_as_a_number(self) -> None:
        """Not a construct kober has and packeteer lacks, a spelling (#175).

        So it loads and checks clean, rather than being declined.
        """
        spec = self._load("""
name: t
version: "1"
entry: m
input: datagram
units:
  m:
    fields:
      - {name: xs, bits: 8, count: 2}
""")
        self.assertEqual(check(spec).diagnostics, ())

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
