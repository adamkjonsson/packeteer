"""Loading a protocol spec into the grammar dataclasses (#105)."""
from __future__ import annotations

import json
import pathlib
import textwrap
import unittest

from packeteer.protospec import SpecError, from_mapping, load, loads
from packeteer.protospec.spec import (
    BytesType,
    Count,
    CountOf,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Remaining,
    SizeOf,
    Switch,
    Transport,
    UnitRef,
)

_EXAMPLES = pathlib.Path(__file__).resolve().parents[2] / "examples" / "protocols"

_MINIMAL = """
name: tiny
version: "1.0"
entry: message
units:
  message:
    fields:
      - {name: value, type: {int: {bits: 8}}}
"""


def _spec(body: str) -> object:
    return loads(textwrap.dedent(body), fmt="yaml", source="test.yaml")


class TestMinimalSpec(unittest.TestCase):

    def test_loads(self) -> None:
        spec = _spec(_MINIMAL)
        self.assertEqual(spec.name, "tiny")
        self.assertEqual(spec.version, "1.0")
        self.assertEqual(spec.entry, "message")
        self.assertEqual(list(spec.units), ["message"])

    def test_defaults(self) -> None:
        """A spec that says nothing gets the least surprising answers."""
        spec = _spec(_MINIMAL)
        self.assertEqual(spec.input, InputShape.DATAGRAM)
        self.assertEqual(spec.over, Transport.EITHER)
        self.assertEqual(spec.ports, frozenset())
        self.assertIsNone(spec.doc)
        self.assertEqual(spec.unsupported, ())

    def test_missing_required_key_names_it(self) -> None:
        complete = {
            "name": "tiny", "version": "1.0", "entry": "message",
            "units": {"message": {"fields": [
                {"name": "value", "type": {"int": {"bits": 8}}},
            ]}},
        }
        for key in complete:
            with self.subTest(key=key):
                partial = {k: v for k, v in complete.items() if k != key}
                with self.assertRaises(SpecError) as ctx:
                    from_mapping(partial)
                self.assertIn(key, str(ctx.exception))


class TestTheTwoAxes(unittest.TestCase):
    """`input` is the stream shape; `over` is the transport.  Not the same."""

    def test_both_are_read(self) -> None:
        spec = _spec(_MINIMAL + "\ninput: stream\nover: tcp\nports: [8443]\n")
        self.assertEqual(spec.input, InputShape.STREAM)
        self.assertEqual(spec.over, Transport.TCP)
        self.assertEqual(spec.ports, frozenset({8443}))

    def test_they_are_independent(self) -> None:
        """DNS is the example: datagram over UDP, stream over TCP."""
        udp = _spec(_MINIMAL + "\ninput: datagram\nover: udp\n")
        tcp = _spec(_MINIMAL + "\ninput: stream\nover: tcp\n")
        self.assertEqual((udp.input, udp.over), (InputShape.DATAGRAM, Transport.UDP))
        self.assertEqual((tcp.input, tcp.over), (InputShape.STREAM, Transport.TCP))

    def test_a_bad_value_lists_the_alternatives(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec(_MINIMAL + "\nover: sctp\n")
        message = str(ctx.exception)
        self.assertIn("sctp", message)
        for allowed in ("udp", "tcp", "either"):
            self.assertIn(allowed, message)


class TestSizes(unittest.TestCase):
    """kober's four forms, and `4` meaning `{fixed: 4}`."""

    def _size(self, form: str) -> object:
        spec = _spec(f"""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {{name: v, type: {{bytes: {{size: {form}}}}}}}
        """)
        return spec.units["m"].fields[0].type.size

    def test_bare_integer_is_fixed(self) -> None:
        self.assertEqual(self._size("4"), Fixed(length=4))

    def test_fixed(self) -> None:
        self.assertEqual(self._size("{fixed: 4}"), Fixed(length=4))

    def test_expr(self) -> None:
        self.assertEqual(self._size('{expr: "n * 2"}'), FromExpr(expr="n * 2"))

    def test_remaining(self) -> None:
        self.assertEqual(self._size("{remaining: true}"), Remaining())

    def test_unknown_form_lists_the_alternatives(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            self._size("{nonsense: 1}")
        self.assertIn("nonsense", str(ctx.exception))
        self.assertIn("expr", str(ctx.exception))

    def test_a_sized_type_needs_a_size(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            self._size("")
        self.assertIn("size", str(ctx.exception))


class TestPacketeersOwnKeys(unittest.TestCase):
    """The five keys that are packeteer's and not kober's."""

    def setUp(self) -> None:
        self.spec = load(_EXAMPLES / "sensor.yaml")

    def test_over_and_ports(self) -> None:
        self.assertEqual(self.spec.over, Transport.UDP)
        self.assertEqual(self.spec.ports, frozenset({9000}))

    def test_const(self) -> None:
        magic = self.spec.units["reading"].fields[0]
        self.assertEqual(magic.const.value, 0x5345)

    def test_derive_count_of(self) -> None:
        count = self.spec.units["reading"].fields[2]
        self.assertEqual(count.derive, CountOf(field="samples"))

    def test_derive_size_of(self) -> None:
        length = self.spec.units["sample"].fields[1]
        self.assertEqual(length.derive, SizeOf(field="value"))

    def test_sensitive(self) -> None:
        value = self.spec.units["sample"].fields[2]
        self.assertTrue(value.sensitive)
        self.assertFalse(self.spec.units["sample"].fields[0].sensitive)

    def test_an_unknown_derive_rule_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: v, type: {int: {bits: 8}}, derive: {hash_of: w}}
            """)
        self.assertIn("hash_of", str(ctx.exception))


class TestFieldTypes(unittest.TestCase):

    def test_int_carries_width_sign_endian_and_enum(self) -> None:
        spec = load(_EXAMPLES / "sensor.yaml")
        reading = spec.units["sample"].fields[3].type
        self.assertEqual(reading.bits, 32)
        self.assertTrue(reading.signed)
        self.assertEqual(reading.endian.value, "little")
        self.assertEqual(spec.units["sample"].fields[0].type.enum, "kind")

    def test_int_width_is_bounded(self) -> None:
        for bits in (0, 65):
            with self.subTest(bits=bits):
                with self.assertRaises(SpecError) as ctx:
                    _spec(f"""
                        name: t
                        version: "1"
                        entry: m
                        units:
                          m:
                            fields:
                              - {{name: v, type: {{int: {{bits: {bits}}}}}}}
                    """)
                self.assertIn("bits", str(ctx.exception))

    def test_unit_reference_in_both_forms(self) -> None:
        spec = _spec("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: a, type: {unit: other}}
                  - {name: b, type: {unit: {name: other}}}
              other:
                fields:
                  - {name: v, type: {int: {bits: 8}}}
        """)
        self.assertEqual(spec.units["m"].fields[0].type, UnitRef(unit="other"))
        self.assertEqual(spec.units["m"].fields[1].type, UnitRef(unit="other"))

    def test_repeat_by_count(self) -> None:
        spec = load(_EXAMPLES / "sensor.yaml")
        self.assertEqual(spec.units["reading"].fields[3].repeat, Count(expr="count"))

    def test_a_field_type_names_exactly_one_construct(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: v, type: {int: {bits: 8}, bytes: {size: 1}}}
            """)
        self.assertIn("exactly one", str(ctx.exception))


class TestSwitch(unittest.TestCase):

    _BODY = """
        name: t
        version: "1"
        entry: m
        units:
          m:
            fields:
              - {name: kind, type: {int: {bits: 8}}}
              - name: rest
                type:
                  switch:
                    on: "kind"
                    cases:
                      1: {int: {bits: 8}}
                      2: {bytes: {size: 2}}
                    default: {bytes: {size: {remaining: true}}}
    """

    def test_cases_and_default(self) -> None:
        switch = _spec(self._BODY).units["m"].fields[1].type
        self.assertIsInstance(switch, Switch)
        self.assertEqual(switch.on, "kind")
        self.assertEqual(set(switch.arms), {1, 2})
        self.assertIsInstance(switch.arms[1], IntType)
        self.assertIsInstance(switch.default, BytesType)

    def test_the_yaml_on_key_is_restored(self) -> None:
        """`on:` is a YAML 1.1 boolean, and it is a switch's dispatch key."""
        self.assertEqual(_spec(self._BODY).units["m"].fields[1].type.on, "kind")

    def test_both_on_and_true_is_refused(self) -> None:
        body = self._BODY.replace('on: "kind"', 'on: "kind"\n                    "on": "kind"')
        with self.assertRaises(SpecError) as ctx:
            _spec(body)
        self.assertIn("on", str(ctx.exception))

    def test_json_string_case_keys_mean_the_same_cases(self) -> None:
        data = json.loads(json.dumps({
            "name": "t", "version": "1", "entry": "m",
            "units": {"m": {"fields": [
                {"name": "kind", "type": {"int": {"bits": 8}}},
                {"name": "rest", "type": {"switch": {
                    "on": "kind", "cases": {"1": {"int": {"bits": 8}}},
                }}},
            ]}},
        }))
        switch = from_mapping(data).units["m"].fields[1].type
        self.assertEqual(set(switch.arms), {1})


class TestJSONAndYAMLAgree(unittest.TestCase):

    def test_the_same_spec_either_way(self) -> None:
        yaml_spec = load(_EXAMPLES / "sensor.yaml")
        as_json = json.dumps({
            "name": "sensor", "version": "1.0", "entry": "reading",
            "over": "udp", "ports": [9000], "input": "datagram",
            "enums": {"kind": {0: "temperature"}},
            "units": {"reading": {"fields": [
                {"name": "magic", "type": {"int": {"bits": 16}}, "const": 0x5345},
            ]}},
        })
        json_spec = loads(as_json, fmt="json", source="s.json")
        self.assertEqual(json_spec.name, yaml_spec.name)
        self.assertEqual(json_spec.over, yaml_spec.over)
        self.assertEqual(json_spec.ports, yaml_spec.ports)

    def test_malformed_json_is_a_spec_error(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            loads("{not json", fmt="json")
        self.assertIn("JSON", str(ctx.exception))

    def test_malformed_yaml_is_a_spec_error(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            loads("name: [unclosed", fmt="yaml")
        self.assertIn("YAML", str(ctx.exception))

    def test_an_unknown_format_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            loads("{}", fmt="toml")
        self.assertIn("toml", str(ctx.exception))


class TestLocations(unittest.TestCase):
    """The dotted path is always there; the line comes from YAML only."""

    def test_yaml_carries_line_numbers(self) -> None:
        spec = load(_EXAMPLES / "sensor.yaml")
        field = spec.units["reading"].fields[0]
        self.assertIsNotNone(field.loc.line)
        self.assertEqual(field.loc.path, "units.reading.fields[0]")
        self.assertTrue(field.loc.source.endswith("sensor.yaml"))

    def test_json_carries_paths_without_lines(self) -> None:
        spec = loads(json.dumps({
            "name": "t", "version": "1", "entry": "m",
            "units": {"m": {"fields": [{"name": "v", "type": {"int": {"bits": 8}}}]}},
        }), fmt="json", source="s.json")
        field = spec.units["m"].fields[0]
        self.assertIsNone(field.loc.line)
        self.assertEqual(field.loc.path, "units.m.fields[0]")

    def test_an_error_names_where(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: v, type: {int: {bits: 999}}}
            """)
        self.assertIn("units.m.fields[0]", str(ctx.exception))

    def test_a_missing_file_is_a_spec_error(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            load(_EXAMPLES / "nope.yaml")
        self.assertIn("nope.yaml", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()


class TestKoberSpecsLoad(unittest.TestCase):
    """The superset claim, exercised against specs written for kober.

    These are inline rather than vendored copies of kober's files: copies
    drift, and what is being asserted is that the *constructs* load and that
    the ones this version cannot compile are reported as "not supported yet"
    rather than as unknown keys.
    """

    _DNS_LIKE = """
        name: dns
        version: "1.0"
        entry: message
        input: either
        enums:
          rrtype: {1: a, 28: aaaa}
        units:
          message:
            fields:
              - {name: id, type: {int: {bits: 16}}}
              - {name: qdcount, type: {int: {bits: 16}}}
              - {name: questions, type: {unit: question}, repeat: {count: "qdcount"}}
          question:
            fields:
              - {name: qname, type: {unit: name}}
              - {name: qtype, type: {int: {bits: 16, enum: rrtype}}}
          name:
            fields:
              - {name: length, type: {int: {bits: 8}}}
              - name: rest
                type:
                  switch:
                    on: "length >> 6"
                    cases:
                      0: {string: {size: {expr: "length"}}}
                      3: {unit: {name: compressed, args: ["length"]}}
          compressed:
            fields:
              - {name: offset, type: {int: {bits: 8}}}
              - {name: target, type: {pointer: {at: "offset", type: {unit: name}}}}
    """

    _HTTP_LIKE = """
        name: http
        version: "1.0"
        entry: message
        input: stream
        units:
          message:
            fields:
              - name: start_line
                type: {string: {size: {terminated: {delimiter: "\\r\\n"}}}}
              - {name: headers, type: {unit: header}, repeat: {until: "header.name == ''"}}
              - {name: chunked, type: {select: {over: headers, where: "true", value: "1"}}}
          header:
            fields:
              - {name: name, type: {string: {size: {terminated: {delimiter: ":"}}}}}
    """

    def test_a_dns_shaped_spec_loads(self) -> None:
        spec = _spec(self._DNS_LIKE)
        self.assertEqual(spec.input, InputShape.EITHER)
        self.assertEqual(set(spec.units),
                         {"message", "question", "name", "compressed"})
        self.assertEqual(spec.units["message"].fields[2].repeat, Count(expr="qdcount"))

    def test_its_unsupported_constructs_are_named(self) -> None:
        found = {u.construct for u in _spec(self._DNS_LIKE).unsupported}
        self.assertIn("pointer", found)
        self.assertIn("unit.args", found)

    def test_an_http_shaped_spec_loads(self) -> None:
        spec = _spec(self._HTTP_LIKE)
        self.assertEqual(spec.input, InputShape.STREAM)
        self.assertEqual(len(spec.units), 2)

    def test_delimiter_framing_and_select_are_named(self) -> None:
        found = {u.construct for u in _spec(self._HTTP_LIKE).unsupported}
        self.assertIn("size.terminated", found)
        self.assertIn("select", found)
        self.assertIn("repeat.until", found)

    def test_unsupported_carries_a_location_and_a_reason(self) -> None:
        """The checker prints these, so they have to be worth printing."""
        for item in _spec(self._HTTP_LIKE).unsupported:
            with self.subTest(construct=item.construct):
                self.assertTrue(item.loc.path)
                self.assertTrue(item.note)

    def test_unsupported_is_not_an_error(self) -> None:
        """Loading finishes, so the checker can report every fault at once."""
        spec = _spec(self._HTTP_LIKE)
        self.assertTrue(spec.unsupported)
        self.assertEqual(spec.name, "http")


class TestUnknownConstructsAreStillErrors(unittest.TestCase):
    """"Not supported yet" is for kober's constructs, not for typos."""

    def test_an_unknown_field_type_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: v, type: {flout: {bits: 8}}}
            """)
        self.assertIn("flout", str(ctx.exception))

    def test_a_repeat_with_no_recognised_form_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: v, type: {int: {bits: 8}}, repeat: {twice: true}}
            """)
        self.assertIn("count", str(ctx.exception))


class TestYAMLImplicitTyping(unittest.TestCase):
    """YAML 1.1 mangles `on`, `yes`, `no` and `1.10`; say so, do not guess.

    packeteer reads specs as ordinary YAML rather than reinterpreting the
    document, because a spec has to mean the same thing to every YAML tool
    that opens it.  So a coerced value is named and the author is told to
    quote it — kober's approach, and the messages are deliberately alike.
    """

    def _load(self, body: str) -> object:
        return loads(textwrap.dedent(body), fmt="yaml")

    def test_a_unit_named_on_is_refused_with_the_reason(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            self._load("""
                name: t
                version: "1"
                entry: "on"
                units:
                  on:
                    fields:
                      - {name: v, type: {int: {bits: 8}}}
            """)
        self.assertIn("quote it", str(ctx.exception))

    def test_a_field_named_no_is_refused_with_the_reason(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            self._load("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: no, type: {int: {bits: 8}}}
            """)
        self.assertIn("booleans", str(ctx.exception))

    def test_an_unquoted_version_is_refused_rather_than_truncated(self) -> None:
        """`version: 1.10` is the float 1.1, which is not the string "1.10"."""
        with self.assertRaises(SpecError) as ctx:
            self._load("""
                name: t
                version: 1.10
                entry: m
                units:
                  m:
                    fields:
                      - {name: v, type: {int: {bits: 8}}}
            """)
        self.assertIn("quote it", str(ctx.exception))

    def test_quoting_is_all_it_takes(self) -> None:
        spec = self._load("""
            name: t
            version: "1.10"
            entry: m
            units:
              m:
                fields:
                  - {name: "no", type: {int: {bits: 8}}}
        """)
        self.assertEqual(spec.version, "1.10")
        self.assertEqual(spec.units["m"].fields[0].name, "no")

    def test_json_is_unaffected(self) -> None:
        """JSON has no implicit typing, so none of this applies to it."""
        spec = from_mapping({
            "name": "t", "version": "1.10", "entry": "m",
            "units": {"m": {"fields": [
                {"name": "no", "type": {"int": {"bits": 8}}},
            ]}},
        })
        self.assertEqual(spec.version, "1.10")
        self.assertEqual(spec.units["m"].fields[0].name, "no")


class TestUnknownKeysAreRefused(unittest.TestCase):
    """A misspelled key that loads and does nothing is worse than a refusal.

    It produces a decoder that silently does the wrong thing — kober's
    reasoning, and this was found by a `doc:` inside YAML flow style splitting
    on its comma and leaving a stray key that was quietly ignored.
    """

    def test_an_unknown_top_level_key(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec(_MINIMAL + "\nnmae: typo\n")
        self.assertIn("nmae", str(ctx.exception))

    def test_an_unknown_unit_key(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    feilds:
                      - {name: a, type: {int: {bits: 8}}}
            """)
        self.assertIn("feilds", str(ctx.exception))

    def test_an_unknown_field_key(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: a, type: {int: {bits: 8}}, sensitve: true}
            """)
        self.assertIn("sensitve", str(ctx.exception))

    def test_the_message_lists_what_is_known(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _spec(_MINIMAL + "\nnmae: typo\n")
        self.assertIn("'entry'", str(ctx.exception))

    def test_a_flow_style_doc_split_on_its_comma_is_caught(self) -> None:
        """`doc: a, b` inside braces is two keys, and the second is a typo."""
        with self.assertRaises(SpecError) as ctx:
            _spec("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: a, type: {int: {bits: 8}}, doc: Reserved, must be zero.}
            """)
        self.assertIn("must be zero", str(ctx.exception))

    def test_kober_keys_this_version_lacks_are_not_typos(self) -> None:
        """`params` and `emit` load and are reported as unsupported instead."""
        spec = _spec("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                params: []
                fields:
                  - {name: a, type: {int: {bits: 8}}}
        """)
        self.assertIn("unit.params", {u.construct for u in spec.unsupported})
