"""Validating a spec before any data exists (#107)."""
from __future__ import annotations

import textwrap
import unittest

from packeteer.protospec import check, load, loads
from packeteer.protospec.check import CheckResult

_EXAMPLE = "examples/protocols/sensor.yaml"


def _check(body: str) -> CheckResult:
    return check(loads(textwrap.dedent(body), fmt="yaml", source="t.yaml"))


def _messages(result: CheckResult) -> str:
    return " | ".join(d.message for d in result.diagnostics)


_UNIT = """
    name: t
    version: "1"
    entry: m
    units:
      m:
        fields:
"""


def _unit(fields: str) -> CheckResult:
    """Check a one-unit spec whose fields are *fields*."""
    return _check(_UNIT + textwrap.indent(textwrap.dedent(fields), " " * 10))


class TestAGoodSpecPasses(unittest.TestCase):

    def test_the_example_spec_is_clean(self) -> None:
        result = check(load(_EXAMPLE))
        self.assertEqual(result.diagnostics, ())
        self.assertTrue(result.ok(strict=True))
        self.assertEqual(result.summary(), "sensor 1.0: ok")


class TestEveryFaultIsReported(unittest.TestCase):
    """Not just the first — that is what lets a spec be fixed in one pass."""

    def test_three_faults_come_back_together(self) -> None:
        result = _unit("""
            - {name: a, type: {int: {bits: 8, enum: nope}}}
            - {name: b, type: {int: {bits: 8}}, derive: {count_of: missing}}
            - {name: c, type: {int: {bits: 8}}, const: "text"}
        """)
        self.assertEqual(len(result.errors), 3)
        joined = _messages(result)
        self.assertIn("nope", joined)
        self.assertIn("missing", joined)
        self.assertIn("const", joined)


class TestStructure(unittest.TestCase):

    def test_a_missing_entry_unit_lists_what_exists(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: nowhere
            units:
              m:
                fields:
                  - {name: a, type: {int: {bits: 8}}}
        """)
        self.assertIn("nowhere", _messages(result))
        self.assertIn("m", _messages(result))

    def test_an_unknown_unit_reference(self) -> None:
        self.assertIn("ghost", _messages(_unit("""
            - {name: a, type: {unit: ghost}}
        """)))

    def test_an_unknown_enum(self) -> None:
        self.assertIn("nope", _messages(_unit("""
            - {name: a, type: {int: {bits: 8, enum: nope}}}
        """)))

    def test_duplicate_field_names(self) -> None:
        self.assertIn("two fields named", _messages(_unit("""
            - {name: a, type: {int: {bits: 8}}}
            - {name: a, type: {int: {bits: 8}}}
        """)))

    def test_an_unreachable_unit_is_a_warning(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: a, type: {int: {bits: 8}}}
              orphan:
                fields:
                  - {name: b, type: {int: {bits: 8}}}
        """)
        self.assertEqual(result.errors, ())
        self.assertIn("never referenced", _messages(result))
        self.assertTrue(result.ok())
        self.assertFalse(result.ok(strict=True))

    def test_recursion_is_not_supported_yet(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: a, type: {unit: m}}
        """)
        self.assertIn("recursive", _messages(result))


class TestDeclarationOrder(unittest.TestCase):
    """A field may only reference fields decoded before it."""

    def test_a_forward_reference_is_refused(self) -> None:
        result = _unit("""
            - {name: body, type: {bytes: {size: {expr: "length"}}}}
            - {name: length, type: {int: {bits: 8}}}
        """)
        self.assertIn("declared later", _messages(result))

    def test_a_backward_reference_is_fine(self) -> None:
        result = _unit("""
            - {name: length, type: {int: {bits: 8}}, derive: {size_of: body}}
            - {name: body, type: {bytes: {size: {expr: "length"}}}}
        """)
        self.assertEqual(result.errors, ())

    def test_a_field_that_does_not_exist(self) -> None:
        self.assertIn("no field 'nope'", _messages(_unit("""
            - {name: body, type: {bytes: {size: {expr: "nope"}}}}
        """)))

    def test_a_repeated_field_has_no_list_type(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: n, type: {int: {bits: 8}}}
                  - {name: xs, type: {unit: e}, repeat: {count: "n"}}
                  - {name: body, type: {bytes: {size: {expr: "xs"}}}}
              e:
                fields:
                  - {name: v, type: {int: {bits: 8}}}
        """)
        self.assertIn("no list type", _messages(result))

    def test_a_dotted_path_descends_into_a_unit(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: header, type: {unit: h}}
                  - {name: body, type: {bytes: {size: {expr: "header.length"}}}}
              h:
                fields:
                  - {name: length, type: {int: {bits: 8}}}
        """)
        self.assertEqual(result.errors, ())


class TestExpressionTypes(unittest.TestCase):

    def test_a_size_must_be_an_integer(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: tag, type: {string: {size: 4}}}
                  - {name: body, type: {bytes: {size: {expr: "tag"}}}}
        """)
        self.assertIn("expected int", _messages(result))

    def test_a_repeat_count_must_be_an_integer(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: tag, type: {string: {size: 4}}}
                  - {name: xs, type: {unit: e}, repeat: {count: "tag"}}
              e:
                fields:
                  - {name: v, type: {int: {bits: 8}}}
        """)
        self.assertIn("expected int", _messages(result))

    def test_a_bad_expression_is_reported_not_raised(self) -> None:
        result = _unit("""
            - {name: body, type: {bytes: {size: {expr: "1 +"}}}}
        """)
        self.assertTrue(result.errors)
        self.assertIn("1 +", _messages(result))


class TestEncodability(unittest.TestCase):
    """The half kober never had to check: a spec that decodes may not encode."""

    def test_count_of_needs_a_repeated_field(self) -> None:
        self.assertIn("does not repeat", _messages(_unit("""
            - {name: n, type: {int: {bits: 8}}, derive: {count_of: v}}
            - {name: v, type: {int: {bits: 8}}}
        """)))

    def test_size_of_a_repeated_field_says_use_count_of(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: n, type: {int: {bits: 8}}}
                  - {name: sz, type: {int: {bits: 8}}, derive: {size_of: xs}}
                  - {name: xs, type: {unit: e}, repeat: {count: "n"}}
              e:
                fields:
                  - {name: v, type: {int: {bits: 8}}}
        """)
        self.assertIn("count_of", _messages(result))

    def test_derive_naming_a_field_that_does_not_exist(self) -> None:
        self.assertIn("ghost", _messages(_unit("""
            - {name: n, type: {int: {bits: 8}}, derive: {size_of: ghost}}
        """)))

    def test_derive_cannot_name_itself(self) -> None:
        self.assertIn("cannot name the field it is on", _messages(_unit("""
            - {name: n, type: {int: {bits: 8}}, derive: {size_of: n}}
        """)))

    def test_derive_needs_an_integer_field(self) -> None:
        self.assertIn("integer field", _messages(_unit("""
            - {name: n, type: {string: {size: 2}}, derive: {size_of: v}}
            - {name: v, type: {int: {bits: 8}}}
        """)))

    def test_a_length_nothing_derives_is_a_warning_with_the_fix(self) -> None:
        """The capture still round-trips; building one by hand is the problem."""
        result = _unit("""
            - {name: length, type: {int: {bits: 8}}}
            - {name: body, type: {bytes: {size: {expr: "length"}}}}
        """)
        self.assertEqual(result.errors, ())
        self.assertIn("size_of: body", _messages(result))

    def test_a_const_of_the_wrong_type(self) -> None:
        self.assertIn("const", _messages(_unit("""
            - {name: magic, type: {int: {bits: 16}}, const: "SE"}
        """)))

    def test_a_const_too_wide_for_its_field(self) -> None:
        self.assertIn("does not fit", _messages(_unit("""
            - {name: magic, type: {int: {bits: 8}}, const: 999}
        """)))

    def test_a_const_on_a_unit_has_nowhere_to_go(self) -> None:
        result = _check("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: h, type: {unit: e}, const: 1}
              e:
                fields:
                  - {name: v, type: {int: {bits: 8}}}
        """)
        self.assertIn("value of its own", _messages(result))


class TestSwitchWarnings(unittest.TestCase):

    def test_no_default_is_a_warning(self) -> None:
        result = _unit("""
            - {name: kind, type: {int: {bits: 8}}}
            - name: rest
              type:
                switch:
                  on: "kind"
                  cases:
                    1: {int: {bits: 8}}
        """)
        self.assertEqual(result.errors, ())
        self.assertIn("no default", _messages(result))

    def test_a_default_silences_it(self) -> None:
        result = _unit("""
            - {name: kind, type: {int: {bits: 8}}}
            - name: rest
              type:
                switch:
                  on: "kind"
                  cases:
                    1: {int: {bits: 8}}
                  default: {bytes: {size: {remaining: true}}}
        """)
        self.assertEqual(result.diagnostics, ())


class TestStreamFraming(unittest.TestCase):
    """A stream spec must prove a reassembler can find a message's end."""

    _DNS_OVER_TCP = """
        name: dnstcp
        version: "1.0"
        input: stream
        over: tcp
        ports: [53]
        entry: framed
        units:
          framed:
            fields:
              - {name: length, type: {int: {bits: 16}}, derive: {size_of: message}}
              - {name: message, type: {bytes: {size: {expr: "length"}}}}
    """

    def test_the_dns_over_tcp_shape_proves_and_yields_its_prefix(self) -> None:
        result = _check(self._DNS_OVER_TCP)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.prefix_size, 2)

    def test_a_datagram_spec_has_no_prefix(self) -> None:
        self.assertIsNone(check(load(_EXAMPLE)).prefix_size)

    def test_no_framing_field_is_refused(self) -> None:
        result = _check("""
            name: t
            version: "1"
            input: stream
            over: tcp
            entry: m
            units:
              m:
                fields:
                  - {name: body, type: {bytes: {size: {remaining: true}}}}
        """)
        self.assertIn("not supported yet", _messages(result))
        self.assertIsNone(result.prefix_size)

    def test_the_sized_field_must_be_last(self) -> None:
        result = _check("""
            name: t
            version: "1"
            input: stream
            over: tcp
            entry: m
            units:
              m:
                fields:
                  - {name: length, type: {int: {bits: 16}}, derive: {size_of: body}}
                  - {name: body, type: {bytes: {size: {expr: "length"}}}}
                  - {name: trailer, type: {int: {bits: 8}}}
        """)
        self.assertIn("not the last field", _messages(result))

    def test_a_variable_field_before_the_length_names_itself(self) -> None:
        result = _check("""
            name: t
            version: "1"
            input: stream
            over: tcp
            entry: m
            units:
              m:
                fields:
                  - {name: head, type: {bytes: {size: {remaining: true}}}}
                  - {name: length, type: {int: {bits: 16}}, derive: {size_of: body}}
                  - {name: body, type: {bytes: {size: {expr: "length"}}}}
        """)
        self.assertIn("'head' has no fixed width", _messages(result))

    def test_a_fixed_header_before_the_length_is_counted(self) -> None:
        result = _check("""
            name: t
            version: "1"
            input: stream
            over: tcp
            entry: m
            units:
              m:
                fields:
                  - {name: magic, type: {int: {bits: 16}}, const: 0x5345}
                  - {name: length, type: {int: {bits: 32}}, derive: {size_of: body}}
                  - {name: body, type: {bytes: {size: {expr: "length"}}}}
        """)
        self.assertEqual(result.errors, ())
        self.assertEqual(result.prefix_size, 6)


class TestUnsupportedConstructsAreReportedAsSuch(unittest.TestCase):
    """A kober spec should say "not supported yet", never "unknown key"."""

    def test_a_pointer_is_named(self) -> None:
        result = _unit("""
            - {name: offset, type: {int: {bits: 8}}}
            - {name: target, type: {pointer: {at: "offset", type: {int: {bits: 8}}}}}
        """)
        joined = _messages(result)
        self.assertIn("not supported yet", joined)
        self.assertIn("pointer", joined)

    def test_delimiter_framing_is_named(self) -> None:
        result = _unit("""
            - {name: line, type: {string: {size: {terminated: {delimiter: "\\r\\n"}}}}}
        """)
        self.assertIn("not supported yet", _messages(result))


if __name__ == "__main__":
    unittest.main()
