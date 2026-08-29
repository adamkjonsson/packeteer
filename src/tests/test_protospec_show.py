"""Printing the field tree a spec describes (#108)."""
from __future__ import annotations

import textwrap
import unittest

from packeteer.protospec import load, loads, render

_EXAMPLE = "examples/protocols/sensor.yaml"


def _render(body: str, **kwargs: bool) -> str:
    return render(loads(textwrap.dedent(body), fmt="yaml"), **kwargs)


class TestTheExampleSpec(unittest.TestCase):
    """The tree in the plan, rendered from the spec the tests load."""

    def setUp(self) -> None:
        self.out = render(load(_EXAMPLE))

    def test_the_header_says_when_the_protocol_is_used(self) -> None:
        self.assertEqual(
            self.out.splitlines()[0],
            "sensor 1.0 — input: datagram, over: udp, ports: 9000, entry: reading",
        )

    def test_enums_are_listed_with_their_labels(self) -> None:
        self.assertIn("enum kind: 0=temperature, 1=humidity, 2=pressure", self.out)

    def test_the_tree(self) -> None:
        self.assertIn("├── magic: u16 = 0x5345", self.out)
        self.assertIn("├── count: u8  (derived: count_of samples)", self.out)
        self.assertIn("└── samples: → sample  ×count", self.out)

    def test_nested_units_are_expanded_in_place(self) -> None:
        self.assertIn("    ├── kind: u8 enum kind", self.out)
        self.assertIn("    ├── length: u8  (derived: size_of value)", self.out)

    def test_qualifiers_appear(self) -> None:
        self.assertIn("value: bytes[length]  [sensitive]", self.out)
        self.assertIn("reading: i32 le", self.out)

    def test_docs_can_be_left_out(self) -> None:
        self.assertIn("One datagram", self.out)
        self.assertNotIn("One datagram", render(load(_EXAMPLE), docs=False))


class TestTypeText(unittest.TestCase):

    def _line(self, field: str, extra: str = "") -> str:
        out = _render(f"""
            name: t
            version: "1"
            entry: m
            {extra}
            units:
              m:
                fields:
                  - {field}
        """)
        return out.splitlines()[-1]

    def test_integers(self) -> None:
        self.assertIn("u8", self._line("{name: a, type: {int: {bits: 8}}}"))
        self.assertIn("i32", self._line(
            "{name: a, type: {int: {bits: 32, signed: true}}}"))
        self.assertIn("u16 le", self._line(
            "{name: a, type: {int: {bits: 16, endian: little}}}"))

    def test_a_one_byte_little_endian_int_says_nothing_about_order(self) -> None:
        """Byte order is meaningless for one byte, so it is not printed."""
        self.assertNotIn("le", self._line(
            "{name: a, type: {int: {bits: 8, endian: little}}}"))

    def test_sizes(self) -> None:
        self.assertIn("bytes[4]", self._line("{name: a, type: {bytes: {size: 4}}}"))
        self.assertIn("bytes[rest]", self._line(
            "{name: a, type: {bytes: {size: {remaining: true}}}}"))

    def test_an_expression_size_is_shown_as_written(self) -> None:
        self.assertIn("bytes[n * 2]", self._line(
            '{name: a, type: {bytes: {size: {expr: "n * 2"}}}}'))

    def test_an_undefined_enum_is_marked(self) -> None:
        self.assertIn("enum ghost (undefined)", self._line(
            "{name: a, type: {int: {bits: 8, enum: ghost}}}"))

    def test_an_anonymous_field(self) -> None:
        self.assertIn("(anonymous)", self._line(
            "{name: null, type: {int: {bits: 3}}}"))


class TestSwitches(unittest.TestCase):

    _SPEC = """
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
                    on: "kind >> 6"
                    cases:
                      0: {int: {bits: 8}}
                      3: {bytes: {size: 2}}
                    default: {bytes: {size: {remaining: true}}}
    """

    def test_the_selector_is_shown_as_written(self) -> None:
        self.assertIn("switch on kind >> 6", _render(self._SPEC))

    def test_each_case_is_a_child(self) -> None:
        out = _render(self._SPEC)
        self.assertIn("case 0: u8", out)
        self.assertIn("case 3: bytes[2]", out)
        self.assertIn("default: bytes[rest]", out)


class TestItWorksOnASpecThatDoesNotCheck(unittest.TestCase):
    """When a spec is wrong is exactly when a reader wants to see it."""

    def test_an_undefined_unit_is_marked_not_raised(self) -> None:
        out = _render("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: a, type: {unit: ghost}}
        """)
        self.assertIn("→ ghost (undefined)", out)

    def test_a_missing_entry_unit_is_marked(self) -> None:
        out = _render("""
            name: t
            version: "1"
            entry: nowhere
            units:
              m:
                fields:
                  - {name: a, type: {int: {bits: 8}}}
        """)
        self.assertIn("nowhere (undefined)", out)

    def test_a_recursive_unit_is_marked_rather_than_expanded_forever(self) -> None:
        out = _render("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: a, type: {int: {bits: 8}}}
                  - {name: nested, type: {unit: m}}
        """)
        self.assertIn("(recursive)", out)

    def test_an_unparseable_expression_falls_back_to_its_source(self) -> None:
        out = _render("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: a, type: {bytes: {size: {expr: "1 +"}}}}
        """)
        self.assertIn("bytes[1 +]", out)


class TestUnsupportedConstructsAreMarked(unittest.TestCase):
    """The loader stands something in for them, so the tree must say so.

    Without this, a `pointer` field would print as `bytes[rest]` and the tree
    would quietly misreport what the author wrote.
    """

    def test_a_pointer_says_so(self) -> None:
        out = _render("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: at, type: {int: {bits: 8}}}
                  - {name: target, type: {pointer: {at: "at", type: {int: {bits: 8}}}}}
        """)
        self.assertIn("(not supported yet: pointer)", out)

    def test_delimiter_framing_says_so(self) -> None:
        out = _render("""
            name: t
            version: "1"
            entry: m
            units:
              m:
                fields:
                  - {name: line, type: {string: {size: {terminated: {delimiter: "\\r\\n"}}}}}
        """)
        self.assertIn("not supported yet", out)


class TestKoberSpecsRender(unittest.TestCase):
    """The real test of legibility: something nobody wrote for this renderer."""

    def test_dns_renders_every_construct_it_uses(self) -> None:
        out = render(load("/Users/adam/projs/zipline-kober/examples/dns.yaml"))
        for expected in ("enum opcode:", "├── id: u16", "(anonymous): u3",
                         "→ question", "switch on length >> 6", "case 0:"):
            with self.subTest(expected=expected):
                self.assertIn(expected, out)

    def test_long_docs_are_wrapped(self) -> None:
        out = render(load("/Users/adam/projs/zipline-kober/examples/http.yaml"))
        self.assertTrue(all(len(line) <= 100 for line in out.splitlines()))


if __name__ == "__main__":
    unittest.main()
