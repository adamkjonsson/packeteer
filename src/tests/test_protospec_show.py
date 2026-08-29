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


class TestEverythingAtOnce(unittest.TestCase):
    """Every construct the renderer handles, in one spec.

    Shaped after kober's own `dns.yaml`, written inline rather than loaded
    from a kober checkout: a test that reads a file outside this repository
    passes on the machine that has it and fails everywhere else.
    """

    _SPEC = """
        name: dnslike
        version: "1.0"
        entry: message
        enums:
          opcode: {0: query, 1: iquery, 2: status}
        units:
          message:
            fields:
              - {name: id, type: {int: {bits: 16}}}
              - {name: flags, type: {unit: flags}}
              - {name: qdcount, type: {int: {bits: 16}}}
              - {name: questions, type: {unit: question}, repeat: {count: "qdcount"}}
          flags:
            fields:
              - {name: qr, type: {int: {bits: 1}}}
              - {name: opcode, type: {int: {bits: 4, enum: opcode}}}
              - {name: null, type: {int: {bits: 3}}}
          question:
            fields:
              - {name: length, type: {int: {bits: 8}}}
              - name: rest
                type:
                  switch:
                    on: "length >> 6"
                    cases:
                      0: {string: {size: {expr: "length"}}}
                      3: {bytes: {size: 2}}
    """

    def test_every_construct_renders(self) -> None:
        out = _render(self._SPEC)
        for expected in ("enum opcode:", "├── id: u16", "(anonymous): u3",
                         "→ question", "×qdcount", "switch on length >> 6",
                         "case 0: string[length]", "case 3: bytes[2]"):
            with self.subTest(expected=expected):
                self.assertIn(expected, out)

    def test_a_nested_unit_is_expanded_under_its_field(self) -> None:
        out = _render(self._SPEC)
        self.assertIn("├── flags: → flags", out)
        self.assertIn("│   ├── qr: u1", out)


class TestLongDocsAreWrapped(unittest.TestCase):
    """An unwrapped paragraph destroys the tree, and real specs have them."""

    _SPEC = """
        name: wordy
        version: "1.0"
        entry: m
        units:
          m:
            doc: >
              One request or response. Framing is decided here, from the
              headers, and the two body fields are mutually exclusive by
              construction: a message reads at most one of them, and a message
              with neither framing header reads no body at all.
            fields:
              - name: a
                type: {int: {bits: 8}}
                doc: >
                  Header lines up to and including the blank line that ends
                  them. The blank line is kept as the last element rather than
                  dropped: it is input, and every byte has to be accounted for.
    """

    def test_no_line_runs_long(self) -> None:
        for line in _render(self._SPEC).splitlines():
            with self.subTest(line=line[:40]):
                self.assertLessEqual(len(line), 100)

    def test_the_text_survives_the_wrapping(self) -> None:
        out = _render(self._SPEC).replace("\n", " ")
        self.assertIn("every byte has to be accounted for", " ".join(out.split()))

    def test_docs_can_still_be_omitted(self) -> None:
        self.assertNotIn("Framing is decided here", _render(self._SPEC, docs=False))


class TestTestsStayInsideTheRepository(unittest.TestCase):
    """A test that reads a path outside this checkout passes only here.

    This is a real failure, not a hypothetical: two tests in this file loaded
    kober's example specs from a sibling directory, which passed locally and
    failed in CI on the first run.
    """

    def test_no_test_module_names_an_absolute_path(self) -> None:
        import pathlib as _pathlib

        # Built rather than written out, so this test does not match itself.
        markers = [quote + "/" + root + "/"
                   for quote in ('"', "'")
                   for root in ("Users", "home", "root")]

        here = _pathlib.Path(__file__).resolve().parent
        for module in sorted(here.glob("test_*.py")):
            source = module.read_text(encoding="utf-8")
            found = [m for m in markers if m in source]
            with self.subTest(module=module.name):
                # Not assertNotIn: its failure message would print the whole
                # module.
                self.assertEqual(
                    found, [],
                    f"{module.name} reads a path outside the repository",
                )


if __name__ == "__main__":
    unittest.main()
