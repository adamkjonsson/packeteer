"""The expression language for sizes, counts and switch selectors (#106)."""
from __future__ import annotations

import unittest

from packeteer.protospec.errors import SpecError
from packeteer.protospec.expr import (
    MAX_SHIFT,
    BinOp,
    BoolLiteral,
    BytesLiteral,
    Compare,
    ExprType,
    Index,
    IntLiteral,
    Ref,
    StrLiteral,
    indexes,
    parse,
    references,
    type_of,
    unparse,
)
from packeteer.protospec.spec import Location, MapType

_LOC = Location(path="units.m.fields[0]", source="test.yaml")


def _parse(source: str) -> object:
    return parse(source, _LOC)


def _typed(source: str, **types: str) -> ExprType:
    """Type *source*, with each named reference given a type."""
    table = {name: ExprType(value) for name, value in types.items()}

    def resolve(ref: Ref) -> ExprType:
        try:
            return table[".".join(ref.path)]
        except KeyError:
            raise SpecError(f"unknown field {'.'.join(ref.path)!r}", _LOC) from None

    return type_of(_parse(source), resolve, _LOC)


class TestKoberExpressionsParse(unittest.TestCase):
    """Every expression in kober's own dns and http specs, verbatim.

    Inline rather than vendored: what is asserted is that these *constructs*
    parse, and a copied file would drift.  The four that use functions are
    below, since this version has no function table.
    """

    _CORPUS = [
        "qdcount",
        "ancount",
        "rdlength",
        "length",
        "length >> 6",
        "labels.length == 0 or labels.length >= 192",
        "headers.name == '' and headers.value == ''",
        "chunks.length == 0",
        "content_length",
        "not chunked and content_length > 0",
        "fields.name == '' and fields.value == ''",
        "length > 0",
    ]

    def test_all_parse(self) -> None:
        for source in self._CORPUS:
            with self.subTest(expr=source):
                self.assertIsNotNone(_parse(source))

    def test_all_round_trip_through_unparse(self) -> None:
        """What `show` prints must be what the author wrote."""
        for source in self._CORPUS:
            with self.subTest(expr=source):
                self.assertEqual(unparse(_parse(source)), source)


class TestLiterals(unittest.TestCase):

    def test_integers_in_every_base(self) -> None:
        for source, value in (("42", 42), ("0x2a", 42), ("0b101010", 42)):
            with self.subTest(expr=source):
                self.assertEqual(_parse(source), IntLiteral(value=value))

    def test_text_and_bytes_and_bools(self) -> None:
        self.assertEqual(_parse("'chunked'"), StrLiteral(value="chunked"))
        self.assertEqual(_parse("b'\\r\\n'"), BytesLiteral(value=b"\r\n"))
        self.assertEqual(_parse("true"), BoolLiteral(value=True))
        self.assertEqual(_parse("false"), BoolLiteral(value=False))

    def test_a_float_is_refused_rather_than_truncated(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _parse("1.5")
        self.assertIn("floating-point", str(ctx.exception))

    def test_none_is_not_a_value(self) -> None:
        with self.assertRaises(SpecError):
            _parse("None")

    def test_an_empty_expression_is_refused(self) -> None:
        for source in ("", "   "):
            with self.subTest(expr=source):
                with self.assertRaises(SpecError) as ctx:
                    _parse(source)
                self.assertIn("empty", str(ctx.exception))


class TestReferences(unittest.TestCase):
    """A bare name means `this`; `parent` and `root` reach outward."""

    def test_a_bare_name_is_this(self) -> None:
        self.assertEqual(_parse("length"), Ref(scope="this", path=("length",)))

    def test_a_dotted_path_descends(self) -> None:
        self.assertEqual(_parse("header.length"),
                         Ref(scope="this", path=("header", "length")))

    def test_scope_words(self) -> None:
        self.assertEqual(_parse("parent.n"), Ref(scope="parent", path=("n",)))
        self.assertEqual(_parse("root.id"), Ref(scope="root", path=("id",)))
        self.assertEqual(_parse("this.n"), Ref(scope="this", path=("n",)))

    def test_a_scope_word_alone_is_not_a_reference(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _parse("parent")
        self.assertIn("parent", str(ctx.exception))

    def test_references_yields_them_in_source_order(self) -> None:
        found = [".".join(r.path) for r in references(_parse("a + b * c"))]
        self.assertEqual(found, ["a", "b", "c"])

    def test_references_of_a_literal_is_empty(self) -> None:
        self.assertEqual(list(references(_parse("42"))), [])


class TestRefusedConstructs(unittest.TestCase):
    """Refused by name, not by leaking an AST class at a spec author."""

    def test_each_construct_is_named(self) -> None:
        cases = {
            "f(x)": "call",
            "xs[1:2]": "a slice",
            "[1, 2]": "a list",
            "(1, 2)": "a tuple",
            "{1: 2}": "a dict",
            "lambda: 1": "a lambda",
            "1 if x else 2": "a conditional expression",
            "[y for y in xs]": "a comprehension",
            "f'{x}'": "an f-string",
            "2 ** 8": "'**'",
            "x in xs": "'in'",
            "x is None": "'is'",
        }
        for source, expected in cases.items():
            with self.subTest(expr=source):
                with self.assertRaises(SpecError) as ctx:
                    _parse(source)
                self.assertIn(expected, str(ctx.exception))

    def test_a_call_is_not_supported_yet_rather_than_invalid(self) -> None:
        """A spec written for kober may use one of its three functions."""
        for source, name in (("to_int(v)", "to_int"), ("trim(v)", "trim"),
                             ("lower(v)", "lower")):
            with self.subTest(expr=source):
                with self.assertRaises(SpecError) as ctx:
                    _parse(source)
                message = str(ctx.exception)
                self.assertIn("not supported yet", message)
                self.assertIn(name, message)

    def test_a_chained_comparison_says_how_to_write_it(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _parse("0 < n < 10")
        self.assertIn("and", str(ctx.exception))

    def test_a_syntax_error_names_the_expression(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _parse("1 +")
        self.assertIn("1 +", str(ctx.exception))


class TestShiftGuard(unittest.TestCase):
    """A shift is the one operator that makes an arbitrarily large integer."""

    def test_a_shift_within_the_limit_is_fine(self) -> None:
        self.assertIsInstance(_parse(f"1 << {MAX_SHIFT}"), BinOp)

    def test_an_oversized_shift_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _parse(f"1 << {MAX_SHIFT + 1}")
        self.assertIn(str(MAX_SHIFT), str(ctx.exception))

    def test_a_negative_shift_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _parse("1 << -1")
        self.assertIn("negative", str(ctx.exception))


class TestTyping(unittest.TestCase):
    """Four types and no coercion."""

    def test_arithmetic_is_integer(self) -> None:
        self.assertEqual(_typed("a + b", a="int", b="int"), ExprType.INT)
        self.assertEqual(_typed("a >> 6", a="int"), ExprType.INT)

    def test_arithmetic_on_text_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _typed("a + b", a="str", b="str")
        self.assertIn("expected int", str(ctx.exception))

    def test_ordering_is_integer_only(self) -> None:
        self.assertEqual(_typed("a < b", a="int", b="int"), ExprType.BOOL)
        with self.assertRaises(SpecError):
            _typed("a < b", a="str", b="str")

    def test_equality_needs_the_same_type_on_both_sides(self) -> None:
        self.assertEqual(_typed("a == 'x'", a="str"), ExprType.BOOL)
        self.assertEqual(_typed("a == 1", a="int"), ExprType.BOOL)
        with self.assertRaises(SpecError) as ctx:
            _typed("a == 1", a="str")
        self.assertIn("no coercion", str(ctx.exception))

    def test_boolean_operators_need_booleans(self) -> None:
        self.assertEqual(_typed("a and b", a="bool", b="bool"), ExprType.BOOL)
        self.assertEqual(_typed("not a", a="bool"), ExprType.BOOL)

    def test_there_is_no_truthiness_and_the_error_says_so(self) -> None:
        """The mistake this language provokes most, since most languages allow it."""
        with self.assertRaises(SpecError) as ctx:
            _typed("qdcount and a", qdcount="int", a="bool")
        self.assertIn("!= 0", str(ctx.exception))

    def test_an_unresolved_reference_comes_from_the_resolver(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _typed("nope + 1")
        self.assertIn("nope", str(ctx.exception))

    def test_unknown_is_accepted_wherever_a_type_is_expected(self) -> None:
        """A declined field's type is not worked out, so it is not held against it (#167).

        The operator still decides the result: arithmetic is int, a comparison
        and ``not`` are bool, whatever the unknown operand turns out to be.
        """
        self.assertEqual(_typed("n + 1", n="unknown"), ExprType.INT)
        self.assertEqual(_typed("not n", n="unknown"), ExprType.BOOL)
        self.assertEqual(_typed("n > 0", n="unknown"), ExprType.BOOL)
        self.assertEqual(_typed("n == 'chunked'", n="unknown"), ExprType.BOOL)
        self.assertEqual(_typed("n", n="unknown"), ExprType.UNKNOWN)

    def test_unknown_does_not_excuse_the_other_operand(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _typed("n and k", n="unknown", k="int")
        self.assertIn("!= 0", str(ctx.exception))

    def test_a_real_kober_expression_types(self) -> None:
        self.assertEqual(
            _typed("not chunked and content_length > 0",
                   chunked="bool", content_length="int"),
            ExprType.BOOL,
        )


class TestUnparse(unittest.TestCase):
    """`show` prints these, so they have to read as what the author wrote."""

    def test_precedence_needs_no_parentheses(self) -> None:
        self.assertEqual(unparse(_parse("a + b * c")), "a + b * c")

    def test_parentheses_are_kept_where_they_matter(self) -> None:
        self.assertEqual(unparse(_parse("(a + b) * c")), "(a + b) * c")

    def test_booleans_print_as_yaml_spells_them(self) -> None:
        self.assertEqual(unparse(_parse("true")), "true")
        self.assertEqual(unparse(_parse("false")), "false")

    def test_scope_prefixes_survive(self) -> None:
        self.assertEqual(unparse(_parse("parent.header.length")),
                         "parent.header.length")
        self.assertEqual(unparse(_parse("this.n")), "n")

    def test_nested_boolean_operators(self) -> None:
        self.assertEqual(unparse(_parse("a or b and c")), "a or b and c")
        self.assertEqual(unparse(_parse("(a or b) and c")), "(a or b) and c")

    def test_a_comparison_of_two_operations(self) -> None:
        self.assertEqual(unparse(_parse("a * 4 == b + 1")), "a * 4 == b + 1")


class TestParsedShapes(unittest.TestCase):

    def test_binop(self) -> None:
        expr = _parse("length * 4")
        self.assertEqual(expr, BinOp(op="*", left=Ref("this", ("length",)),
                                     right=IntLiteral(4)))

    def test_compare(self) -> None:
        expr = _parse("qr == 0")
        self.assertEqual(expr, Compare(op="==", left=Ref("this", ("qr",)),
                                       right=IntLiteral(0)))

    def test_floor_division_and_div_are_the_same_operator(self) -> None:
        self.assertEqual(_parse("a / b"), _parse("a // b"))


if __name__ == "__main__":
    unittest.main()


class TestMapEntries(unittest.TestCase):
    """kober 0.6.0's one index, an entry of a map parameter (#208).

    Parsed and typed here; whether the name is a map parameter, and the
    decline, are the checker's.
    """

    _KEYS = MapType(key=ExprType.INT, item=ExprType.BYTES)

    def _typed(self, source: str, **types: str) -> ExprType:
        table = {name: ExprType(value) for name, value in types.items()}

        def resolve(ref: Ref) -> ExprType:
            return table[".".join(ref.path)]

        def resolve_map(name: str) -> MapType:
            if name != "keys":
                raise SpecError(f"{name!r} is not a map parameter", _LOC)
            return self._KEYS

        return type_of(_parse(source), resolve, _LOC, resolve_map)

    def test_it_parses_as_an_index(self) -> None:
        self.assertEqual(_parse("keys[receiver]"),
                         Index(table="keys", key=Ref(scope="this", path=("receiver",))))
        self.assertEqual(_parse("keys[hdr.rx + 1]").key,
                         BinOp(op="+", left=Ref(scope="this", path=("hdr", "rx")),
                               right=IntLiteral(value=1)))

    def test_what_kober_refuses_at_load_is_refused(self) -> None:
        cases = {
            "keys[1:2]": "a slice is not allowed",
            "keys[1, 2]": "an index is one expression, not several",
            "hdr.keys[0]": "only a map parameter can be indexed, by its name",
            "this[0]": "only a map parameter can be indexed, by its name",
            "true[0]": "only a map parameter can be indexed, by its name",
            "keys[0][1]": "only a map parameter can be indexed, by its name",
        }
        for source, expected in cases.items():
            with self.subTest(expr=source), self.assertRaises(SpecError) as ctx:
                _parse(source)
            self.assertIn(expected, str(ctx.exception))

    def test_it_has_the_maps_value_type(self) -> None:
        self.assertEqual(self._typed("keys[rx]", rx="int"), ExprType.BYTES)
        self.assertEqual(self._typed("keys[rx] == keys[tx]", rx="int", tx="int"),
                         ExprType.BOOL)

    def test_its_key_has_the_maps_key_type(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            self._typed("keys[name]", name="str")
        self.assertIn("the key of 'keys' is str, expected int", str(ctx.exception))

    def test_its_value_is_typed_where_it_is_used(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            self._typed("keys[rx] + 1", rx="int")
        self.assertIn("is bytes, expected int", str(ctx.exception))

    def test_a_name_that_is_not_a_map_is_refused_by_the_resolver(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            self._typed("kind[0]", kind="int")
        self.assertIn("'kind' is not a map parameter", str(ctx.exception))

    def test_with_no_maps_every_index_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _typed("kind[0]", kind="int")
        self.assertIn("only a map parameter can be indexed", str(ctx.exception))

    def test_its_key_is_a_reference_and_its_table_is_not(self) -> None:
        refs = list(references(_parse("keys[rx] == 1")))
        self.assertEqual(refs, [Ref(scope="this", path=("rx",))])

    def test_every_entry_is_found(self) -> None:
        found = [i.table for i in indexes(_parse("keys[a] == keys[ids[b]] or c"))]
        self.assertEqual(found, ["keys", "keys", "ids"])

    def test_it_unparses_as_written(self) -> None:
        for source in ("keys[receiver]", "keys[rx + 1] == x", "-keys[a]",
                       "keys[a or b]", "root.n + keys[parent.rx] * 2"):
            with self.subTest(expr=source):
                self.assertEqual(unparse(_parse(source)), source)
