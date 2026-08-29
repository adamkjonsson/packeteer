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
    IntLiteral,
    Ref,
    StrLiteral,
    parse,
    references,
    type_of,
    unparse,
)
from packeteer.protospec.spec import Location

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
            "xs[0]": "indexing",
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
