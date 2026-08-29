"""Compiling a spec to a Python module (#109)."""
from __future__ import annotations

import ast
import importlib.util
import sys
import tempfile
import textwrap
import unittest
import uuid
from pathlib import Path
from types import ModuleType

from packeteer import protocols
from packeteer.protospec import SpecError, check, compile_spec, load, loads

_EXAMPLE = "examples/protocols/sensor.yaml"


def _source(body: str) -> str:
    """Compile a spec written inline and return the generated source."""
    return compile_spec(loads(textwrap.dedent(body), fmt="yaml"),
                        source="t.yaml", generator="packeteer test")


class _Compiled:
    """A generated module, imported and cleaned up afterwards."""

    def __init__(self, code: str) -> None:
        self.dir = tempfile.TemporaryDirectory()
        name = f"_gen_{uuid.uuid4().hex}"
        path = Path(self.dir.name) / f"{name}.py"
        path.write_text(code, encoding="utf-8")
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        self.module: ModuleType = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.module
        self.name = name
        spec.loader.exec_module(self.module)

    def close(self) -> None:
        registered = getattr(self.module, "PROTOCOL", None)
        if registered is not None and protocols.for_section(registered.name):
            protocols.unregister(registered.name)
        sys.modules.pop(self.name, None)
        self.dir.cleanup()


class _CompileTestCase(unittest.TestCase):
    """Compiles a spec, imports it, and unregisters it afterwards."""

    def compile(self, body: str) -> ModuleType:
        compiled = _Compiled(_source(body))
        self.addCleanup(compiled.close)
        return compiled.module

    def compile_file(self, path: str) -> ModuleType:
        compiled = _Compiled(compile_spec(load(path), source=path,
                                          generator="packeteer test"))
        self.addCleanup(compiled.close)
        return compiled.module


class TestTheExampleSpecCompiles(_CompileTestCase):

    def setUp(self) -> None:
        self.mod = self.compile_file(_EXAMPLE)
        self.msg = self.mod.Reading(magic=0x5345, version=1, count=2, samples=[
            self.mod.Sample(kind=0, length=4, value=b"21.5", reading=-3),
            self.mod.Sample(kind=1, length=2, value=b"48", reading=7),
        ])

    def test_decode_encode_round_trip(self) -> None:
        self.assertEqual(self.mod.decode(self.mod.encode(self.msg)), self.msg)

    def test_encode_decode_round_trip(self) -> None:
        """The direction that catches the bugs: bytes in, identical bytes out."""
        raw = self.mod.encode(self.msg)
        self.assertEqual(self.mod.encode(self.mod.decode(raw)), raw)

    def test_to_spec_from_spec_round_trip(self) -> None:
        self.assertEqual(self.mod.from_spec(self.mod.to_spec(self.msg)), self.msg)

    def test_bytes_reach_the_spec_as_hex(self) -> None:
        section = self.mod.to_spec(self.msg)
        self.assertEqual(section["samples"][0]["value"], b"21.5".hex())

    def test_it_registers_itself(self) -> None:
        proto = protocols.for_section("sensor")
        self.assertIsNotNone(proto)
        self.assertEqual(proto.over, "udp")
        self.assertEqual(proto.ports, frozenset({9000}))

    def test_truncated_input_raises_rather_than_half_building(self) -> None:
        raw = self.mod.encode(self.msg)
        for cut in range(1, len(raw)):
            with (self.subTest(bytes_kept=cut),
                  self.assertRaises(ValueError)):
                self.mod.decode(raw[:cut])


class TestItWorksThroughPacketeer(_CompileTestCase):
    """The point of compiling: everything v0.10.0 shipped works on it."""

    def setUp(self) -> None:
        self.mod = self.compile_file(_EXAMPLE)
        self.msg = self.mod.Reading(magic=0x5345, version=1, count=1, samples=[
            self.mod.Sample(kind=2, length=3, value=b"1013", reading=1),
        ])
        self.msg.samples[0].value = b"101"

    def _frame(self) -> bytes:
        from packeteer.generate import PacketBuilder

        return (PacketBuilder()
                .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                .ip(src="10.0.0.1", dst="10.0.0.2").udp(dst_port=9000)
                .app(self.msg).build())

    def test_builder_and_parser(self) -> None:
        from packeteer.parse import parse_packet

        pkt = parse_packet(self._frame())
        self.assertEqual(pkt.app_protocol, "sensor")
        self.assertEqual(pkt.app, self.msg)

    def test_parse_build_is_byte_identical(self) -> None:
        import packeteer.__main__ as cli
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet
        from packeteer.parse.core import _packet_to_spec

        original = self._frame()
        spec = _packet_to_spec(parse_packet(original))
        spec["ethernet"] = {"src_mac": "00:00:00:00:00:01",
                            "dst_mac": "00:00:00:00:00:02"}
        rebuilt, _ = cli._apply_spec_to_builder(PacketBuilder(), spec, 1)
        self.assertEqual(rebuilt.build(), original)


class TestGeneratedCodeIsSafe(_CompileTestCase):
    """Author text reaches Python source here, so this is where it must hold."""

    def test_a_generated_module_imports_only_packeteer_and_the_stdlib(self) -> None:
        tree = ast.parse(compile_spec(load(_EXAMPLE)))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        for name in imported:
            with self.subTest(module=name):
                root = name.split(".")[0]
                self.assertIn(root, {"packeteer", "dataclasses", "typing",
                                     "__future__"})

    def test_a_doc_string_cannot_escape_its_docstring(self) -> None:
        code = _source('''
            name: t
            version: "1"
            entry: m
            doc: 'ends the docstring """ and then some'
            units:
              m:
                fields:
                  - {name: a, type: {int: {bits: 8}}}
        ''')
        ast.parse(code)              # would raise if the escape leaked
        self.assertNotIn('""" and then some', code)

    def test_a_field_name_that_is_not_an_identifier_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _source("""
                name: t
                version: "1"
                entry: m
                units:
                  m:
                    fields:
                      - {name: "not a name", type: {int: {bits: 8}}}
            """)
        self.assertIn("identifier", str(ctx.exception))

    def test_a_unit_name_colliding_with_a_generated_name_is_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _source("""
                name: t
                version: "1"
                entry: Reader
                units:
                  Reader:
                    fields:
                      - {name: a, type: {int: {bits: 8}}}
            """)
        self.assertIn("Reader", str(ctx.exception))

    def test_two_units_compiling_to_one_class_are_refused(self) -> None:
        with self.assertRaises(SpecError) as ctx:
            _source("""
                name: t
                version: "1"
                entry: my_unit
                units:
                  my_unit:
                    fields:
                      - {name: a, type: {int: {bits: 8}}}
                  My_unit:
                    fields:
                      - {name: b, type: {int: {bits: 8}}}
            """)
        self.assertIn("compile to", str(ctx.exception))

    def test_a_keyword_field_gets_one_trailing_underscore(self) -> None:
        """The only change ever made to a name, and it is visible in the source."""
        mod = self.compile("""
            name: t
            version: "1"
            entry: m
            over: udp
            ports: [9100]
            units:
              m:
                fields:
                  - {name: class, type: {int: {bits: 8}}}
        """)
        obj = mod.M(class_=7)
        self.assertEqual(mod.encode(obj), b"\x07")
        self.assertEqual(mod.to_spec(obj), {"class": 7})


class TestFieldKinds(_CompileTestCase):

    def _round_trip(self, fields: str, obj_kwargs: dict, raw: bytes) -> None:
        mod = self.compile(f"""
            name: t
            version: "1"
            entry: m
            over: udp
            ports: [9101]
            units:
              m:
                fields:
{textwrap.indent(textwrap.dedent(fields), " " * 18)}
        """)
        obj = mod.M(**obj_kwargs)
        self.assertEqual(mod.encode(obj), raw)
        self.assertEqual(mod.decode(raw), obj)

    def test_sub_byte_fields_pack_into_bytes(self) -> None:
        self._round_trip(
            """
            - {name: qr, type: {int: {bits: 1}}}
            - {name: opcode, type: {int: {bits: 4}}}
            - {name: rest, type: {int: {bits: 3}}}
            """,
            {"qr": 1, "opcode": 2, "rest": 5},
            bytes([0b1_0010_101]),
        )

    def test_little_endian_and_signed(self) -> None:
        self._round_trip(
            """
            - {name: v, type: {int: {bits: 32, signed: true, endian: little}}}
            """,
            {"v": -2},
            b"\xfe\xff\xff\xff",
        )

    def test_a_fixed_size_bytes_field(self) -> None:
        self._round_trip(
            """
            - {name: v, type: {bytes: {size: 3}}}
            """,
            {"v": b"abc"}, b"abc",
        )

    def test_a_string_field_uses_its_encoding(self) -> None:
        self._round_trip(
            """
            - {name: v, type: {string: {size: 2, encoding: ascii}}}
            """,
            {"v": "hi"}, b"hi",
        )

    def test_a_remaining_bytes_field(self) -> None:
        self._round_trip(
            """
            - {name: v, type: {bytes: {size: {remaining: true}}}}
            """,
            {"v": b"whatever"}, b"whatever",
        )

    def test_an_anonymous_field_is_written_as_zero(self) -> None:
        mod = self.compile("""
            name: t
            version: "1"
            entry: m
            over: udp
            ports: [9102]
            units:
              m:
                fields:
                  - {name: a, type: {int: {bits: 4}}}
                  - {name: null, type: {int: {bits: 4}}}
        """)
        self.assertEqual(mod.encode(mod.M(a=5)), b"\x50")
        self.assertFalse(hasattr(mod.M(), "None"))


class TestSwitches(_CompileTestCase):

    _SPEC = """
        name: t
        version: "1"
        entry: m
        over: udp
        ports: [9103]
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

    def test_each_arm_round_trips(self) -> None:
        mod = self.compile(self._SPEC)
        for kind, rest, raw in ((1, 9, b"\x01\x09"), (2, b"ab", b"\x02ab"),
                                (7, b"xyz", b"\x07xyz")):
            with self.subTest(kind=kind):
                obj = mod.M(kind=kind, rest=rest)
                self.assertEqual(mod.encode(obj), raw)
                self.assertEqual(mod.decode(raw), obj)

    def test_bytes_in_a_switch_arm_still_reach_the_spec_as_hex(self) -> None:
        mod = self.compile(self._SPEC)
        self.assertEqual(mod.to_spec(mod.M(kind=2, rest=b"ab"))["rest"],
                         b"ab".hex())

    def test_no_default_makes_an_unmatched_value_undecodable(self) -> None:
        mod = self.compile(self._SPEC.replace(
            "                    default: {bytes: {size: {remaining: true}}}\n", ""))
        with self.assertRaises(ValueError) as ctx:
            mod.decode(b"\x09zz")
        self.assertIn("no case", str(ctx.exception))


class TestCompiledSpecsAreChecked(unittest.TestCase):
    """The compiler assumes a coherent spec; the CLI is what guarantees it."""

    def test_the_example_spec_checks_clean_before_it_compiles(self) -> None:
        self.assertTrue(check(load(_EXAMPLE)).ok(strict=True))


if __name__ == "__main__":
    unittest.main()
