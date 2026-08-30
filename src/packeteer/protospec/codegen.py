"""Turn a checked spec into a Python module implementing the protocol.

The output is an ordinary module: dataclasses for the messages, four functions
moving one between bytes, an object and a packet-spec section, and an
:class:`~packeteer.protocols.AppProtocol` registered at import.  Everything
v0.10.0 shipped then works on it — ``PacketBuilder.app``, ``pkt.app``, a
section in ``packeteer parse`` output, ``packeteer build`` reading it back.

**Author-supplied text reaches Python source here**, which is the one place
"a spec cannot run code" could be lost by carelessness.  Three rules, taken
from kober's ``pygen.py`` because the failure mode is severe:

1. **Names are validated, never silently renamed.**  A field that is not an
   identifier, or that collides with a name the generated module uses, is a
   :class:`~packeteer.protospec.errors.SpecError`.  A decoder whose field
   quietly changed name is worse than one that will not compile.
2. **Nothing is interpolated.**  Doc text and enum labels become escaped
   literals; no author string is ever concatenated into code.
3. **The output is parsed before it is returned**, so a bug in this module is
   a refusal rather than a broken file on someone's disk.

Bit-level work lives in :mod:`packeteer.protospec.runtime` rather than being
emitted inline, so a one-bit field and a thirty-two-bit field compile to the
same shape of call and the result stays readable.
"""
from __future__ import annotations

import ast
import keyword
import re
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from packeteer.protospec.errors import SpecError
from packeteer.protospec.expr import (
    BinOp,
    BoolLiteral,
    BoolOp,
    BytesLiteral,
    Expr,
    IntLiteral,
    Ref,
    StrLiteral,
    UnaryOp,
    parse,
)
from packeteer.protospec.spec import (
    BytesType,
    CountOf,
    Endian,
    Field,
    FieldType,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Location,
    Size,
    Spec,
    StringType,
    Switch,
    Unit,
    UnitRef,
)

__all__ = ["compile_spec"]

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Names the generated module uses itself.  A field or unit that wants one of
# these is refused rather than renamed around.
_RESERVED: frozenset[str] = frozenset({
    "AppProtocol", "Any", "Reader", "Writer", "PROTOCOL", "annotations",
    "dataclass", "decode", "encode", "field", "from_spec", "register",
    "to_spec", "frame_length",
})

_SCOPE_VARS: dict[str, str] = {"this": "_obj", "parent": "_parent", "root": "_root"}


@dataclass
class _Names:
    """The Python names a spec's units and fields compile to."""

    units: dict[str, str] = dataclass_field(default_factory=dict)
    fields: dict[tuple[str, str], str] = dataclass_field(default_factory=dict)

    def unit(self, name: str) -> str:
        """Return the class name for unit *name*."""
        return self.units[name]

    def field(self, unit: str, name: str) -> str:
        """Return the attribute name for *unit*'s field *name*."""
        return self.fields[(unit, name)]


def compile_spec(spec: Spec, *, source: str | None = None,
                 generator: str = "packeteer") -> str:
    """Return the Python source of a module implementing *spec*.

    Args:
        spec: The spec to compile.  It should have passed
            :func:`packeteer.protospec.check` first; this function assumes the
            spec is coherent and reports only faults specific to generating
            code, such as a field name that is not a Python identifier.
        source: The spec's file name, named in the generated header.
        generator: What to credit in the header, normally
            ``"packeteer X.Y.Z"``.

    Returns:
        Python source, already parsed *and imported* once to prove it is
        valid — see :meth:`_Generator._check_importable`.

    Raises:
        SpecError: If a name cannot be compiled, or if the generated source
            does not parse or import — which is a bug in this module rather
            than in the spec, and is reported as such.

    """
    if spec.input is InputShape.STREAM:
        raise SpecError(
            "not supported yet: 'input: stream' — a stream protocol's messages "
            "span packets, and packeteer decodes one packet at a time.  Its "
            "guarantee is that a capture rebuilds byte for byte, which a "
            "reassembled message cannot do, so reassembly is out of scope "
            "here; kober (https://github.com/adamkjonsson/zipline-kober) "
            "decodes stream-shaped protocols.  A spec whose messages each fit "
            "in one packet should say 'input: datagram'.",
            spec.loc.child("input"),
        )
    return _Generator(spec, source, generator).run()


@dataclass
class _Generator:
    """Emits one module."""

    spec: Spec
    source: str | None
    generator: str
    names: _Names = dataclass_field(default_factory=_Names)
    lines: list[str] = dataclass_field(default_factory=list)

    def run(self) -> str:
        """Emit the module and prove it parses."""
        self._assign_names()
        self._emit_header()
        self._emit_dataclasses()
        for unit in self.spec.units.values():
            self._emit_unit_decoder(unit)
            self._emit_unit_encoder(unit)
            self._emit_unit_measure(unit)
            self._emit_unit_to_spec(unit)
            self._emit_unit_from_spec(unit)
            self._emit_unit_sanitise(unit)
        self._emit_api()
        code = "\n".join(self.lines) + "\n"
        try:
            ast.parse(code)
        except SyntaxError as exc:      # pragma: no cover - a generator bug
            raise SpecError(
                f"generated source does not parse ({exc.msg} at line "
                f"{exc.lineno}); this is a bug in packeteer's compiler, not in "
                f"the spec",
                self.spec.loc,
            ) from exc
        self._check_importable(code)
        return code

    def _check_importable(self, code: str) -> None:
        """Prove the emitted module loads, not merely that it parses.

        #132 was a module that parsed and then raised ``NameError`` on
        import, which reached whoever ran it next rather than the compiler
        that wrote it.  Parsing cannot catch that: the module is
        syntactically fine.

        The module is executed in a throwaway namespace and the protocol it
        registers is removed again, so compiling never leaves one behind.
        Skipped when the name is already registered, since executing the
        module would collide with it — and undoing that collision would mean
        touching a protocol this function did not create.
        """
        from packeteer import protocols

        if any(p.name == self.spec.name for p in protocols.registered()):
            return
        namespace: dict[str, object] = {}
        try:
            exec(compile(code, f"<{self.spec.name}>", "exec"), namespace)  # noqa: S102
        except Exception as exc:        # pragma: no cover - a generator bug
            raise SpecError(
                f"generated module does not import ({type(exc).__name__}: "
                f"{exc}); this is a bug in packeteer's compiler, not in the "
                f"spec",
                self.spec.loc,
            ) from exc
        finally:
            if any(p.name == self.spec.name for p in protocols.registered()):
                protocols.unregister(self.spec.name)

    # ── names ─────────────────────────────────────────────────────────────────

    def _assign_names(self) -> None:
        """Work out every Python name, refusing any that cannot be made."""
        taken: dict[str, str] = {}
        for unit_name, unit in self.spec.units.items():
            cls = _class_name(unit_name, unit.loc)
            if cls in _RESERVED:
                raise SpecError(
                    f"unit {unit_name!r} compiles to {cls!r}, which the "
                    f"generated module uses itself", unit.loc,
                )
            if cls in taken:
                raise SpecError(
                    f"units {taken[cls]!r} and {unit_name!r} both compile to "
                    f"{cls!r}", unit.loc,
                )
            taken[cls] = unit_name
            self.names.units[unit_name] = cls

            seen: dict[str, str] = {}
            for fld in unit.fields:
                if fld.name is None:
                    continue
                attr = _attr_name(fld.name, fld.loc)
                if attr in seen:
                    raise SpecError(
                        f"fields {seen[attr]!r} and {fld.name!r} both compile "
                        f"to {attr!r}",
                        fld.loc,
                    )
                seen[attr] = fld.name
                self.names.fields[(unit_name, fld.name)] = attr

    # ── module ────────────────────────────────────────────────────────────────

    def _emit(self, line: str = "") -> None:
        self.lines.append(line)

    def _emit_header(self) -> None:
        origin = f" from {self.source}" if self.source else ""
        self._emit(f"# Generated by {self.generator}{origin} "
                   f"(spec {self.spec.name} {self.spec.version}).")
        self._emit("# Do not edit; edit the spec and recompile.")
        doc = self.spec.doc or f"The {self.spec.name} protocol."
        self._emit(_docstring(doc, indent=""))
        self._emit("from __future__ import annotations")
        self._emit()
        self._emit("from dataclasses import dataclass, field")
        self._emit("from typing import Any")
        self._emit()
        self._emit("from packeteer.protocols import AppProtocol, register")
        self._emit("from packeteer.protospec.runtime import Reader, Writer")
        self._emit()

    def _emit_dataclasses(self) -> None:
        for unit in self.spec.units.values():
            self._emit()
            self._emit("@dataclass")
            self._emit(f"class {self.names.unit(unit.name)}:")
            self._emit(_docstring(unit.doc or f"The {unit.name} unit.",
                                  indent="    "))
            emitted = False
            for fld in unit.fields:
                if fld.name is None:
                    continue
                attr = self.names.field(unit.name, fld.name)
                annotation = self._annotation(fld)
                self._emit(f"    {attr}: {annotation} = {self._default(fld)}")
                emitted = True
            if not emitted:
                self._emit("    pass")
            self._emit()

    def _annotation(self, fld: Field) -> str:
        """Return the type annotation for a field."""
        inner = self._type_annotation(fld.type)
        if fld.repeat is not None:
            return f"list[{inner}]"
        # A derived field is None when it is to be computed, which is what
        # lets a captured value that disagrees with the derivation survive.
        return f"{inner} | None" if fld.derive is not None else inner

    def _type_annotation(self, field_type: FieldType) -> str:
        if isinstance(field_type, IntType):
            return "int"
        if isinstance(field_type, BytesType):
            return "bytes"
        if isinstance(field_type, StringType):
            return "str"
        if isinstance(field_type, UnitRef):
            return self.names.unit(field_type.unit)
        return "Any"                     # a switch's arms differ

    def _default(self, fld: Field) -> str:
        """Return the default value expression for a field."""
        if fld.repeat is not None:
            return "field(default_factory=list)"
        if fld.derive is not None:
            return "None"
        if fld.const is not None:
            return repr(fld.const.value)
        if isinstance(fld.type, IntType):
            return "0"
        if isinstance(fld.type, BytesType):
            return 'b""'
        if isinstance(fld.type, StringType):
            return '""'
        if isinstance(fld.type, UnitRef):
            # A lambda, not the class itself: `default_factory` is evaluated
            # when the class body runs, and a unit may reference one defined
            # later in the spec — or reference it mutually (#132).
            cls = self.names.unit(fld.type.unit)
            return f"field(default_factory=lambda: {cls}())"
        return "None"

    # ── decoding ──────────────────────────────────────────────────────────────

    def _emit_unit_decoder(self, unit: Unit) -> None:
        cls = self.names.unit(unit.name)
        self._emit()
        self._emit(f"def _decode_{_snake(unit.name)}(_r: Reader, _root: Any = None, "
                   f"_parent: Any = None) -> {cls}:")
        self._emit(f'    """Decode one {unit.name} from *_r*."""')
        self._emit(f"    _obj = {cls}()")
        self._emit("    if _root is None:")
        self._emit("        _root = _obj")
        for fld in unit.fields:
            self._emit_field_decode(unit, fld, "    ")
        self._emit_derived_clears(unit, "    ")
        self._emit("    return _obj")
        self._emit()

    def _emit_field_decode(self, unit: Unit, fld: Field, pad: str) -> None:
        target = (f"_obj.{self.names.field(unit.name, fld.name)}"
                  if fld.name is not None else "_discard")
        if fld.repeat is not None:
            count = self._py(fld.repeat.expr, unit, fld.loc)
            self._emit(f"{pad}{target} = []")
            self._emit(f"{pad}for _ in range({count}):")
            self._emit_read(unit, fld, fld.type, f"{pad}    ", "_item")
            self._emit(f"{pad}    {target}.append(_item)")
            return
        self._emit_read(unit, fld, fld.type, pad, target)

    def _emit_derived_clears(self, unit: Unit, pad: str) -> None:
        """Clear every derived field whose captured value the spec would derive.

        Run once the whole unit is decoded, because a derivation may read
        fields that come after the field deriving from them — a length before
        its data being the ordinary case.

        A field cleared here is omitted from the packet spec, so a well-formed
        capture produces a spec with no redundant lengths and counts.  One that
        disagrees keeps the captured value, which is what makes a malformed
        capture rebuild byte-for-byte.
        """
        for fld in unit.fields:
            if fld.derive is None or fld.name is None:
                continue
            attr = f"_obj.{self.names.field(unit.name, fld.name)}"
            self._emit(f"{pad}if {attr} == {self._derived_value(unit, fld)}:")
            self._emit(f"{pad}    {attr} = None")

    def _derived_value(self, unit: Unit, fld: Field) -> str:
        """Return the expression computing what a derived field should hold."""
        target = next(f for f in unit.fields if f.name == fld.derive.field)
        value = f"_obj.{self.names.field(unit.name, target.name)}"
        if isinstance(fld.derive, CountOf):
            return f"len({value})"
        if isinstance(target.type, StringType):
            return f"len({value}.encode({target.type.encoding!r}))"
        if isinstance(target.type, UnitRef):
            return f"len(_bytes_of_{_snake(target.type.unit)}({value}))"
        return f"len({value})"

    def _emit_read(self, unit: Unit, fld: Field, field_type: FieldType,
                   pad: str, target: str) -> None:
        """Emit the statements that read one value into *target*."""
        if isinstance(field_type, IntType):
            args = [str(field_type.bits)]
            if field_type.signed:
                args.append("signed=True")
            if field_type.endian is Endian.LITTLE:
                args.append("little=True")
            self._emit(f"{pad}{target} = _r.read_int({', '.join(args)})")
            self._emit_const_check(fld, field_type, pad, target)
        elif isinstance(field_type, BytesType):
            self._emit(f"{pad}{target} = {self._read_bytes(unit, fld, field_type.size)}")
            self._emit_const_check(fld, field_type, pad, target)
        elif isinstance(field_type, StringType):
            read = self._read_bytes(unit, fld, field_type.size)
            self._emit(f"{pad}{target} = {read}.decode({field_type.encoding!r})")
            self._emit_const_check(fld, field_type, pad, target)
        elif isinstance(field_type, UnitRef):
            self._emit(f"{pad}{target} = _decode_{_snake(field_type.unit)}"
                       f"(_r, _root, _obj)")
        elif isinstance(field_type, Switch):
            self._emit_switch_decode(unit, fld, field_type, pad, target)

    def _emit_const_check(self, fld: Field, field_type: FieldType,
                          pad: str, target: str) -> None:
        """Emit the check that a constant field holds what the spec says.

        Raising on a mismatch is the point: a port claim is weak, so this is
        what makes someone else's traffic on the same port stay an opaque
        payload rather than become a wrong message.
        """
        if fld.const is None or not isinstance(field_type,
                                               (IntType, BytesType, StringType)):
            return
        expected = repr(fld.const.value)
        name = fld.name or "constant"
        self._emit(f"{pad}if {target} != {expected}:")
        self._emit(f'{pad}    raise ValueError(f"{name} is {{{target}!r}}, '
                   f'expected {{{expected}!r}}")')

    def _read_bytes(self, unit: Unit, fld: Field, size: Size) -> str:
        if isinstance(size, Fixed):
            return f"_r.read_bytes({size.length})"
        if isinstance(size, FromExpr):
            return f"_r.read_bytes({self._py(size.expr, unit, fld.loc)})"
        return "_r.read_rest()"

    def _emit_switch_decode(self, unit: Unit, fld: Field, switch: Switch,
                            pad: str, target: str) -> None:
        self._emit(f"{pad}_sel = {self._py(switch.on, unit, fld.loc)}")
        first = True
        for value, arm in sorted(switch.arms.items()):
            self._emit(f"{pad}{'if' if first else 'elif'} _sel == {value}:")
            self._emit_read(unit, fld, arm, pad + "    ", target)
            first = False
        self._emit(f"{pad}else:")
        if switch.default is not None:
            self._emit_read(unit, fld, switch.default, pad + "    ", target)
        else:
            # No default means the region is undecodable rather than guessed
            # at.  Raising is what leaves the bytes as an opaque payload.
            self._emit(f"{pad}    raise ValueError("
                       f'f"no case for {{_sel}} in {fld.name or "switch"}")')

    # ── encoding ──────────────────────────────────────────────────────────────

    def _emit_unit_encoder(self, unit: Unit) -> None:
        cls = self.names.unit(unit.name)
        self._emit()
        self._emit(f"def _encode_{_snake(unit.name)}(_obj: {cls}, _w: Writer, "
                   f"_root: Any = None, _parent: Any = None) -> None:")
        self._emit(f'    """Encode one {unit.name} into *_w*."""')
        self._emit("    if _root is None:")
        self._emit("        _root = _obj")
        for fld in unit.fields:
            self._emit_field_encode(unit, fld, "    ")
        self._emit()

    def _emit_field_encode(self, unit: Unit, fld: Field, pad: str) -> None:
        if fld.name is None:
            # An anonymous field is reserved bits; write them as zero.
            self._emit_write(unit, fld, fld.type, pad, "0")
            return
        value = f"_obj.{self.names.field(unit.name, fld.name)}"
        if fld.derive is not None:
            # None means derive it; anything else is an override, written
            # verbatim so a capture that disagreed with its own derivation
            # rebuilds byte-for-byte.
            value = (f"({value} if {value} is not None "
                     f"else {self._derived_value(unit, fld)})")
        if fld.repeat is not None:
            self._emit(f"{pad}for _item in {value}:")
            self._emit_write(unit, fld, fld.type, f"{pad}    ", "_item")
            return
        self._emit_write(unit, fld, fld.type, pad, value)

    def _emit_write(self, unit: Unit, fld: Field, field_type: FieldType,
                    pad: str, value: str) -> None:
        """Emit the statements that write one value."""
        if isinstance(field_type, IntType):
            args = [value, str(field_type.bits)]
            if field_type.signed:
                args.append("signed=True")
            if field_type.endian is Endian.LITTLE:
                args.append("little=True")
            self._emit(f"{pad}_w.write_int({', '.join(args)})")
        elif isinstance(field_type, BytesType):
            self._emit(f"{pad}_w.write_bytes({value})")
        elif isinstance(field_type, StringType):
            self._emit(f"{pad}_w.write_bytes({value}.encode("
                       f"{field_type.encoding!r}))")
        elif isinstance(field_type, UnitRef):
            self._emit(f"{pad}_encode_{_snake(field_type.unit)}"
                       f"({value}, _w, _root, _obj)")
        elif isinstance(field_type, Switch):
            self._emit_switch_encode(unit, fld, field_type, pad, value)

    def _emit_switch_encode(self, unit: Unit, fld: Field, switch: Switch,
                            pad: str, value: str) -> None:
        self._emit(f"{pad}_sel = {self._py(switch.on, unit, fld.loc)}")
        first = True
        for arm_value, arm in sorted(switch.arms.items()):
            self._emit(f"{pad}{'if' if first else 'elif'} _sel == {arm_value}:")
            self._emit_write(unit, fld, arm, pad + "    ", value)
            first = False
        self._emit(f"{pad}else:")
        if switch.default is not None:
            self._emit_write(unit, fld, switch.default, pad + "    ", value)
        else:
            self._emit(f"{pad}    raise ValueError("
                       f'f"no case for {{_sel}} in {fld.name or "switch"}")')

    # ── packet spec ───────────────────────────────────────────────────────────

    def _emit_unit_measure(self, unit: Unit) -> None:
        """Emit a helper returning a unit's encoded bytes, for ``size_of``."""
        cls = self.names.unit(unit.name)
        self._emit()
        self._emit(f"def _bytes_of_{_snake(unit.name)}(_obj: {cls}) -> bytes:")
        self._emit(f'    """Return one {unit.name} encoded, to measure it."""')
        self._emit("    _w = Writer()")
        self._emit(f"    _encode_{_snake(unit.name)}(_obj, _w)")
        self._emit("    return _w.getvalue()")
        self._emit()

    def _emit_unit_to_spec(self, unit: Unit) -> None:
        self._emit()
        self._emit(f"def _to_spec_{_snake(unit.name)}(_obj: Any) -> dict[str, Any]:")
        self._emit(f'    """Return the packet-spec section for one {unit.name}."""')
        self._emit("    _out: dict[str, Any] = {}")
        for fld in unit.fields:
            if fld.name is None:
                continue
            attr = self.names.field(unit.name, fld.name)
            key = fld.name
            value = f"_obj.{attr}"
            if isinstance(fld.type, Switch) and fld.repeat is None:
                self._emit_switch_convert(
                    unit, fld, fld.type, f"_out[{key!r}]", value,
                    self._spec_value,
                )
            elif fld.repeat is not None:
                item = self._spec_value(fld.type, "_item")
                self._emit(f"    _out[{key!r}] = [{item} for _item in {value}]")
            elif fld.derive is not None:
                # Present only when the capture disagreed with the derivation.
                self._emit(f"    if {value} is not None:")
                self._emit(f"        _out[{key!r}] = "
                           f"{self._spec_value(fld.type, value)}")
            else:
                self._emit(f"    _out[{key!r}] = {self._spec_value(fld.type, value)}")
        self._emit("    return _out")
        self._emit()

    def _sensitive_fields(self) -> set[str]:
        """Return every ``sensitive:`` field in the spec, as ``unit.field``."""
        return {
            f"{unit.name}.{fld.name}"
            for unit in self.spec.units.values()
            for fld in unit.fields
            if fld.name is not None and fld.sensitive
        }

    def _emit_unit_sanitise(self, unit: Unit) -> None:
        """Emit the redactor for one unit's section.

        It walks the same keys :meth:`_emit_unit_to_spec` writes, so the two
        cannot drift: a field redacted here is a field that reaches a spec.
        """
        self._emit()
        self._emit(f"def _sanitise_{_snake(unit.name)}"
                   f"(_section: dict[str, Any], _r: Any, _opts: Any) -> None:")
        self._emit(f'    """Redact one {unit.name} section in place."""')
        body = False
        for fld in unit.fields:
            if fld.name is None:
                continue
            key = fld.name
            if fld.sensitive:
                body = True
                self._emit(f"    if {key!r} in _section:")
                target = f"_section[{key!r}]"
                if fld.repeat is not None:
                    self._emit(f"        {target} = [{self._redact(fld.type, '_item')}"
                               f" for _item in {target}]")
                else:
                    self._emit(f"        {target} = {self._redact(fld.type, target)}")
            elif isinstance(fld.type, UnitRef):
                # Not annotated itself, but something inside it may be.
                body = True
                nested = f"_sanitise_{_snake(fld.type.unit)}"
                self._emit(f"    if {key!r} in _section:")
                if fld.repeat is not None:
                    self._emit(f"        for _item in _section[{key!r}]:")
                    self._emit(f"            {nested}(_item, _r, _opts)")
                else:
                    self._emit(f"        {nested}(_section[{key!r}], _r, _opts)")
        if not body:
            self._emit("    return")
        self._emit()

    def _redact(self, field_type: FieldType, value: str) -> str:
        """Return the redacted stand-in for one value of *field_type*."""
        if isinstance(field_type, StringType):
            return "'[redacted]'"
        if isinstance(field_type, BytesType):
            # Hex in a spec, and the length is often what a `size` field
            # derives from, so zero the bytes rather than dropping them.
            return f"('00' * (len({value}) // 2))"
        if isinstance(field_type, IntType):
            return "0"
        # A unit or a switch arm: the shape is only known at run time.
        return f"_redact_any({value})"

    def _emit_switch_convert(
        self, unit: Unit, fld: Field, switch: Switch, target: str,
        value: str, convert: "Callable[[FieldType, str], str]",
        pad: str = "    ",
    ) -> None:
        """Emit the selector dispatch a switch field needs outside decoding.

        ``to_spec`` and ``from_spec`` both have to know which arm a value
        belongs to, and the arm is chosen the same way the decoder chooses it:
        by the selector expression, whose fields are already set on ``_obj``
        because they precede the switch field.

        Without this a unit-typed arm went into a spec **as the dataclass**,
        so the section could not be written to JSON at all — `packeteer parse`
        produced something no file could hold.
        """
        self._emit(f"{pad}_sel = {self._py(switch.on, unit, fld.loc)}")
        first = True
        for case, arm in sorted(switch.arms.items()):
            self._emit(f"{pad}{'if' if first else 'elif'} _sel == {case}:")
            self._emit(f"{pad}    {target} = {convert(arm, value)}")
            first = False
        self._emit(f"{pad}else:")
        if switch.default is not None:
            self._emit(f"{pad}    {target} = {convert(switch.default, value)}")
        else:
            # No arm and no default: the decoder refuses to guess, and neither
            # does this — but the value is carried through unchanged rather
            # than dropped, so nothing is silently lost on the way out.
            self._emit(f"{pad}    {target} = {value}")
        self._emit()

    def _spec_value(self, field_type: FieldType, value: str) -> str:
        """Return the JSON-safe form of a value for a packet spec."""
        if isinstance(field_type, BytesType):
            return f"{value}.hex()"
        if isinstance(field_type, UnitRef):
            return f"_to_spec_{_snake(field_type.unit)}({value})"
        if isinstance(field_type, Switch):
            # An arm's type is not known statically, so the runtime type
            # decides — bytes become hex the same way they would anywhere else.
            return f"_spec_any({value})"
        return value

    def _emit_unit_from_spec(self, unit: Unit) -> None:
        cls = self.names.unit(unit.name)
        self._emit()
        self._emit(f"def _from_spec_{_snake(unit.name)}"
                   f"(_section: dict[str, Any]) -> {cls}:")
        self._emit(f'    """Build one {unit.name} from a packet-spec section."""')
        self._emit(f"    _obj = {cls}()")
        for fld in unit.fields:
            if fld.name is None:
                continue
            attr = self.names.field(unit.name, fld.name)
            key = fld.name
            if isinstance(fld.type, Switch) and fld.repeat is None:
                self._emit(f"    if {key!r} in _section:")
                self._emit_switch_convert(
                    unit, fld, fld.type, f"_obj.{attr}",
                    f"_section[{key!r}]", self._from_spec_value, pad="        ",
                )
            elif fld.repeat is not None:
                item = self._from_spec_value(fld.type, "_item")
                self._emit(f"    _obj.{attr} = [{item} for _item in "
                           f"_section.get({key!r}, [])]")
            else:
                self._emit(f"    if {key!r} in _section:")
                self._emit(f"        _obj.{attr} = "
                           f"{self._from_spec_value(fld.type, f'_section[{key!r}]')}")
        self._emit("    return _obj")
        self._emit()

    def _from_spec_value(self, field_type: FieldType, value: str) -> str:
        """Return the expression rebuilding a value from a packet spec."""
        if isinstance(field_type, BytesType):
            return f"bytes.fromhex({value})"
        if isinstance(field_type, UnitRef):
            return f"_from_spec_{_snake(field_type.unit)}({value})"
        if isinstance(field_type, Switch):
            return value
        return value

    # ── the module's public four ──────────────────────────────────────────────

    def _emit_api(self) -> None:
        entry = _snake(self.spec.entry)
        cls = self.names.unit(self.spec.entry)
        self._emit()
        self._emit("def _redact_any(_value: Any) -> Any:")
        self._emit('    """Blank every leaf of a value whose shape is only '
                   'known at run time."""')
        self._emit("    if isinstance(_value, str):")
        self._emit("        return '[redacted]'")
        self._emit("    if isinstance(_value, bool):")
        self._emit("        return False")
        self._emit("    if isinstance(_value, int):")
        self._emit("        return 0")
        self._emit("    if isinstance(_value, dict):")
        self._emit("        return {_k: _redact_any(_v) for _k, _v in _value.items()}")
        self._emit("    if isinstance(_value, list):")
        self._emit("        return [_redact_any(_v) for _v in _value]")
        self._emit("    return _value")
        self._emit()
        self._emit()
        self._emit("def _spec_any(_value: Any) -> Any:")
        self._emit('    """Return a switch arm\'s value in a JSON-safe form."""')
        self._emit("    if isinstance(_value, bytes):")
        self._emit("        return _value.hex()")
        self._emit("    return _value")
        self._emit()
        self._emit()
        self._emit(f"def decode(data: bytes, transport: str = "
                   f"{self.spec.over.value!r}) -> {cls}:")
        self._emit(f'    """Decode *data* into a {cls}."""')
        self._emit(f"    return _decode_{entry}(Reader(data))")
        self._emit()
        self._emit()
        self._emit(f"def encode(msg: Any, transport: str = "
                   f"{self.spec.over.value!r}) -> bytes:")
        self._emit(f'    """Encode a {cls} to bytes."""')
        self._emit("    _w = Writer()")
        self._emit(f"    _encode_{entry}(msg, _w)")
        self._emit("    return _w.getvalue()")
        self._emit()
        self._emit()
        self._emit("def to_spec(msg: Any) -> dict[str, Any]:")
        self._emit(f'    """Return the packet-spec section for a {cls}."""')
        self._emit(f"    return _to_spec_{entry}(msg)")
        self._emit()
        self._emit()
        self._emit(f"def from_spec(section: dict[str, Any]) -> {cls}:")
        self._emit(f'    """Build a {cls} from a packet-spec section."""')
        self._emit(f"    return _from_spec_{entry}(section)")
        self._emit()
        self._emit()
        self._emit("def sanitise(section: dict[str, Any], replacer: Any, "
                   "options: Any) -> None:")
        annotated = self._sensitive_fields()
        if annotated:
            listed = ", ".join(sorted(annotated))
            if len(listed) > 60:
                listed = f"{len(annotated)} fields marked sensitive"
            self._emit(f'    """Redact {listed}."""')
        else:
            self._emit('    """Redact nothing: the spec marks no field '
                       'sensitive."""')
        self._emit(f"    _sanitise_{entry}(section, replacer, options)")
        self._emit()
        self._emit()
        ports = ", ".join(str(p) for p in sorted(self.spec.ports))
        self._emit("PROTOCOL = AppProtocol(")
        self._emit(f"    name={self.spec.name!r},")
        self._emit(f"    over={self.spec.over.value!r},")
        self._emit(f"    ports=frozenset({{{ports}}}),")
        self._emit(f"    messages=({cls},),")
        self._emit("    decode=decode,")
        self._emit("    encode=encode,")
        self._emit("    to_spec=to_spec,")
        self._emit("    from_spec=from_spec,")
        self._emit("    sanitise=sanitise,")
        if not self._sensitive_fields():
            # Q4: a compiled protocol always has a sanitiser, so "nobody wrote
            # one" is not its failure mode — "nobody marked anything" is, and
            # silence is the one outcome that must not be available.
            self._emit("    redacts_nothing=True,")
        self._emit(")")
        self._emit()
        self._emit("register(PROTOCOL)")

    # ── expressions ───────────────────────────────────────────────────────────

    def _py(self, source: str, unit: Unit, loc: Location) -> str:
        """Compile one spec expression to a Python expression."""
        return self._render(parse(source, loc), unit, loc)

    def _render(self, expr: Expr, unit: Unit, loc: Location) -> str:
        """Render one expression node, fully parenthesised."""
        if isinstance(expr, IntLiteral):
            return str(expr.value)
        if isinstance(expr, BoolLiteral):
            return "True" if expr.value else "False"
        if isinstance(expr, (StrLiteral, BytesLiteral)):
            return repr(expr.value)
        if isinstance(expr, Ref):
            return self._render_ref(expr, unit, loc)
        if isinstance(expr, UnaryOp):
            op = "not " if expr.op == "not" else expr.op
            return f"({op}{self._render(expr.operand, unit, loc)})"
        if isinstance(expr, BoolOp):
            joined = f" {expr.op} ".join(
                self._render(o, unit, loc) for o in expr.operands)
            return f"({joined})"
        if isinstance(expr, BinOp):
            # `/` floors, because the language has no floating-point type.
            op = "//" if expr.op == "/" else expr.op
            return (f"({self._render(expr.left, unit, loc)} {op} "
                    f"{self._render(expr.right, unit, loc)})")
        return (f"({self._render(expr.left, unit, loc)} {expr.op} "
                f"{self._render(expr.right, unit, loc)})")

    def _render_ref(self, ref: Ref, unit: Unit, loc: Location) -> str:
        """Render a reference against the object it resolves from."""
        base = _SCOPE_VARS[ref.scope]
        current = unit if ref.scope == "this" else None
        parts = [base]
        for name in ref.path:
            if current is not None and (current.name, name) in self.names.fields:
                parts.append(self.names.field(current.name, name))
                nxt = next((f for f in current.fields if f.name == name), None)
                current = (self.spec.units.get(nxt.type.unit)
                           if nxt is not None and isinstance(nxt.type, UnitRef)
                           else None)
            else:
                parts.append(_attr_name(name, loc))
                current = None
        return ".".join(parts)


# ── names ─────────────────────────────────────────────────────────────────────

def _class_name(name: str, loc: Location) -> str:
    """Return the class name a unit compiles to."""
    _require_identifier(name, "a unit name", loc)
    return "".join(part[:1].upper() + part[1:] for part in name.split("_") if part)


def _attr_name(name: str, loc: Location) -> str:
    """Return the attribute name a field compiles to."""
    _require_identifier(name, "a field name", loc)
    # A Python keyword gets one trailing underscore, which is the only change
    # ever made to a name — and it is visible in the generated source.
    return f"{name}_" if keyword.iskeyword(name) else name


def _require_identifier(name: str, what: str, loc: Location) -> None:
    """Raise unless *name* can become a Python name unchanged."""
    if not _IDENTIFIER.match(name):
        raise SpecError(
            f"{what} must be a Python identifier to compile, and {name!r} is "
            f"not; rename it in the spec rather than have the generated code "
            f"disagree with it",
            loc,
        )


def _snake(name: str) -> str:
    """Return the suffix used for a unit's generated functions."""
    return name.lower()


def _docstring(text: str, indent: str) -> str:
    """Return *text* as a docstring, escaped so no author string can escape it."""
    body = " ".join(text.strip().split())
    return f'{indent}{"".join(chr(34) * 3)}{_escape(body)}{"".join(chr(34) * 3)}'


def _escape(text: str) -> str:
    """Escape author text for inclusion in a docstring."""
    return text.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
