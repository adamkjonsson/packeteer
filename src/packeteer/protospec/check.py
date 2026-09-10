"""Validate a protocol spec before any data exists.

Two things make this worth doing at all.  A spec that cannot be checked is a
decoder that has to be *tried* against a capture to find out whether it is
right, and a checker that stops at the first fault makes fixing a spec an
iterative guessing game.  So :func:`check` collects **every** fault it can
find and reports them together, which is kober's behaviour and worth copying
exactly.

Three groups of check run here.

**What kober checks too** — a field may only reference fields decoded before
it, enums and units exist, nothing is unreachable, and every expression types.

**What is new because packeteer encodes.**  kober is decode-only; packeteer
compiles an encoder from the same spec, so a spec can be perfectly decodable
and still not describe an encoder.  A ``derive`` naming a field it does not
size, a ``const`` on a field whose type cannot hold it, a length nothing
computes — none of those stop a decoder, and all of them stop a compiler.

**What is new because of streams.**  A spec declaring ``input: stream`` has to
prove its entry unit is *length-prefixed*: the message length must be readable
from a fixed-position prefix, or a reassembler cannot know where a message
ends without having already read it.  The proof yields the prefix size, which
the compiler needs to generate ``frame_length``.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from packeteer.protospec.errors import SpecError
from packeteer.protospec.expr import (
    ExprType,
    Ref,
    parse,
    references,
    type_of,
    unparse,
)
from packeteer.protospec.spec import (
    BytesType,
    CountOf,
    Field,
    FieldType,
    Fill,
    Fixed,
    FromExpr,
    InputShape,
    IntType,
    Location,
    Remaining,
    Size,
    SizeOf,
    Spec,
    StringType,
    Switch,
    Unit,
    UnitRef,
)

__all__ = ["Diagnostic", "CheckResult", "check", "trailing_width",
           "run_relative_units"]

_BITS_PER_BYTE = 8


@dataclass(frozen=True)
class Diagnostic:
    """One fault found in a spec.

    Attributes:
        severity: ``"error"`` or ``"warning"``.  A warning is something that
            is legal and probably not meant; ``--strict`` promotes them.
        message: What is wrong, and where possible what to do instead.
        location: Where in the spec it is.

    """

    severity: str
    message: str
    location: Location

    def __str__(self) -> str:
        return f"{self.severity}: {self.location}: {self.message}"


@dataclass(frozen=True)
class CheckResult:
    """Everything :func:`check` found, and what it proved.

    Attributes:
        spec: The spec that was checked.
        diagnostics: Every fault, in the order found.
        prefix_size: For a length-prefixed stream spec, the number of bytes a
            reassembler must have before it can know how long a message is.
            ``None`` for a datagram spec, or when the proof failed.

    """

    spec: Spec
    diagnostics: tuple[Diagnostic, ...] = ()
    prefix_size: int | None = None

    @property
    def errors(self) -> tuple[Diagnostic, ...]:
        """Diagnostics that stop the spec compiling."""
        return tuple(d for d in self.diagnostics if d.severity == "error")

    @property
    def warnings(self) -> tuple[Diagnostic, ...]:
        """Diagnostics that are legal but probably not meant."""
        return tuple(d for d in self.diagnostics if d.severity == "warning")

    def ok(self, *, strict: bool = False) -> bool:
        """Whether the spec passed.

        Args:
            strict: When ``True``, a warning fails too.

        Returns:
            ``True`` when nothing stops the spec compiling.

        """
        return not self.errors and not (strict and self.warnings)

    def summary(self) -> str:
        """Return the one-line verdict, as the CLI prints it.

        Returns:
            ``"name version: ok"``, or a count of what was found.

        """
        head = f"{self.spec.name} {self.spec.version}"
        if not self.diagnostics:
            return f"{head}: ok"
        parts = []
        if self.errors:
            parts.append(f"{len(self.errors)} error(s)")
        if self.warnings:
            parts.append(f"{len(self.warnings)} warning(s)")
        return f"{head}: {', '.join(parts)}"


def check(spec: Spec) -> CheckResult:
    """Validate *spec*, collecting every fault rather than stopping at the first.

    Args:
        spec: The spec to check.

    Returns:
        A :class:`CheckResult` holding every diagnostic, and the prefix size
        when the spec is a length-prefixed stream.

    """
    return _Checker(spec).run()


@dataclass
class _Checker:
    """Holds the spec and the diagnostics found while walking it."""

    spec: Spec
    diagnostics: list[Diagnostic] = dataclass_field(default_factory=list)
    # Where each unit is referenced from, for resolving `parent`.
    referenced_from: dict[str, list[tuple[str, int]]] = dataclass_field(
        default_factory=dict,
    )

    def run(self) -> CheckResult:
        """Run every check and return the result."""
        self._report_unsupported()
        self._check_entry()
        self._build_reference_map()
        self._check_units()
        self._check_reachability()
        prefix = self._check_framing()
        return CheckResult(
            spec=self.spec,
            diagnostics=tuple(self.diagnostics),
            prefix_size=prefix,
        )

    # ── reporting ─────────────────────────────────────────────────────────────

    def _error(self, message: str, loc: Location) -> None:
        self.diagnostics.append(Diagnostic("error", message, loc))

    def _warn(self, message: str, loc: Location) -> None:
        self.diagnostics.append(Diagnostic("warning", message, loc))

    def _report_unsupported(self) -> None:
        """Report constructs the loader read but this version cannot compile.

        Reported as *not supported yet* rather than as unknown keys, because a
        spec written for kober will contain them and the difference matters:
        one says "this will work later", the other says "you typed something
        wrong".
        """
        for item in self.spec.unsupported:
            note = f" — {item.note}" if item.note else ""
            self._error(f"not supported yet: {item.construct}{note}", item.loc)

    # ── structure ─────────────────────────────────────────────────────────────

    def _check_entry(self) -> None:
        if self.spec.entry not in self.spec.units:
            known = ", ".join(sorted(self.spec.units)) or "none"
            self._error(
                f"entry unit {self.spec.entry!r} is not defined; "
                f"units are: {known}",
                self.spec.loc.child("entry"),
            )

    def _build_reference_map(self) -> None:
        """Record where each unit is referenced from, for `parent` resolution."""
        for unit in self.spec.units.values():
            for index, fld in enumerate(unit.fields):
                for referenced in _unit_refs(fld.type):
                    self.referenced_from.setdefault(referenced, []).append(
                        (unit.name, index),
                    )

    def _check_reachability(self) -> None:
        """Warn about units nothing reaches, and refuse recursion."""
        if self.spec.entry not in self.spec.units:
            return
        seen: set[str] = set()
        stack = [self.spec.entry]
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            unit = self.spec.units.get(name)
            if unit is None:
                continue
            for fld in unit.fields:
                stack.extend(_unit_refs(fld.type))

        for name, unit in self.spec.units.items():
            if name not in seen:
                self._warn(
                    f"unit {name!r} is never referenced from the entry unit",
                    unit.loc,
                )
        self._check_recursion()

    def _check_recursion(self) -> None:
        """Refuse a unit that can contain itself.

        Legal in kober and not in this version: a recursive unit has no
        statically known size, which the encoder and the stream prefix proof
        both need.
        """
        for name in self.spec.units:
            if self._reaches(name, name):
                self._error(
                    f"not supported yet: unit {name!r} is recursive",
                    self.spec.units[name].loc,
                )

    def _reaches(self, start: str, target: str) -> bool:
        """Whether *target* is reachable from *start* through unit references."""
        seen: set[str] = set()
        stack = [
            ref for fld in self.spec.units[start].fields
            for ref in _unit_refs(fld.type)
        ] if start in self.spec.units else []
        while stack:
            name = stack.pop()
            if name == target:
                return True
            if name in seen or name not in self.spec.units:
                continue
            seen.add(name)
            for fld in self.spec.units[name].fields:
                stack.extend(_unit_refs(fld.type))
        return False

    # ── units and fields ──────────────────────────────────────────────────────

    def _check_units(self) -> None:
        for unit in self.spec.units.values():
            self._check_unit(unit)
            self._check_fill(unit)
            self._check_remaining(unit)
        self._check_run_relative()

    def _check_remaining(self, unit: Unit) -> None:
        """Refuse a ``remaining`` with anything decoded after it.

        ``remaining`` takes everything left, so a field after one is read from
        an exhausted cursor for every input there will ever be.  There is no
        message such a spec decodes, which is why this is an error rather than
        a warning: nothing is left for the author to weigh.
        """
        for index, fld in enumerate(unit.fields[:-1]):
            if not _has_remaining(fld.type):
                continue
            after = unit.fields[index + 1].name
            self._error(
                f"{fld.name!r} is sized 'remaining', which takes everything "
                f"left, but {after!r} is decoded after it and would have no "
                f"bytes to read; size it 'fill' to leave the trailing fields "
                f"their bytes",
                fld.loc,
            )
            return

    def _check_fill(self, unit: Unit) -> None:
        """Check every ``fill`` in *unit* has a trailer the spec fixes."""
        fills = [i for i, f in enumerate(unit.fields)
                 if _has_fill(f.type)]
        if not fills:
            return
        if len(fills) > 1:
            named = ", ".join(repr(unit.fields[i].name) for i in fills)
            self._error(
                f"unit {unit.name!r} has {len(fills)} 'fill' fields ({named}); "
                f"only one can take what is left",
                unit.fields[fills[1]].loc,
            )
            return
        index = fills[0]
        fld = unit.fields[index]
        if fld.repeat is not None:
            self._error(
                "a 'fill' field cannot repeat: the first element would take "
                "everything left and no later one could read anything",
                fld.loc,
            )
            return
        if trailing_width(unit, index, self.spec) is None:
            self._error(
                f"the fields after {fld.name!r} do not have a width the spec "
                f"fixes, so 'fill' cannot say where it ends; give every "
                f"trailing field a fixed width, or size this one another way",
                fld.loc,
            )

    def _check_run_relative(self) -> None:
        """Refuse a run-relative unit referenced from anywhere but last.

        A ``remaining`` reads to the end of the run and a ``fill`` reads to the
        end of the run less its own unit's trailer.  Either one inside a unit
        that is not the last thing decoded eats the bytes of whatever follows.
        """
        relative = run_relative_units(self.spec)
        if not relative:
            return
        for unit in self.spec.units.values():
            for index, fld in enumerate(unit.fields[:-1]):
                culprits = [r for r in _unit_refs(fld.type) if r in relative]
                if not culprits:
                    continue
                after = unit.fields[index + 1].name
                self._error(
                    f"{fld.name!r} is unit {culprits[0]!r}, which reads to the "
                    f"end of the message through {relative[culprits[0]]!r}, but "
                    f"{after!r} is decoded after it and would have no bytes "
                    f"left",
                    fld.loc,
                )

    def _check_unit(self, unit: Unit) -> None:
        seen: set[str] = set()
        for index, fld in enumerate(unit.fields):
            if fld.name is not None:
                if fld.name in seen:
                    self._error(
                        f"unit {unit.name!r} has two fields named {fld.name!r}",
                        fld.loc,
                    )
                seen.add(fld.name)
            self._check_field(unit, index, fld)

    def _check_field(self, unit: Unit, index: int, fld: Field) -> None:
        self._check_type(unit, index, fld, fld.type)
        self._check_const(fld)
        self._check_derive(unit, fld)
        if fld.repeat is not None:
            self._check_expr(unit, index, fld.repeat.expr, ExprType.INT,
                             "a repeat count", fld.loc)
        if fld.condition is not None:
            self._check_expr(unit, index, fld.condition, ExprType.BOOL,
                             "a condition", fld.loc)

    def _check_type(self, unit: Unit, index: int, fld: Field,
                    field_type: FieldType) -> None:
        """Check one type, recursing into a switch's arms."""
        if isinstance(field_type, IntType):
            if field_type.enum is not None and field_type.enum not in self.spec.enums:
                known = ", ".join(sorted(self.spec.enums)) or "none"
                self._error(
                    f"unknown enum {field_type.enum!r}; declared enums: {known}",
                    fld.loc,
                )
        elif isinstance(field_type, (BytesType, StringType)):
            self._check_size(unit, index, fld, field_type.size)
        elif isinstance(field_type, UnitRef):
            if field_type.unit not in self.spec.units:
                known = ", ".join(sorted(self.spec.units)) or "none"
                self._error(
                    f"unknown unit {field_type.unit!r}; units are: {known}",
                    fld.loc,
                )
        elif isinstance(field_type, Switch):
            self._check_expr(unit, index, field_type.dispatch, ExprType.INT,
                             "a switch selector", fld.loc)
            if field_type.default is None:
                self._warn(
                    "this switch has no default, so a value no case matches "
                    "leaves the region undecoded; say 'default:' if that is "
                    "meant",
                    fld.loc,
                )
            for arm in field_type.arms.values():
                self._check_type(unit, index, fld, arm)
            if field_type.default is not None:
                self._check_type(unit, index, fld, field_type.default)

    def _check_size(self, unit: Unit, index: int, fld: Field, size: Size) -> None:
        """Check a size, and whether the encoder can produce it."""
        if isinstance(size, FromExpr):
            self._check_expr(unit, index, size.expr, ExprType.INT, "a size",
                             fld.loc)
            self._check_size_is_derived(unit, fld, size)
        elif isinstance(size, Fixed) and size.length < 0:
            self._error(f"a fixed size cannot be negative, got {size.length}",
                        fld.loc)

    def _check_size_is_derived(self, unit: Unit, fld: Field,
                               size: FromExpr) -> None:
        """Warn when nothing computes the length this field is sized by.

        A capture still round-trips — the length was read from the wire and is
        written back — but a message built by hand needs the author to set the
        length themselves and keep it right, which is exactly the bookkeeping
        ``derive`` exists to remove.
        """
        if fld.name is None:
            return
        try:
            expr = parse(size.expr, fld.loc)
        except SpecError:
            return                      # already reported by _check_expr
        refs = list(references(expr))
        if len(refs) != 1 or refs[0].scope != "this" or len(refs[0].path) != 1:
            return
        length_field = _field_named(unit, refs[0].path[0])
        if length_field is None:
            return                      # already reported by _check_expr
        derive = length_field.derive
        if isinstance(derive, SizeOf) and derive.field == fld.name:
            return
        self._warn(
            f"{fld.name!r} is sized by {refs[0].path[0]!r}, which nothing "
            f"derives; add 'derive: {{size_of: {fld.name}}}' to it, or set it "
            f"by hand on every message you build",
            length_field.loc,
        )

    def _check_const(self, fld: Field) -> None:
        """Check that the field's type can hold its constant."""
        if fld.const is None:
            return
        value = fld.const.value
        expected = _const_type_name(fld.type)
        if expected is None:
            self._error(
                "'const' needs a field with a value of its own; a unit or "
                "switch has none",
                fld.loc,
            )
            return
        actual = _value_type_name(value)
        if actual != expected:
            self._error(
                f"'const' is {actual} but the field holds {expected}",
                fld.loc,
            )
            return
        if isinstance(fld.type, IntType) and isinstance(value, int):
            limit = 1 << fld.type.bits
            if not fld.type.signed and not 0 <= value < limit:
                self._error(
                    f"'const' {value} does not fit in {fld.type.bits} "
                    f"unsigned bits", fld.loc,
                )

    def _check_derive(self, unit: Unit, fld: Field) -> None:
        """Check that a derivation names something it can actually derive from."""
        if fld.derive is None:
            return
        if not isinstance(fld.type, IntType):
            self._error("'derive' needs an integer field", fld.loc)
            return
        target = _field_named(unit, fld.derive.field)
        if target is None:
            self._error(
                f"'derive' names {fld.derive.field!r}, which is not a field of "
                f"unit {unit.name!r}",
                fld.loc,
            )
            return
        if target is fld:
            self._error("'derive' cannot name the field it is on", fld.loc)
            return
        if isinstance(fld.derive, CountOf) and target.repeat is None:
            self._error(
                f"'count_of' names {fld.derive.field!r}, which does not "
                f"repeat; there is nothing to count",
                fld.loc,
            )
        if fld.const is not None:
            self._error(
                "a field cannot be both 'const' and 'derive': one fixes the "
                "value, the other computes it",
                fld.loc,
            )
        if isinstance(fld.derive, SizeOf) and not isinstance(
                target.type, (BytesType, StringType, UnitRef)):
            self._error(
                f"'size_of' names {fld.derive.field!r}, whose encoded length "
                f"is fixed by its type; size a bytes, string or unit field",
                fld.loc,
            )
        if isinstance(fld.derive, SizeOf) and target.repeat is not None:
            self._error(
                f"'size_of' names {fld.derive.field!r}, which repeats; use "
                f"'count_of', or size a single element",
                fld.loc,
            )
        if target.condition is not None:
            # An absent field has no length and no elements to count, and
            # which it is cannot be known from the spec.  Refusing beats
            # deriving a zero that silently means "the guard was false".
            self._error(
                f"'derive' names {fld.derive.field!r}, which has a "
                f"'condition' and so may be absent; a derivation cannot say "
                f"whether it is deriving from nothing or from an empty value",
                fld.loc,
            )

    # ── expressions ───────────────────────────────────────────────────────────

    def _check_expr(self, unit: Unit, index: int, source: str,
                    expected: ExprType, what: str, loc: Location) -> None:
        """Parse, scope and type one expression."""
        try:
            expr = parse(source, loc)
        except SpecError as exc:
            self._error(exc.message, exc.location or loc)
            return
        try:
            actual = type_of(expr, self._resolver(unit, index, loc), loc)
        except SpecError as exc:
            self._error(exc.message, exc.location or loc)
            return
        if actual is not expected:
            self._error(
                f"{what} is {actual.value}, expected {expected.value}: "
                f"{unparse(expr)}",
                loc,
            )

    def _resolver(self, unit: Unit, index: int,
                  loc: Location) -> Callable[[Ref], ExprType]:
        """Return a resolver typing a reference from *unit*'s field *index*."""
        def resolve(ref: Ref) -> ExprType:
            return self._resolve(ref, unit, index, loc)
        return resolve

    def _resolve(self, ref: Ref, unit: Unit, index: int,
                 loc: Location) -> ExprType:
        """Type one reference, enforcing that it reads only decoded fields."""
        if ref.scope == "root":
            start = self.spec.units.get(self.spec.entry)
            limit = None
        elif ref.scope == "parent":
            start, limit = self._parent_of(unit, ref, loc)
        else:
            start, limit = unit, index

        if start is None:
            raise SpecError(
                f"{unparse(ref)} has no {ref.scope} unit to resolve against", loc,
            )
        return self._walk(ref, start, limit, loc)

    def _parent_of(self, unit: Unit, ref: Ref,
                   loc: Location) -> tuple[Unit | None, int | None]:
        """Return the unit that references *unit*, and where from.

        A unit referenced from more than one place has more than one parent,
        so the reference has to hold at every site.  The earliest site is
        returned, which is the strictest of them.
        """
        sites = self.referenced_from.get(unit.name, [])
        if not sites:
            raise SpecError(
                f"unit {unit.name!r} is never referenced, so {unparse(ref)} "
                f"has no parent",
                loc,
            )
        names = {name for name, _ in sites}
        if len(names) > 1:
            # Every site must satisfy the reference; the earliest index in the
            # earliest-named unit is the tightest constraint.
            self._warn(
                f"unit {unit.name!r} is referenced from {len(names)} units, so "
                f"{unparse(ref)} must resolve in all of them",
                loc,
            )
        parent_name, parent_index = min(sites, key=lambda site: (site[0], site[1]))
        return self.spec.units.get(parent_name), parent_index

    def _walk(self, ref: Ref, unit: Unit, limit: int | None,
              loc: Location) -> ExprType:
        """Follow *ref*'s dotted path from *unit*, and type what it lands on."""
        current = unit
        for depth, name in enumerate(ref.path):
            found = None
            for position, fld in enumerate(current.fields):
                if fld.name != name:
                    continue
                if depth == 0 and limit is not None and position >= limit:
                    raise SpecError(
                        f"{name!r} is declared later in unit {current.name!r}; "
                        f"a field may only reference fields decoded before it",
                        loc,
                    )
                found = fld
                break
            if found is None:
                raise SpecError(
                    f"unit {current.name!r} has no field {name!r}", loc,
                )
            if depth == len(ref.path) - 1:
                if found.repeat is not None:
                    raise SpecError(
                        f"{name!r} repeats, and the expression language has no "
                        f"list type",
                        loc,
                    )
                return _type_of_field(found.type, name, loc)
            if not isinstance(found.type, UnitRef):
                raise SpecError(
                    f"{name!r} is not a unit, so {unparse(ref)} cannot descend "
                    f"into it",
                    loc,
                )
            nested = self.spec.units.get(found.type.unit)
            if nested is None:
                raise SpecError(f"unknown unit {found.type.unit!r}", loc)
            current, limit = nested, None
        raise SpecError(f"{unparse(ref)} does not name a field", loc)

    # ── framing ───────────────────────────────────────────────────────────────

    def _check_framing(self) -> int | None:
        """Prove a stream spec is length-prefixed, and return the prefix size.

        A reassembler has to know how long a message is *before* it has the
        whole message, so the length must be readable from a fixed-position
        prefix.  The shape this version accepts is the one DNS-over-TCP and
        most binary RPC use: an integer field at a fixed offset whose
        ``derive: size_of`` names the last field of the entry unit, with
        everything else fixed-width.
        """
        if self.spec.input is not InputShape.STREAM:
            return None
        entry = self.spec.units.get(self.spec.entry)
        if entry is None or not entry.fields:
            return None

        framing = [f for f in entry.fields if isinstance(f.derive, SizeOf)]
        if len(framing) != 1:
            self._error(
                "not supported yet: an 'input: stream' spec needs exactly one "
                "field deriving 'size_of' in its entry unit, to say where a "
                f"message ends; found {len(framing)}",
                entry.loc,
            )
            return None

        length_field = framing[0]
        target_name = length_field.derive.field
        if entry.fields[-1].name != target_name:
            self._error(
                f"not supported yet: {target_name!r} is sized by "
                f"{length_field.name!r} but is not the last field of the entry "
                f"unit, so a message's end cannot be computed from the prefix",
                length_field.loc,
            )
            return None

        prefix_bits = 0
        for fld in entry.fields:
            if fld.name == target_name:
                break
            width = _fixed_bits(fld, self.spec)
            if width is None:
                self._error(
                    f"not supported yet: {fld.name!r} has no fixed width, so "
                    f"{length_field.name!r} is not at a fixed offset and "
                    f"cannot be read from a prefix",
                    fld.loc,
                )
                return None
            prefix_bits += width

        if prefix_bits % _BITS_PER_BYTE:
            self._error(
                f"the prefix ending at {length_field.name!r} is {prefix_bits} "
                f"bits, which is not a whole number of bytes",
                length_field.loc,
            )
            return None
        return prefix_bits // _BITS_PER_BYTE


# ── widths a `fill` and the framing checks both need ──────────────────────────

def trailing_width(unit: Unit, index: int, spec: Spec) -> int | None:
    """Return the bytes the fields after *index* claim, or ``None`` if unknown.

    Total by **refusal** rather than by approximation: a field whose width the
    spec does not fix returns ``None`` rather than a guess, because a guessed
    boundary is exactly what this module exists to prevent.  A trailer that is
    not a whole number of bytes is unknown for the same reason.

    Args:
        unit: The unit the ``fill`` is in.
        index: Position of the ``fill`` field within *unit*.
        spec: The spec, for resolving nested units.

    Returns:
        The trailing width in bytes, or ``None`` when the spec does not fix it.

    """
    total = 0
    for fld in unit.fields[index + 1:]:
        width = _fixed_bits(fld, spec)
        if width is None:
            return None
        total += width
    if total % _BITS_PER_BYTE:
        return None
    return total // _BITS_PER_BYTE


def run_relative_units(spec: Spec) -> dict[str, str]:
    """Return each unit whose extent is the run's, and the field that makes it so.

    A ``remaining`` reads to the end of the run and a ``fill`` reads to the end
    of the run less its own unit's trailer.  Both are measured against the
    **run**, not against the enclosing unit, so a unit containing either is
    only correct where nothing is decoded after it.  Referencing one from any
    earlier position makes it eat bytes that belong to the fields that follow.

    The property is transitive: a unit referencing a run-relative unit is
    itself run-relative.

    Args:
        spec: The spec to walk.

    Returns:
        Unit name to the field name that makes it run-relative, for every unit
        that is.

    """
    direct: dict[str, str] = {}
    for unit in spec.units.values():
        for fld in unit.fields:
            if _is_run_relative_type(fld.type):
                direct.setdefault(unit.name, fld.name or "<anonymous>")
                break

    found = dict(direct)
    changed = True
    while changed:                       # transitive closure, units are finite
        changed = False
        for unit in spec.units.values():
            if unit.name in found:
                continue
            for fld in unit.fields:
                names = _unit_refs(fld.type)
                if any(ref in found for ref in names):
                    found[unit.name] = fld.name or "<anonymous>"
                    changed = True
                    break
    return found


def _has_remaining(field_type: FieldType) -> bool:
    """Whether a type is, or contains, a ``remaining``-sized region."""
    if isinstance(field_type, (BytesType, StringType)):
        return isinstance(field_type.size, Remaining)
    if isinstance(field_type, Switch):
        arms = list(field_type.arms.values())
        if field_type.default is not None:
            arms.append(field_type.default)
        return any(_has_remaining(arm) for arm in arms)
    return False


def _has_fill(field_type: FieldType) -> bool:
    """Whether a type is, or contains, a ``fill``-sized region."""
    if isinstance(field_type, (BytesType, StringType)):
        return isinstance(field_type.size, Fill)
    if isinstance(field_type, Switch):
        arms = list(field_type.arms.values())
        if field_type.default is not None:
            arms.append(field_type.default)
        return any(_has_fill(arm) for arm in arms)
    return False


def _is_run_relative_type(field_type: FieldType) -> bool:
    """Whether a type reads to the end of the run rather than a stated length."""
    if isinstance(field_type, (BytesType, StringType)):
        return isinstance(field_type.size, (Remaining, Fill))
    if isinstance(field_type, Switch):
        arms = list(field_type.arms.values())
        if field_type.default is not None:
            arms.append(field_type.default)
        return any(_is_run_relative_type(arm) for arm in arms)
    return False


# ── helpers ───────────────────────────────────────────────────────────────────

def _unit_refs(field_type: FieldType) -> list[str]:
    """Return every unit named by *field_type*, including a switch's arms."""
    if isinstance(field_type, UnitRef):
        return [field_type.unit]
    if isinstance(field_type, Switch):
        found = [name for arm in field_type.arms.values() for name in _unit_refs(arm)]
        if field_type.default is not None:
            found += _unit_refs(field_type.default)
        return found
    return []


def _field_named(unit: Unit, name: str) -> Field | None:
    """Return *unit*'s field called *name*, or ``None``."""
    for fld in unit.fields:
        if fld.name == name:
            return fld
    return None


def _type_of_field(field_type: FieldType, name: str, loc: Location) -> ExprType:
    """Return the expression type a field of *field_type* has."""
    if isinstance(field_type, IntType):
        return ExprType.INT
    if isinstance(field_type, StringType):
        return ExprType.STR
    if isinstance(field_type, BytesType):
        return ExprType.BYTES
    raise SpecError(
        f"{name!r} is a {type(field_type).__name__.lower().replace('type', '')} "
        f"and has no value an expression can use",
        loc,
    )


def _fixed_bits(fld: Field, spec: Spec) -> int | None:
    """Return a field's encoded width in bits, or ``None`` when it varies.

    A field with a ``condition`` has no fixed width whatever its type: it
    occupies its width or nothing at all, and which of those is not knowable
    from the spec.  Refusing here rather than approximating is what keeps a
    guessed boundary out of the framing checks that read this.
    """
    if fld.repeat is not None or fld.condition is not None:
        return None
    return _fixed_bits_of_type(fld.type, spec)


def _fixed_bits_of_type(field_type: FieldType, spec: Spec) -> int | None:
    """Return a type's encoded width in bits, or ``None`` when it varies."""
    if isinstance(field_type, IntType):
        return field_type.bits
    if isinstance(field_type, (BytesType, StringType)):
        if isinstance(field_type.size, Fixed):
            return field_type.size.length * _BITS_PER_BYTE
        return None
    if isinstance(field_type, UnitRef):
        unit = spec.units.get(field_type.unit)
        if unit is None:
            return None
        total = 0
        for fld in unit.fields:
            width = _fixed_bits(fld, spec)
            if width is None:
                return None
            total += width
        return total
    return None                          # a switch's arms may differ in width


def _const_type_name(field_type: FieldType) -> str | None:
    """Return the name of the value type *field_type* holds, or ``None``."""
    if isinstance(field_type, IntType):
        return "an integer"
    if isinstance(field_type, StringType):
        return "text"
    if isinstance(field_type, BytesType):
        return "bytes"
    return None


def _value_type_name(value: object) -> str:
    """Name a constant's type the way :func:`_const_type_name` does."""
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, int):
        return "an integer"
    if isinstance(value, str):
        return "text"
    if isinstance(value, bytes):
        return "bytes"
    return type(value).__name__

