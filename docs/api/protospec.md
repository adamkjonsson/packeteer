# `packeteer.protospec`

**Import:** `from packeteer import protospec`

Reads a protocol spec and compiles it to a Python module implementing
{class}`~packeteer.protocols.AppProtocol`.  Everything
{doc}`packeteer protocol <../cli/protocol>` does is here — the CLI is a thin
wrapper, and the spec format itself is documented in
{doc}`../protocols/format`.

The four steps are separate on purpose, because each answers a different
question:

```python
from packeteer import protospec

spec = protospec.load("sensor.yaml")          # is it a well-formed spec?
result = protospec.check(spec)                # does it describe something buildable?
print(protospec.render(spec))                 # what does it actually say?
source = protospec.compile_spec(spec)         # turn it into a module
```

{func}`~packeteer.protospec.load` refuses a document that cannot be read *as a
spec*; {func}`~packeteer.protospec.check` collects every remaining fault rather
than stopping at the first, so one run says everything that is wrong.  A spec
with errors should not reach {func}`~packeteer.protospec.compile_spec`.

## Loading

A spec is YAML or JSON.  JSON is read with the standard library, so a spec
always loads; YAML needs the optional extra (`pip install 'packeteer[yaml]'`)
and is only needed to *compile* — a compiled module imports nothing but
packeteer and the standard library.

Constructs kober defines that this version does not implement are neither
refused nor silently dropped.  They are recorded on
{attr}`Spec.unsupported <packeteer.protospec.spec.Spec.unsupported>` so the
checker reports *not supported yet* and names them, rather than *unknown key* —
the difference between "this will work later" and "you typed something wrong".

```{eval-rst}
.. autofunction:: packeteer.protospec.load
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.protospec.loads
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.protospec.from_mapping
   :no-index:
```

```{eval-rst}
.. autoexception:: packeteer.protospec.SpecError
   :members:
   :no-index:
```

## Checking

```{eval-rst}
.. autofunction:: packeteer.protospec.check
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.CheckResult
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.Diagnostic
   :members:
   :no-index:
```

### Widths

A `fill`-sized field ends where the fields after it begin, so its length is the
run's less what they claim.  That width is resolved **once**, here, and the
compiler reads it from this function rather than working it out again — the two
cannot then disagree about where a body ends.

It is total by **refusal** rather than by approximation: a trailing field whose
width the spec does not fix returns `None`, because a guessed boundary is what
the checker exists to prevent.

```{eval-rst}
.. autofunction:: packeteer.protospec.check.trailing_width
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.protospec.check.run_relative_units
   :no-index:
```

## Compiling

The generated module is a plain Python file meant to be committed and reviewed.
It imports only packeteer and the standard library, and holds a dataclass per
unit plus `encode`, `decode`, `to_spec` and `from_spec`.

```{eval-rst}
.. autofunction:: packeteer.protospec.compile_spec
   :no-index:
```

## Rendering

```{eval-rst}
.. autofunction:: packeteer.protospec.render
   :no-index:
```

`render` works on a spec that does **not** check, which is when it is most
useful: an expression naming a field that does not exist still appears in the
tree, so you can see what you wrote next to what you meant.

---

## The spec model

`packeteer.protospec.spec` holds the shape of a loaded spec.  Everything in it
is frozen data: the loader produces it, the checker validates it, and the
compiler turns it into Python.

Two declarations are easy to confuse and are independent.
{attr}`Spec.input <packeteer.protospec.spec.Spec.input>` is kober's — the
**stream shape** a spec is written against.
{attr}`Spec.over <packeteer.protospec.spec.Spec.over>` is packeteer's — **which
transport** carries it.  DNS is the example that makes the difference plain: it
is `input: datagram, over: udp` over UDP and `input: stream, over: tcp` over
TCP, because a TCP DNS message declares its own length and a UDP one does not.

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Spec
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Unit
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Field
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Location
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Unsupported
   :members:
   :no-index:
```

### Declarations

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.InputShape
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Transport
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Endian
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.EnumDef
   :members:
   :no-index:
```

### Field types

A field names exactly one of these.  See
{ref}`how a field is written <shorthands>` for the spellings that build them.

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.IntType
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.BytesType
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.StringType
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.UnitRef
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Switch
   :members:
   :no-index:
```

### Sizes

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Fixed
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.FromExpr
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Remaining
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Fill
   :members:
   :no-index:
```

### Repeats, constants and derivations

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Count
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.Const
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.SizeOf
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.protospec.spec.CountOf
   :members:
   :no-index:
```
