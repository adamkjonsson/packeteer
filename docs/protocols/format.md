# Spec Format Reference

A **protocol spec** describes an application protocol declaratively: what its
messages look like on the wire, which transport and ports carry them, and how
to compute the fields a sender derives rather than chooses.
`packeteer protocol compile` turns one into a Python module that
{doc}`registers an AppProtocol <../guide/adding-a-protocol>`, after which
packeteer parses, builds, serialises and redacts that protocol exactly as it
does DNS, DHCP or HTTP.

A spec is YAML or JSON.  JSON loads from the standard library; YAML needs the
optional extra:

```console
$ pip install 'packeteer[yaml]'
```

```yaml
name: sensor
version: "1.0"
input: datagram
entry: reading
over: udp
ports: [9000]
doc: Field telemetry from the shed sensors.

enums:
  kind: {0: temperature, 1: humidity, 2: pressure}

units:
  reading:
    fields:
      - {name: magic,   type: {int: {bits: 16}}, const: 0x5345}
      - {name: count,   type: {int: {bits: 8}}, derive: {count_of: samples}}
      - {name: samples, type: {unit: sample}, repeat: {count: "count"}}

  sample:
    fields:
      - {name: kind,   type: {int: {bits: 8, enum: kind}}}
      - {name: length, type: {int: {bits: 8}}, derive: {size_of: value}}
      - {name: value,  type: {bytes: {size: {expr: "length"}}}, sensitive: true}
```

---

(protocols-scope)=
## What a spec can and cannot describe

**One message per packet payload.**  packeteer decodes one packet at a time,
and its guarantee is that a capture rebuilds byte for byte.  A protocol whose
messages span TCP segments has no packet-level identity to reconstruct, so
reassembling one could never participate in `parse` → edit → `build` — see
[`input`](#input) below.  Such a protocol is
[kober](https://github.com/adamkjonsson/zipline-kober)'s, not packeteer's.

**Binary framing, not delimiters.**  A field's length comes from a constant, an
earlier field, or the rest of the message.  A field that ends at a byte
sequence — an HTTP header line ending at `\r\n` — is not expressible.

Constructs kober has that this version does not implement are reported by
`packeteer protocol check` as **not supported yet**, naming them, rather than
as unknown keys:

| Construct | Why not |
|---|---|
| `pointer` | Decoding one is straightforward; *encoding* one needs a compression model, and packeteer's own DNS encoder declines to compress |
| `select` | A question asked across a repeated field — what HTTP needs to decide its own framing |
| `computed` | A value derived at decode time; `derive` is the encode-direction answer and covers the cases that matter here |
| `{size: {terminated: …}}` | Delimiter framing |
| `repeat: {until: …}`, `repeat: {to_end: true}` | Repeat by condition, or to the end of the run |
| unit `params:` / `{unit: {args: …}}` | Unit parameters |
| recursion | A recursive unit has no statically known size, which both the encoder and the framing checks need |

---

(protocols-kober)=
## Relationship to kober's dialect

The dialect is a **superset of
[kober](https://github.com/adamkjonsson/zipline-kober)'s**.  kober's keys keep
kober's meaning, and packeteer adds five of its own — [`over`](#over),
[`ports`](#ports), [`const`](#const), [`derive`](#derive) and
[`sensitive`](#sensitive) — which are what a spec needs in order to describe an
**encoder**.  kober decodes only, and so never had to.

A kober spec therefore loads here and describes the same messages; adding
`derive` lines is what makes it describe an encoder too.

This is documented and reasoned, **not enforced by a test suite shared between
the projects**, so treat it as a strong intention rather than a guarantee.

---

## Top level

| Key | Default | Description |
|-----|---------|-------------|
| `name` | *(required)* | Protocol name.  Becomes the registered protocol's name, and so the packet-spec section key — see [`name`](#name) |
| `version` | *(required)* | Spec version, free-form.  **Quote it**: unquoted `1.10` is the number 1.1 in YAML, not the text `"1.10"` |
| `entry` | *(required)* | Name of the unit one message consists of |
| `units` | *(required)* | Every unit, by name — see [Units](#units) |
| `enums` | `{}` | Named values for integer fields — see [Enums](#enums) |
| `over` | `either` | Which transport carries it: `udp`, `tcp`, `either` |
| `ports` | `[]` | Transport ports that identify it |
| `input` | `datagram` | The stream shape the spec is written against — see [`input`](#input) |
| `doc` | — | Free-text description.  Becomes the generated module's docstring |

(name)=
### `name`

Doubles as the packet-spec section key, so a protocol named `sensor` makes
`packeteer parse` emit a `"sensor"` object beside `"network"` and
`"transport"`, and `packeteer build` read it back.

It may not be one of the structural keys in {doc}`../packet-spec/format` —
`ethernet`, `network`, `transport`, `payload` and the rest.  Registering one
that collides is refused, naming the collision.

(over)=
(ports)=
### `over` and `ports`

What decides when the protocol is used.  A packet whose source or destination
port is claimed, on a matching transport, is handed to this protocol's decoder;
the destination port is consulted first.

**A port claim is a weak signal**, and deliberately so.  A decoder that raises
leaves the bytes as an opaque payload and parsing carries on, which is what
makes claiming a busy port survivable.  Give the entry unit a
[`const`](#const) so a mismatch is recognised rather than mangled.

(input)=
### `input`

kober's key, with kober's meaning: the **stream shape** the spec is written
against — `datagram`, `stream`, or `either`.

It is a different axis from [`over`](#over), which is the **transport**.  DNS
is the example that makes the difference plain: it is `input: datagram, over:
udp` over UDP, and `input: stream, over: tcp` over TCP, because a TCP DNS
message declares its own length and a UDP one does not.

**`input: stream` is refused by `packeteer protocol compile`.**  A stream
protocol's messages span packets — see [scope](#protocols-scope).  A spec whose
messages each fit in one packet should say `input: datagram`, which is the
default.

---

(units)=
## Units

A unit is a named group of fields, decoded in order.  `entry` names the one a
whole message is.

```yaml
units:
  reading:
    doc: One datagram — a header and a run of samples.
    fields:
      - {name: magic, type: {int: {bits: 16}}, const: 0x5345}
```

| Key | Default | Description |
|-----|---------|-------------|
| `fields` | *(required)* | The unit's fields, in wire order |
| `doc` | — | Free-text description |

---

## Fields

| Key | Default | Description |
|-----|---------|-------------|
| `name` | *(required)* | Field name.  Must be a Python identifier, since it becomes an attribute.  `null` makes the field anonymous — decoded and re-encoded, but not named |
| `type` | *(required)* | What it holds — see [Types](#types) |
| `repeat` | — | How many times it occurs — see [`repeat`](#repeat) |
| `const` | — | A value written on encode and checked on decode — see [`const`](#const) |
| `derive` | — | How the encoder computes it — see [`derive`](#derive) |
| `sensitive` | `false` | Whether `packeteer sanitise` redacts it — see [`sensitive`](#sensitive) |
| `doc` | — | Free-text description |

A field may only reference fields **decoded before it**.  A forward reference
is refused by `check`, naming the field and where it was declared.

(types)=
### Types

A type names exactly one construct.

#### `int`

```yaml
type: {int: {bits: 16, signed: false, endian: big, enum: kind}}
```

| Key | Default | Description |
|-----|---------|-------------|
| `bits` | *(required)* | Width, 1 to 64.  Sub-byte fields are read most-significant bit first, and consecutive ones must add up to whole bytes |
| `signed` | `false` | Two's-complement when `true` |
| `endian` | `big` | `big` or `little`.  Meaningless below 8 bits, and ignored there |
| `enum` | — | Name of the enum labelling its values |

#### `bytes` and `string`

```yaml
type: {bytes: {size: 4}}
type: {bytes: {size: {expr: "length"}}}
type: {string: {size: {remaining: true}, encoding: ascii}}
```

| Size form | Meaning |
|---|---|
| `4` | Exactly four bytes — shorthand for `{fixed: 4}` |
| `{fixed: 4}` | The same |
| `{expr: "n * 2"}` | An integer [expression](#expressions), read from earlier fields |
| `{remaining: true}` | Everything left in the message |
| `{terminated: …}` | Delimiter framing — **not supported yet** |

`string` takes an `encoding` as well, defaulting to `utf-8`.  A `bytes` field
reaches a packet spec as a hex string.

#### `unit`

```yaml
type: {unit: sample}
type: {unit: {name: sample}}
```

Both forms mean the same.  `{unit: {name: x, args: […]}}` is kober's unit
parameters, which are **not supported yet**.

#### `switch`

```yaml
type:
  switch:
    on: "kind"
    cases:
      1: {int: {bits: 8}}
      2: {bytes: {size: 2}}
    default: {bytes: {size: {remaining: true}}}
```

| Key | Default | Description |
|-----|---------|-------------|
| `on` | *(required)* | An integer [expression](#expressions) selecting the case |
| `cases` | *(required)* | The type to use, by value |
| `default` | — | The type for a value no case matches |

**Without a `default`, a value no case matches makes the message
undecodable** — the decoder raises and the bytes stay an opaque payload.  That
is often what you want, so `check` warns rather than refusing, to make it a
choice rather than an oversight.

```{note}
`on:` is a YAML 1.1 boolean.  packeteer reads it back as the key you wrote,
because quoting it would be a papercut every author hits once.  Elsewhere,
an unquoted `on`, `off`, `yes` or `no` becomes `true`/`false` and is refused
with a message saying to quote it.
```

(repeat)=
### `repeat`

```yaml
repeat: {count: "qdcount"}
```

The count is an integer [expression](#expressions).  `repeat: {until: …}` and
`repeat: {to_end: true}` are **not supported yet**.

A repeated field has no value an expression can read: the language has no list
type, so referencing one is refused.

(const)=
### `const`

```yaml
- {name: magic, type: {int: {bits: 16}}, const: 0x5345}
```

The value is the field's default, and **decoding raises when the bytes
disagree**.  That is the point: a port claim is weak, so a magic number is what
keeps another protocol's traffic on the same port an opaque payload instead of
a mangled message.

An explicit override is still written on encode, so deliberately malformed
traffic can be built — packeteer generates it on purpose.

(derive)=
### `derive`

```yaml
- {name: count,  type: {int: {bits: 8}}, derive: {count_of: samples}}
- {name: length, type: {int: {bits: 8}}, derive: {size_of: value}}
```

| Rule | Meaning |
|---|---|
| `size_of: <field>` | The named field's encoded length in bytes.  The target must be a `bytes`, `string` or `unit` field |
| `count_of: <field>` | How many elements the named repeated field has |

A derived field compiles to `int | None`, where `None` means *compute it*:

- **encode** writes the computed value, unless the object carries an override,
  which is written verbatim;
- **decode** clears the field when the capture agrees with the derivation, and
  keeps the captured value when it does not;
- **`to_spec`** omits the key when the field is `None`.

So a well-formed capture produces a spec with no redundant lengths and counts,
and a capture whose length disagrees with its data records the disagreement and
rebuilds byte for byte.  This is the rule `transport.length` and
`transport.checksum` follow — see
{ref}`packet-spec-transport-overrides`.

```{note}
A length used to **read** its target can never disagree with it: exactly that
many bytes were read, so the derivation always matches and the field is always
cleared.  `derive` earns its keep when the target is read some other way — as
`{remaining: true}`, at a fixed size, or where one length covers several
fields.
```

(sensitive)=
### `sensitive`

```yaml
- {name: value, type: {bytes: {size: {expr: "length"}}}, sensitive: true}
```

Marks a field `packeteer sanitise` should redact.

```{warning}
A field that carries anything identifying and is **not** marked is not
redacted, and `sanitise` reports success.  For everything else in packeteer an
unknown protocol means a feature you do not get; here it means data you meant
to remove is still there.
```

---

(enums)=
## Enums

```yaml
enums:
  kind: {0: temperature, 1: humidity, 2: pressure}
```

Labels for an integer field's values, referenced by
`{int: {bits: 8, enum: kind}}`.  They appear in `packeteer protocol show`
output.  Values may be written as numbers or as their string spelling, since
JSON object keys are always strings.

---

(expressions)=
## Expressions

Wherever a spec needs a value it cannot know in advance — a size, a repeat
count, a switch selector — it is written as an expression string.

```yaml
size:   {expr: "header.length * 4"}
count:  "qdcount"
on:     "length >> 6"
```

| | |
|---|---|
| Arithmetic | `+` `-` `*` `/` `%` |
| Bitwise | `&` `\|` `^` `~` `<<` `>>` |
| Comparison | `==` `!=` `<` `<=` `>` `>=` |
| Boolean | `and` `or` `not` |
| Literals | `42`, `0x2a`, `0b101010`, `'text'`, `true`, `false` |

Precedence is Python's, because the parser is Python's — `ast.parse` in
expression mode against a whitelist.  That is why there are no calls, no
indexing and no comprehensions: they are absent from the whitelist and refused
by name.

**Four types and no coercion**: `int`, `str`, `bytes`, `bool`.  Arithmetic and
ordering are integer-only, equality needs both sides to be the same type, and
`and`/`or`/`not` need booleans — `qdcount and …` is an error rather than a test
for non-zero, and the message says to write `!= 0`.

`/` floors, because there is no floating-point type; a float literal is refused
rather than truncated.

### Scoping

| Prefix | Resolves against |
|---|---|
| *(none)* or `this.` | The containing unit |
| `parent.` | The unit that referenced this one |
| `root.` | The entry unit |

A dotted path descends into a nested unit: `header.length` reads the `length`
field of the `header` field's unit.

kober's three functions — `to_int`, `trim`, `lower` — are **not supported
yet**, and a call is reported as such rather than as a syntax error.
