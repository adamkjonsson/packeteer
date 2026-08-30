# Protocol Specs

packeteer ships with DNS, DHCP and HTTP.  A **protocol spec** lets you describe
your own — a proprietary telemetry format, an internal RPC — in YAML, and
compile it to a Python module that packeteer treats exactly like a built-in.

There are two routes to the same place, and this is the one to reach for
first.  The other is {doc}`writing the protocol by hand <../guide/adding-a-protocol>`,
which is what you need when the spec language cannot express your protocol —
see [what a spec can and cannot describe](protocols-scope).

```{toctree}
:maxdepth: 1

format
```

---

## From a spec to a pcap

The spec below is [`examples/protocols/sensor.yaml`](https://github.com/adamkjonsson/packeteer/blob/main/examples/protocols/sensor.yaml)
in the repository.  Sensors send UDP datagrams on port 9000: a magic number, a
version, a count, then that many `{kind, length, value, reading}` records.

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
      - {name: version, type: {int: {bits: 8}}}
      - {name: count,   type: {int: {bits: 8}}, derive: {count_of: samples}}
      - {name: samples, type: {unit: sample}, repeat: {count: "count"}}

  sample:
    fields:
      - {name: kind,    type: {int: {bits: 8, enum: kind}}}
      - {name: length,  type: {int: {bits: 8}}, derive: {size_of: value}}
      - {name: value,   type: {bytes: {size: {expr: "length"}}}, sensitive: true}
      - {name: reading, type: {int: {bits: 32, signed: true, endian: little}}}
```

### 1. Check it

Every fault is reported, not just the first, so a spec gets fixed in one pass.

```console
$ packeteer protocol check sensor.yaml
sensor 1.0: ok
```

`check` types every expression **before any data exists**, and refuses specs
that decode but cannot encode — a `derive` naming a field it does not size, a
`const` a field's type cannot hold.  `--strict` fails on warnings too.

### 2. Look at it

```console
$ packeteer protocol show sensor.yaml
sensor 1.0 — input: datagram, over: udp, ports: 9000, entry: reading

enum kind: 0=temperature, 1=humidity, 2=pressure

reading
  One datagram — a header and a run of samples.
├── magic: u16 = 0x5345
├── version: u8
├── count: u8  (derived: count_of samples)
└── samples: → sample  ×count
    ├── kind: u8 enum kind
    ├── length: u8  (derived: size_of value)
    ├── value: bytes[length]  [sensitive]
    └── reading: i32 le
```

Nested units are expanded in place, so the tree is the message rather than a
set of definitions to assemble in your head.  It works on a spec that does not
yet check, which is when you most want it.

### 3. Compile it

```console
$ packeteer protocol compile sensor.yaml
Wrote sensor.py (sensor 1.0, packeteer 0.11.0)
```

The module lands beside the spec, because it is meant to be committed and
reviewed.  It imports only packeteer and the standard library, and it holds a
dataclass per unit plus `encode`, `decode`, `to_spec` and `from_spec`.

### 4. Use it

Importing it registers the protocol.  Everything packeteer does for a built-in
it now does for yours:

```python
import sensor                                   # registers it
from packeteer.generate import PacketBuilder
from packeteer.parse import parse_packet

msg = sensor.Reading(version=1, samples=[
    sensor.Sample(kind=0, value=b"21.5", reading=-3),
])

frame = (PacketBuilder()
    .ethernet()
    .ip(src="10.0.0.1", dst="10.0.0.2")
    .udp(dst_port=9000)
    .app(msg)
    .build())

pkt = parse_packet(frame)
pkt.app_protocol      # "sensor"
pkt.app               # Reading(magic=21317, version=1, count=None, samples=[…])
```

Note `count=None`.  It is derived, so it is computed on encode and cleared on
decode whenever the capture agreed with the derivation — see
[`derive`](derive).

### 5. And in a packet spec

A registered protocol contributes a section named after it, so a capture parses
to a spec you can edit and build back:

```python
import json
import sensor                                   # registers it
from packeteer.parse import parse_pcap_file

print(json.loads(parse_pcap_file(path="capture.pcap"))["packets"][0]["sensor"])
```

```json
{
  "magic": 21317,
  "version": 1,
  "samples": [ { "kind": 0, "value": "32312e35", "reading": -3 } ]
}
```

Edit it, build it back with `packeteer build`, and the capture round-trips byte
for byte.  There is no `count` or `length` key: both are derived, and a rebuild
works them out.  Had the capture carried a length that *disagreed* with its
data, the key would be there and the disagreement would be rebuilt exactly —
see [`derive`](derive).

### Telling the command line about it

Registration is a side effect of importing, so something has to import the
module.  On the command line that is `--load-protocol`, which every subcommand
accepts, before or after the verb:

```console
$ packeteer parse --load-protocol ./sensor.py capture.pcap
```

Two other routes exist for when repeating the flag becomes tiresome:

| Route | Use it for |
|---|---|
| `--load-protocol FILE`, repeatable | One invocation, explicit |
| `"protocols": ["./sensor.py"]` in a packet spec | A spec that describes itself, so `parse` → edit → `build` needs no flag |
| `PACKETEER_PROTOCOLS`, `:`-separated | A shell that always wants the same ones |

`packeteer parse --load-protocol …` writes the `protocols` key into the spec
it produces, relative to the spec file, so the spec and the module beside it
move together and `packeteer build` needs no flag.

```{warning}
**All three import Python from a path, and importing runs it.**  That is no
worse than `import` — you name the file — but it is no better either.

The `protocols` key is a path *you* wrote in a spec you are editing.  packeteer
never takes such a path from a capture's contents, because a capture is
something you may have been sent: a path discovered while parsing traffic would
let the traffic choose what code runs.  Loading from a spec says on stderr what
it is importing, for the same reason.
```

---

## Where to be careful

**A compiled module is code, and importing it runs it.**  Treat a spec or a
generated module someone sends you the way you would treat any other Python
they send you.

**A port claim is weak.**  Give your entry unit a [`const`](const) magic
number: a decoder that raises leaves the bytes as an opaque payload, which is
what keeps someone else's traffic on the same port from being read as yours.

**Mark what is sensitive.**  A field carrying anything identifying that is not
marked [`sensitive`](sensitive) is not redacted by `packeteer sanitise`.  A
spec that marks nothing at all makes the command warn, once per capture, that
the section went through untouched — but a spec that marks *some* fields and
misses one is silent about the one it missed, because nothing can tell which
of your fields carries a name.

**One message per packet.**  See [scope](protocols-scope): a protocol whose
messages span TCP segments belongs in
[kober](https://github.com/adamkjonsson/zipline-kober), not here.

---

## A larger example

[`examples/protocols/rpc.yaml`](https://github.com/adamkjonsson/packeteer/blob/main/examples/protocols/rpc.yaml)
exercises what the sensor spec does not: bit fields, an enum on a sub-byte
field, a nested unit, and a `switch` whose arms are different units.

It reports one warning on purpose:

```console
$ packeteer protocol check rpc.yaml
warning: rpc.yaml:23: units.message.fields[2]: this switch has no default, so a
  value no case matches leaves the region undecoded; say 'default:' if that is meant
rpc 1.0: 1 warning(s)
```

That is the intended design — an unknown opcode should be undecodable rather
than guessed at — and the warning exists so it is a choice rather than an
oversight.
