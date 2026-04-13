# Architecture overview

## Data flow

packeteer has two primary data representations that it converts between:

```
raw bytes (pcap)  ──parse──▶  packet spec dict  ──build──▶  raw bytes (pcap)
```

The **packet spec dict** is the pivot format.  It mirrors the wire layout of a
packet — each protocol layer gets its own key at the appropriate nesting level
— and is serialisable as JSON.  All library components accept or produce this
dict; the CLI simply drives them from the command line.

## Components

```
┌────────────────────────────────────────────────────────────────────┐
│  packeteer_cli.py                                                  │
│  (parse / build / sanitise / stream subcommands)                   │
└──────────────┬────────────────────────────────┬────────────────────┘
               │                                │
    ┌──────────▼──────────┐        ┌────────────▼────────────┐
    │  packeteer/parser/     │        │  packeteer/generator/      │
    │  parser.py          │        │  builder.py             │
    │  to_config.py       │        │  tcp_stream.py  …       │
    └──────────┬──────────┘        └────────────┬────────────┘
               │                                │
    ┌──────────▼──────────┐        ┌────────────▼────────────┐
    │  Parsed header      │        │  Raw packet bytes       │
    │  dataclasses        │        │  (to pcap / pcapng)     │
    └─────────────────────┘        └─────────────────────────┘
```

**`packeteer.parser`** reads raw bytes and produces `ParsedPacket` objects, which
are then serialised to packet spec dicts by `to_config.py`.

**`packeteer.generator`** reads packet spec dicts and produces raw bytes, one
packet at a time via `PacketBuilder`, or complete synthetic streams via the
stream generator modules.

**`packeteer/sanitiser.py`** operates on packet spec dicts: it deep-copies the dict and
replaces sensitive field values in place.

## Shared header dataclasses

The two packages share the protocol header dataclasses defined in
`packeteer/generator/`.  The parser imports `EthernetHeader`, `IPHeader`,
`TCPHeader`, etc. from `packeteer.generator` and populates them when it decodes
bytes.  The builder consumes those same dataclasses when it encodes bytes.
This means there is a single canonical representation of each protocol header,
and a round-trip `parse → build` reconstruction works without any conversion.

## pcap I/O

Both the `read_pcap` function (in `packeteer/parser/pcap.py`) and the `write_pcap`
/ `write_pcapng` functions (in `packeteer/generator/pcap.py`) work with
`(raw_bytes, ts_sec, ts_frac)` tuples.  The pcap layer is deliberately thin —
it does nothing more than read or write the file container and delegate all
packet interpretation to the parser or builder.
