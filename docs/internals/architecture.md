# Architecture overview

## Data flow

packeteer has two primary data representations that it converts between:

```
raw bytes (pcap)  --parse--→  packet spec dict  --build--→  raw bytes (pcap)
```

The **packet spec dict** is the pivot format.  It mirrors the wire layout of a
packet — each protocol layer gets its own key at the appropriate nesting level
— and is serialisable as JSON.  All library components accept or produce this
dict; the CLI simply drives them from the command line.

## Components

```
+--------------------------------------------------------------------+
|  packeteer_cli.py                                                  |
|  (parse / file-info / build / sanitise / stream / fuzz subcommands)|
+--------------+--------------------+--------------------+-----------+
               |                    |                    |
    +----------v----------+  +------v------+  +----------v-----------+
    |  packeteer/parse/   |  | packeteer/  |  |  packeteer/generate/ |
    |  parser.py          |  | filter.py   |  |  builder.py          |
    |  to_config.py       |  | PacketFilter|  |  tcp_stream.py ...   |
    +----------+----------+  +-------------+  +----------+-----------+
               |                                         |
    +----------v----------+                   +-----------v----------+
    |  Parsed header      |                   |  Raw packet bytes    |
    |  dataclasses        |                   |  (to pcap / pcapng)  |
    +---------------------+                   +----------------------+

packeteer/sanitise.py and packeteer/fuzz.py both operate on packet spec dicts
and are independent of the parse/generate pipeline:

    packet spec dict  --sanitise-->  sanitised spec dict
    packet spec dict  --fuzz------->  list[FuzzVariant]  (spec-level)
    raw bytes         --fuzz_bytes->  list[(label, bytes)]  (byte-level)
```

**`packeteer.parse`** reads raw bytes and produces `ParsedPacket` objects, which
are then serialised to packet spec dicts by `to_config.py`.  In addition to
protocol headers, the parse pipeline decodes application-layer messages: DNS
and mDNS (UDP port 53/5353), DHCP (UDP port 67/68), and HTTP/1.x (TCP port
80/8080).

**`packeteer.filter`** provides the `PacketFilter` dataclass, which expresses
AND-combined filter criteria (protocol, ports, IP addresses/CIDRs, application
layer) over packet spec dicts.  `parse_pcap_file` accepts an optional
`PacketFilter` and excludes non-matching packets from its output.

**`packeteer.generate`** reads packet spec dicts and produces raw bytes, one
packet at a time via `PacketBuilder`, or complete synthetic streams via the
stream generator modules.

**`packeteer/sanitise.py`** operates on packet spec dicts: it deep-copies the dict and
replaces sensitive field values in place.

**`packeteer/fuzz.py`** operates on packet spec dicts (via `fuzz()`) or raw
serialised bytes (via `fuzz_bytes()`).  Both functions are independent of the
parse/generate pipeline and can be used standalone.

## Shared header dataclasses

The two packages share the protocol header dataclasses defined in
`packeteer/generate/`.  The parser imports `EthernetHeader`, `IPHeader`,
`TCPHeader`, etc. from `packeteer.generate` and populates them when it decodes
bytes.  The builder consumes those same dataclasses when it encodes bytes.
This means there is a single canonical representation of each protocol header,
and a round-trip `parse → build` reconstruction works without any conversion.

## pcap I/O

`read_pcap`, `write_pcap`, and `write_pcapng` all live in `packeteer/pcap.py`
and work with `(raw_bytes, ts_sec, ts_frac)` tuples.  The pcap layer is
deliberately thin — it does nothing more than read or write the file container
and delegates all packet interpretation to the parser or builder.
