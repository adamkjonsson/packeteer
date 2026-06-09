# Summarising a Capture

When you want an overview of a capture rather than a full packet-by-packet
decode, {func}`packeteer.parse.info.pcap_info` reads a `.pcap` or `.pcapng`
file and returns a {class}`~packeteer.parse.info.PcapInfo` summary.  This is the
Python entry point behind `packeteer file-info`.

```python
from packeteer.parse import pcap_info

info = pcap_info(path="capture.pcap")
print(info.packet_count)     # packets analysed
print(info.session_count)    # unique directional 5-tuples
print(info.layer_counts)     # {'ethernet': 1240, 'ipv4': 1212, 'tcp': 980, ...}
```

`layer_counts` maps each protocol layer to the number of packets it appeared
in, and `session_count` counts unique **directional** 5-tuples
`(src, dst, src_port, dst_port, protocol)` — so `A→B` and `B→A` are two
sessions.  Only packets with an IP layer contribute a session.

## Rendering the text report

{func}`~packeteer.parse.info.format_pcap_info` produces the same human-readable
report the CLI prints:

```python
from packeteer.parse import pcap_info, format_pcap_info

print(format_pcap_info(pcap_info(path="capture.pcap")))
```

For machine consumption, {meth}`~packeteer.parse.info.PcapInfo.to_dict` returns
a JSON-serialisable dict:

```python
import json

print(json.dumps(pcap_info(path="capture.pcap").to_dict(), indent=2))
```

## Correcting a wrong link-type

A capture sometimes declares the wrong link-layer type in its header, which
would otherwise garble parsing.  By default `pcap_info` scores the declared
type against the supported alternatives (`ethernet` and `raw`) and parses with
whichever yields the most valid IP headers:

```python
info = pcap_info(path="mislabelled.pcap")
print(info.declared_link_type, "->", info.link_type, info.link_type_overridden)
```

Pass `link_type=` to force a specific type (disabling the heuristic), or
`auto_link_type=False` to always trust the header.  See
{doc}`pcap` for the link-type constants.

## Sampling large files

`num` limits the analysis to the first *N* packets.  Reading stops early
without loading the rest of the file, so the true link-type of a very large
capture can be determined from a small sample:

```python
info = pcap_info(path="huge.pcap", num=100)
print(info.packet_count)     # 100
print(info.packet_limit)     # 100
```

Every figure in the result then reflects just that sample.
