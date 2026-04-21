# packeteer

packeteer is a pure-Python toolkit for crafting, capturing, and generating
network traffic without any external dependencies.

Use it to build hand-crafted packets from a JSON description, parse real
pcap captures back into that same format, sanitise sensitive fields before
sharing, or generate complete synthetic network streams — TCP, UDP, or SCTP
— with realistic protocol state, timestamps, and optional impairments.

Everything runs from a CLI or directly from Python. No root, no libpcap, no
compiled extensions — Python 3.10+ and the standard library only.

```{raw} latex
\let\origpart\part\renewcommand{\part}[1]{\let\part\origpart}
```

## In this documentation

```{toctree}
:maxdepth: 1

overview
installation
quickstart
build/index
parse/index
sanitiser/index
synthetic/index
stream/index
packet-spec/index
api/index
internals/index
reference/packet-sizes
reference/rfc-references
```
