# CLI Reference

`packet_lab.py` is the command-line entry point with two subcommands:
`build` constructs packets and writes them to a pcap or pcapng file;
`parse` reads a capture and produces a JSON config that can be fed back
to `build` for replay.

---

## `build`

```
python packet_lab.py build <config.json> (--pcap FILE | --pcapng FILE)
```

Reads the JSON config file, builds each packet, and writes them all to the
output file.  `--pcap` and `--pcapng` are mutually exclusive; one is required.

| Argument | Description |
|----------|-------------|
| `config.json` | *(required)* Path to a JSON file with a top-level `packets` array |
| `--pcap FILE` | Write to a libpcap (`.pcap`) file |
| `--pcapng FILE` | Write to a pcapng (`.pcapng`) file |

### Examples

```bash
# Build from a JSON config and write a pcap file
python packet_lab.py build packets.json --pcap out.pcap

# Build from a JSON config and write a pcapng file
python packet_lab.py build packets.json --pcapng out.pcapng
```

Per-packet fragmentation is controlled via the `metadata.mtu` field in the
JSON config — see {doc}`json-config` and {doc}`fragmentation`.

---

## `parse`

```
python packet_lab.py parse <capture> [options]
```

Reads every packet in a pcap or pcapng file, parses it through all layers, and
outputs a JSON config that can be passed back to `build`.  Both file formats
are auto-detected from the first four bytes — no extension checking needed.

| Option | Description |
|--------|-------------|
| `capture` | *(required)* Path to a `.pcap` or `.pcapng` file |
| `--output FILE`, `-o FILE` | Write the JSON config to FILE instead of printing to stdout |
| `--replay-pcap FILE` | Embed `file_metadata.type = "pcap"` and `file_metadata.pcap = FILE` in the generated config |
| `--replay-pcapng FILE` | Embed `file_metadata.type = "pcapng"` (mutually exclusive with `--replay-pcap`) |

### Examples

```bash
# Print JSON config to stdout
python packet_lab.py parse capture.pcap

# Save JSON config to a file
python packet_lab.py parse capture.pcap --output replay.json

# Save and embed a replay pcap path in the config
python packet_lab.py parse capture.pcap --output replay.json --replay-pcap replayed.pcap

# Parse a pcapng file (auto-detected)
python packet_lab.py parse capture.pcapng --output replay.json

# Round-trip: parse pcapng → config → rebuild as pcapng
python packet_lab.py parse capture.pcapng --output config.json
python packet_lab.py build config.json --pcapng out.pcapng
```

---

## Programmatic equivalent

{func}`packet_parser.parser.parse_pcap_file` is the Python API that `parse`
calls internally.  Use it to read a pcap and get back the same JSON string
without invoking the CLI:

```python
from packet_parser.parser import parse_pcap_file

json_str = parse_pcap_file(path="capture.pcap")
print(json_str)
```

See {doc}`api/parser` for the full parsing API.
