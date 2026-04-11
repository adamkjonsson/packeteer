# Python API

The `packet_parser.to_config` module provides the functions used internally by
`packeteer parse` and `packeteer stream --json` to produce JSON configs from
parsed or generated packets.  See {doc}`../api/parser` for the full API reference.

## Building a config from raw packets

Use `parse_packet` to decode each raw packet, `update_config` to populate a
per-packet dict from each layer, then `to_json_config` and `to_json_string` to
assemble the final output:

```python
import json
from packet_generator.tcp_stream import generate_tcp_stream
from packet_generator.pcap import LINKTYPE_ETHERNET
from packet_parser.parser import parse_packet
from packet_parser.to_config import update_config, to_json_config, to_json_string

stream = generate_tcp_stream(client_ip="10.0.0.1", server_ip="10.0.0.2",
                              num_data_packets=5)
packet_configs = []
for pkt in stream.packets:
    parsed = parse_packet(pkt.raw, link_type=LINKTYPE_ETHERNET)
    cfg = {}
    if parsed.ethernet:
        update_config(cfg, parsed.ethernet)
    if parsed.ip:
        update_config(cfg, parsed.ip)
    if parsed.transport:
        update_config(cfg, parsed.transport)
        if parsed.payload:
            update_config(cfg, parsed.payload)
    cfg["packet_metadata"] = {"timestamp_s": pkt.ts_sec, "timestamp_us": pkt.ts_usec,
                               "direction": pkt.direction, "label": pkt.label}
    packet_configs.append(cfg)

with open("stream.json", "w") as f:
    f.write(to_json_string(to_json_config(packet_configs)))
```

This is the same pipeline that `packeteer stream --json` uses internally.

## Reading a config back

```python
import json

with open("stream.json") as f:
    config = json.load(f)

# Top-level metadata
print(config["metadata"]["nanoseconds"])   # False

# Per-packet fields
for pkt in config["packets"]:
    meta = pkt.get("packet_metadata", {})
    print(meta.get("label"), meta.get("direction"))
```
