# Reference

This section is the complete technical reference for packeteer.  It covers the
packet spec file format, the full public API, protocol header sizes, and the
RFCs that define every wire format the library implements.

| Section | What you will find |
|---------|--------------------|
| {doc}`Packet Spec <../packet-spec/index>` | The JSON format shared by `parse`, `build`, and `stream --json`.  Everything that can appear in a packet spec file, with examples for every field. |
| {doc}`API Reference <../api/index>` | Full Python API: `PacketBuilder`, all header dataclasses, parser functions, sanitisation options, and stream generators. |
| {doc}`Internals <../internals/index>` | How the library works under the hood — useful for contributors and for users who need to extend or embed packeteer beyond the public API. |
| {doc}`Packet Sizes <packet-sizes>` | Fixed header sizes for every supported protocol, tunnel overhead tables, and worked examples for common layer stacks. |
| {doc}`RFC References <rfc-references>` | Every RFC and IEEE standard that packeteer implements, with the specific classes and functions that correspond to each one. |

The packet spec and API sections are the most commonly consulted.  If you are
writing code that builds or parses packets, start with the API Reference;
if you are inspecting or editing a spec file produced by `packeteer parse`,
start with the Packet Spec.

```{toctree}
:maxdepth: 1

../packet-spec/index
../api/index
../internals/index
packet-sizes
rfc-references
```
