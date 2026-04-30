# The CLI

After installation the `packeteer` command is available on your PATH.
Running `python -m packeteer` is exactly equivalent — useful in environments
where the entry-point script is not on the PATH or when you need to target a
specific Python interpreter.

packeteer provides five subcommands, each covering one stage of the
capture-edit-replay workflow:

| Subcommand | Input | Output | Purpose |
|------------|-------|--------|---------|
| `parse` | pcap / pcapng | packet spec (JSON) | Decode a capture into a structured, human-readable description |
| `sanitise` | packet spec or pcap | packet spec and/or pcap | Replace sensitive addresses, ports, and payloads with synthetic equivalents |
| `build` | packet spec | pcap / pcapng | Reconstruct a capture from a packet spec, recomputing all checksums |
| `stream` | flags / INI file | pcap / pcapng / packet spec | Generate a synthetic multi-packet TCP, UDP, or SCTP flow from scratch |
| `fuzz` | packet spec or pcap | packet spec and/or pcap | Produce adversarial variants of each packet for decoder robustness testing |

The subcommands compose naturally into a pipeline.  A typical
parse → sanitise → rebuild workflow looks like:

```
pcap  --parse--→  packet spec  --sanitise--→  clean spec  --build--→  pcap
```

You can also collapse the last two steps into one — `packeteer sanitise`
accepts a pcap file directly and can write a pcap directly:

```
packeteer sanitise capture.pcap --pcap clean.pcap
```

Or generate a synthetic capture in one step:

```
packeteer stream --client 10.0.0.1 --server 10.0.0.2 --pcap out.pcap
```

```{toctree}
:maxdepth: 1

parse
sanitise
build
stream
fuzz
```
