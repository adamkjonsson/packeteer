# `packeteer sanitise` — CLI

```
packeteer sanitise <FILE> [--output <output.json>]
                          [--pcap <output.pcap>] [--pcapng <output.pcapng>]
                          [--no-ips] [--no-macs]
                          [--ports] [--payload] [--timestamps]
```

`FILE` may be a JSON packet spec **or** a pcap/pcapng capture file.  When a
capture file is given, it is parsed automatically before sanitising — no
separate `packeteer parse` step is needed.  The file type is detected from its
magic number, not its extension.

## Options

| Flag | Effect |
|------|--------|
| `--output FILE` / `-o FILE` | Write sanitised packet spec (JSON) to FILE (default: stdout) |
| `--pcap FILE` | Build sanitised packets and write to a libpcap file |
| `--pcapng FILE` | Build sanitised packets and write to a pcapng file |
| `--no-ips` | Keep original IP addresses |
| `--no-macs` | Keep original MAC addresses |
| `--ports` | Replace TCP/UDP port numbers |
| `--payload` | Zero out payload bytes |
| `--timestamps` | Zero out packet timestamps |

`--output`, `--pcap`, and `--pcapng` are independent and may be combined.
When none are given the sanitised packet spec is printed to stdout.

## Examples

One-step sanitise from a capture to a clean pcap:

```bash
packeteer sanitise capture.pcap --pcap clean.pcap
```

Sanitise a capture and produce both a clean pcap and a packet spec:

```bash
packeteer sanitise capture.pcap --pcap clean.pcap --output clean.json
```

Sanitise from a packet spec (classic two-step workflow):

```bash
packeteer parse capture.pcap --output capture.json
packeteer sanitise capture.json --output clean.json
packeteer build clean.json --pcap clean.pcap
```

Full sanitisation (replace everything), input from a capture file:

```bash
packeteer sanitise capture.pcap \
    --ports --payload --timestamps \
    --pcap fully-clean.pcap
```

Keep IPs, replace everything else:

```bash
packeteer sanitise capture.json \
    --no-ips --ports --payload --timestamps \
    --output clean.json
```
