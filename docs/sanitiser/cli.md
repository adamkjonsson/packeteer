# `packeteer sanitise` — CLI

```
packeteer sanitise <input.json> [--output <output.json>]
                       [--no-ips] [--no-macs]
                       [--ports] [--payload] [--timestamps]
```

## Options

| Flag | Effect |
|------|--------|
| `--output FILE` / `-o FILE` | Write result to FILE (default: stdout) |
| `--no-ips` | Keep original IP addresses |
| `--no-macs` | Keep original MAC addresses |
| `--ports` | Replace port numbers |
| `--payload` | Zero out payload bytes |
| `--timestamps` | Zero out packet timestamps |

## Examples

Replace IPs and MACs only (defaults):

```bash
packeteer parse capture.pcap --output capture.json
packeteer sanitise capture.json --output clean.json
packeteer build clean.json --pcap clean.pcap
```

Full sanitisation (replace everything):

```bash
packeteer sanitise capture.json \
    --ports --payload --timestamps \
    --output fully-clean.json
```

Keep IPs, replace everything else:

```bash
packeteer sanitise capture.json \
    --no-ips --ports --payload --timestamps \
    --output clean.json
```
