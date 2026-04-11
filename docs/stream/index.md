# Stream Generation

packeteer generates complete, byte-accurate network streams in two ways: from
the CLI using `packeteer stream`, or directly from Python using one of the three
generator functions.  Both paths produce realistic packet sequences — including
correct protocol state, sequence numbers, checksums, timestamps, and optional
impairments — that can be written to pcap, pcapng, or JSON config files.

Three protocols are supported:

| Protocol | What is generated |
|----------|-------------------|
| `tcp` *(default)* | Three-way handshake, data transfer, four-way teardown with correct seq/ack numbers |
| `udp` | Sequence of client→server datagrams with realistic timestamps |
| `sctp` | Full SCTP association: 4-way handshake, DATA+SACK pairs, graceful shutdown per RFC 9260 |

```{toctree}
:maxdepth: 1

cli
python-api
```
