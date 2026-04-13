# Parsing Captures

packeteer parses captures in two ways: from the CLI using `packeteer parse`,
or directly from Python using the `packeteer.parser` API.  Both paths produce the
same output — a packet spec that mirrors the packet structure layer by layer and
can be fed straight back into `packeteer build` for replay.

```{toctree}
:maxdepth: 1

cli
python-api
```
