# The CLI

packeteer provides four subcommands.  They can be used in isolation or chained
together in a pipeline:

```
pcap  --parse--→  packet spec  --sanitise--→  clean spec  --build--→  pcap
                                                            --stream--→  pcap
```

```{toctree}
:maxdepth: 1

parse
sanitise
build
stream
```
