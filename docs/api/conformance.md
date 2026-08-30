# `packeteer.conformance`

**Import:** `from packeteer import conformance`

Holds an application protocol to the contract every one must meet — whether it
was written by hand or compiled from a spec.

packeteer has two ways to produce an
{class}`~packeteer.protocols.AppProtocol`, and keeps both: DNS, DHCP and HTTP
are not expressible in the spec subset, so the built-ins are hand-written and
will stay so.  Two mechanisms with no shared test is how they drift, and this
module is the shared test.

It is not only for packeteer's own suite.  A protocol you register is treated
exactly like a built-in, so it is worth holding to the same contract:

```python
from packeteer import conformance, protocols

failures = conformance.check_protocol(
    protocols.for_section("sensor"),
    [Reading(version=1, samples=[(2, 21)])],
)
assert not failures, "\n".join(failures)
```

Every check returns *why* it failed rather than raising, so one run reports
everything wrong rather than the first thing.

## What it checks

| Property | Why it is here |
|---|---|
| Encoding is stable | `encode(decode(encode(m)))` must equal `encode(m)`.  A decoder may canonicalise, but it may not lose anything |
| Decoding is exact | `decode(encode(m1)) == m1` for the canonicalised message |
| The spec round trip is lossless | `from_spec(to_spec(m)) == m` |
| A section is JSON | A packet spec gets written to a file |
| Truncated input raises | At **every** byte offset.  A decoder returning a half-built object from a short read turns a snaplen-truncated capture into a spec that quietly says the missing fields were absent |
| The registry resolves it | By message type, and by every declared port on its transport |
| Sanitising leaves a section usable | Still JSON, and no new keys |
| A whole packet round-trips | Built with `PacketBuilder.app`, parsed back, put through the spec and rebuilt: byte for byte |

The last is the guarantee packeteer exists for, and it had been asserted for
the two mechanisms separately, in different files, with different fixtures —
exactly the shape of a guarantee that quietly stops holding on one side.

```{note}
**Canonicalising is allowed; losing something is not.**  DNS returns
`"example.com."` for a name written `"example.com"`, because that is what the
wire format means.  So the check is that the normalisation is *stable*, not
that it is absent, and {func}`canonicalises` reports it as information rather
than as a failure.
```

## Functions

```{eval-rst}
.. autofunction:: packeteer.conformance.check_protocol
```

```{eval-rst}
.. autofunction:: packeteer.conformance.canonicalises
```
