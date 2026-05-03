# Fuzzer

**Import:** `from packeteer.fuzz import fuzz, fuzz_bytes, FuzzOptions, FuzzVariant`

`packeteer.fuzz` generates adversarial packet variants for decoder robustness
testing.  Two complementary functions are provided:

- {func}`~packeteer.fuzz.fuzz` — works on packet spec dicts (the JSON format
  produced by `packeteer parse`) and returns :class:`~packeteer.fuzz.FuzzVariant`
  objects ready for replay.
- {func}`~packeteer.fuzz.fuzz_bytes` — works on raw serialised packet bytes and
  returns ``(label, corrupted_bytes)`` pairs suitable for writing directly to a
  pcap file.

The same {class}`~packeteer.fuzz.FuzzOptions` instance can be passed to both
functions; each silently applies only the mutations relevant to its domain.

See {doc}`../guide/fuzzing` for task-oriented examples and a description of every
mutation type.

---

```{eval-rst}
.. autoclass:: packeteer.fuzz.FuzzOptions
   :members:
   :no-index:
```

```{eval-rst}
.. autoclass:: packeteer.fuzz.FuzzVariant
   :members:
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.fuzz.fuzz
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.fuzz.fuzz_bytes
   :no-index:
```

```{eval-rst}
.. autodata:: packeteer.fuzz.MUTATION_NAMES
   :no-index:
```

```{eval-rst}
.. autodata:: packeteer.fuzz.BYTE_MUTATION_NAMES
   :no-index:
```

```{eval-rst}
.. autodata:: packeteer.fuzz.ALL_MUTATION_NAMES
   :no-index:
```
