# Sanitiser

**Import:** `from packeteer.sanitise import sanitise, SanitiseOptions`

`packeteer.sanitise.sanitise` replaces sensitive fields in a packet config dict with
deterministic synthetic values drawn from IANA-reserved address ranges.  The
original dict is never modified.

See {doc}`../sanitiser/index` for the full feature description and CLI equivalent.

---

```{eval-rst}
.. autoclass:: packeteer.sanitise.SanitiseOptions
   :members:
   :no-index:
```

```{eval-rst}
.. autofunction:: packeteer.sanitise.sanitise
   :no-index:
```
