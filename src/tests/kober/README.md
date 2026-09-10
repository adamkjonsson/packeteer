# Vendored kober specs

`dns.yaml` and `http.yaml`, copied verbatim from
[kober](https://github.com/adamkjonsson/zipline-kober) **0.2.0**
(`4b935a2`), and read by `src/tests/test_kober_dialect.py`.

## Why copies

`docs/protocols/format.md` calls packeteer's dialect a superset of kober's.
Until 0.13.0 that was a claim in two references rather than a property of two
loaders, and this directory is what makes it checkable.

Copies rather than a path into a sibling checkout, because the test has to run
in CI on a machine that has never heard of the other repository — and a
version-pinned copy is a fact about a released dialect, where a live path is a
fact about whatever happens to be checked out.

kober vendors packeteer's specs the same way, under `tests/packeteer/`.

## Drift

The copies going stale is the cost, and the answer is what the test asserts:
the **outcome** for each spec, including the refusals and the exact constructs
reported as *not supported yet*, rather than merely that they load.  A test
that asserts why `http.yaml` is refused fails when the reason changes, which is
the drift detector the copies would otherwise lack.

To refresh, copy both files again, run the suite, and read whatever it says has
changed before adjusting the expectations — a diff here is a dialect change in
one project or the other, and worth understanding rather than absorbing.

## Do not edit

These are not packeteer's files.  Nothing here should be reformatted, fixed, or
made to pass; if a spec no longer loads, that is the finding.
