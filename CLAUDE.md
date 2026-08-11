# packeteer — Claude guidance

## The product

This code consists of a CLI defined in src/packeteer/__main__.py and a Python
API which the CLI uses. It is important that all fuctionality implemented in
the CLI is easily available from the API as well. Keep __main__.py as lean
as possible.

The API should be easy to use and feel logical. Code solving different but similar
problems, for instance for different protocols, should have aligned signatures.

## Code style

- **Type hints everywhere.** All function parameters, return types, and class attributes must be annotated. Use `from __future__ import annotations` at the top of every module.
- **Zero ruff warnings.** After any change, the file you touched must produce no warnings from `ruff check`. The project config is in `ruff.toml`. Never make a warning
go away by changing values in the config file. Using a # noqa: comment to suppress
warnings can only be used as a last resort, and **always ask before making such a change**.

## Git

- **Never commit or push without explicit instruction.** Do not run `git commit`, `git push`, or any destructive git command (`reset --hard`, `checkout .`, etc.) unless I have asked for it in the current message.

## Versioning and changelog

- The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
  While below 1.0, **breaking changes are allowed in a minor bump** (0.7 → 0.8);
  they must still be called out.
- `CHANGELOG.md` follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
  **Every user-visible change gets an entry under `## [Unreleased]` in the same
  change that introduces it** — new/changed public API, CLI flags, packet-spec
  keys, defaults, bug fixes, and docs. Purely internal refactors and test-only
  changes do not.
- Change types, in this order, omitting any that are empty: `Added`, `Changed`,
  `Deprecated`, `Removed`, `Fixed`, `Security`, `Documentation` (the last is a
  project-specific extra for docs-only work).
- Anything that breaks backwards compatibility goes under `Changed` (or
  `Removed`) with a leading **`Breaking:`** and a note on what callers must do
  instead.
- `pyproject.toml` carries the version. During development of the next release
  it is a `.devN` suffix (currently `0.8.0.dev0`); the release commit drops the
  suffix.
- Releasing: rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a fresh
  empty `Unreleased`, set the version in `pyproject.toml`, update the link
  definitions at the bottom of `CHANGELOG.md`, then tag `vX.Y.Z` (full three-part
  version — the older `v0.7` style is not used going forward).

## Project layout

- `src/packeteer/generate/` — packet building and stream generation
- `src/packeteer/parse/` — pcap parsing and config extraction
- `src/packeteer/sanitise.py` — packet sanitisation
- `src/packeteer/pcap.py` — all pcap I/O (read + write); the only place pcap logic lives
- `src/tests/` — unittest test suite; run with `.venv/bin/pytest`

## Virtual environment

All development tasks (tests, docs, wheel builds) use a single venv created from `requirements.txt`:

```bash
python -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

- **Run tests:** `.venv/bin/pytest`
- **Build docs:** `.venv/bin/sphinx-build docs docs/_build/html`
- **Build wheel:** `.venv/bin/python -m build`

## Conventions

- Use `.venv/bin/pytest` to run tests and `ruff` (on PATH) to lint.
- Docstrings follow Google style with ruff-enforced formatting (see `ruff.toml`). Sections (Args, Returns, Raises, Attributes, Example) need a blank line before the closing `"""`.
- `packeteer.pcap` is not re-exported from `packeteer.generate` or `packeteer.parse` — users import it directly.
