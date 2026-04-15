# packeteer — Claude guidance

## Code style

- **Type hints everywhere.** All function parameters, return types, and class attributes must be annotated. Use `from __future__ import annotations` at the top of every module.
- **Zero ruff warnings.** After any change, the file you touched must produce no warnings from `ruff check`. The project config is in `ruff.toml`.

## Git

- **Never commit or push without explicit instruction.** Do not run `git commit`, `git push`, or any destructive git command (`reset --hard`, `checkout .`, etc.) unless I have asked for it in the current message.

## Project layout

- `src/packeteer/generator/` — packet building and stream generation
- `src/packeteer/parser/` — pcap parsing and config extraction
- `src/packeteer/sanitiser/` — packet sanitisation
- `src/packeteer/pcap.py` — all pcap I/O (read + write); the only place pcap logic lives
- `src/tests/` — unittest test suite; run with `./docvenv/bin/pytest`

## Conventions

- The test virtual environment is `./docvenv/`. Use `./docvenv/bin/pytest` to run tests and `ruff` (on PATH) to lint.
- Docstrings follow Google style with ruff-enforced formatting (see `ruff.toml`). Sections (Args, Returns, Raises, Attributes, Example) need a blank line before the closing `"""`.
- `packeteer.pcap` is not re-exported from `packeteer.generator` or `packeteer.parser` — users import it directly.
