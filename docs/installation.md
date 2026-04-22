# Installation

## Requirements

Python 3.10 or later is required (the codebase uses the `X | Y` union type
syntax introduced in Python 3.10).  There are no runtime dependencies beyond
the standard library.

## Clone and install

```bash
git clone https://github.com/adamkjonsson/packeteer.git
cd packeteer
python -m venv .venv
.venv/bin/pip install -e . -r requirements.txt
```

This creates an isolated virtual environment and installs the package in
*editable* mode alongside the development dependencies (pytest and the
documentation tools).  After installation the `packeteer` command is available
as `.venv/bin/packeteer`.

## Run the tests

```bash
.venv/bin/pytest
```

All tests run in under a second.

## Install documentation dependencies

The documentation dependencies are included in `requirements.txt` and are
already installed by the step above.  To build the documentation locally, run
from the `docs/` directory:

| Target | Command | Output |
|--------|---------|--------|
| HTML (incremental) | `make html` | `_build/html/index.html` |
| HTML (clean, reinstalls package) | `make fresh-html` | `_build/html/index.html` |
| PDF (incremental) | `make pdf` | `_build/latex/packeteer.pdf` |
| PDF (clean, reinstalls package) | `make fresh-pdf` | `_build/latex/packeteer.pdf` |

Use `make fresh-html` or `make fresh-pdf` after a version bump — they reinstall the
package so the version number in the rendered output is always up to date.

PDF builds require a TeX distribution with `latexmk` (e.g. `brew install --cask mactex` on macOS).

---

:::{only} html
Next: {doc}`../guide/index`
:::
