# Installation

## Requirements

Python 3.10 or later is required (the codebase uses the `X | Y` union type
syntax introduced in Python 3.10).  There are no runtime dependencies beyond
the standard library.

## Clone and install

```bash
git clone https://github.com/adamkjonsson/packeteer.git
cd packeteer
pip install -e .
```

The `-e` flag installs the package in *editable* mode, so changes to the
source are reflected immediately without reinstalling.  After installation the
`packeteer` command is available on your `PATH`.

## Run the tests

```bash
PYTHONPATH=src python -m unittest discover src/tests/ -v
```

All tests run in under a second with no third-party packages required.

## Install documentation dependencies

To build the documentation locally:

```bash
pip install -r docs/requirements.txt
```

Then from the `docs/` directory:

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

Next: {doc}`quickstart`
