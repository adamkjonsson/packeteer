# Installation

## Requirements

Python 3.10 or later is required (the codebase uses the `X | Y` union type
syntax introduced in Python 3.10).  There are no runtime dependencies beyond
the standard library.

## Clone and install

```bash
git clone https://github.com/adamkjonsson/packet-generator.git
cd packet-generator
pip install -e .
```

The `-e` flag installs the package in *editable* mode, so changes to the
source are reflected immediately without reinstalling.  After installation the
`packeteer` command is available on your `PATH`.

## Run the tests

```bash
python -m unittest discover tests/ -v
```

All tests run in under a second with no third-party packages required.

## Install documentation dependencies

To build the documentation locally:

```bash
pip install -r docs/requirements.txt
cd docs && make html
```

The rendered output appears at `docs/_build/html/index.html`.

---

Next: {doc}`quickstart`
