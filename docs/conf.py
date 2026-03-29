"""Sphinx configuration for packeteer documentation."""
import os
import sys

# Make packet_generator and packet_parser importable without pip install
sys.path.insert(0, os.path.abspath(".."))

# ── Project metadata ──────────────────────────────────────────────────────────

project = "packeteer"
author = "Adam Kjönsson"
release = "0.1.0"
copyright = f"2024, {author}"

# ── Extensions ────────────────────────────────────────────────────────────────

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx_autodoc_typehints",
    "myst_parser",
]

# ── Source ────────────────────────────────────────────────────────────────────

source_suffix = {".md": "myst"}
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# ── MyST ──────────────────────────────────────────────────────────────────────

myst_enable_extensions = [
    "colon_fence",   # :::directive::: syntax for eval-rst blocks
    "deflist",       # definition lists in API pages
    "attrs_inline",  # inline {.class} attribute syntax
]

myst_heading_anchors = 3   # auto-generate anchors for h1–h3

# ── autodoc ───────────────────────────────────────────────────────────────────

autodoc_member_order = "bysource"       # preserve natural call-chain order
autodoc_typehints = "description"       # types in description, not signature
autodoc_typehints_format = "short"      # bytes not builtins.bytes

# Exclude private implementation details from PacketBuilder
autodoc_default_options = {
    "exclude-members": (
        "_layers,_payload_size,_payload_data,_cached_payload,"
        "_payload_bytes,_find_ip_before,_ip_context,_clone_ip,"
        "_clone_ipv6,_assemble_range,_apply_eth_padding,_validate"
    ),
}

# ── intersphinx ───────────────────────────────────────────────────────────────

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# ── Theme ─────────────────────────────────────────────────────────────────────

html_theme = "furo"
html_title = "packeteer"

html_theme_options = {
    "source_repository": "https://github.com/adamkjonsson/packeteer",
    "source_branch": "main",
    "source_directory": "docs/",
}
