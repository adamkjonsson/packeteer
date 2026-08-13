"""Access to the ``packeteer stream`` config-file template.

``packeteer stream`` takes enough options that reproducing an involved setup
is best done from a config file (``--config FILE``).  This module hands out a
documented starting point for one, listing every recognised key with its
default and an explanation.

The template is shipped as package data, so it is available from an installed
wheel and not only from a source checkout.
"""
from __future__ import annotations

from importlib.resources import files

_TEMPLATE_NAME = "stream.ini.template"


def stream_config_template() -> str:
    """Return the ``packeteer stream`` config-file template as text.

    The template is a commented INI file with a ``[stream]`` section: the few
    required keys are set to working values and every other recognised key
    appears as a commented-out example with its default.  Write it somewhere,
    uncomment what you need, and run ``packeteer stream --config FILE``.

    Returns:
        The template file's contents, ending in a newline.

    Example::

        from packeteer.generate import stream_config_template

        with open("my_stream.ini", "w") as f:
            f.write(stream_config_template())

    """
    return (files("packeteer.generate") / _TEMPLATE_NAME).read_text(encoding="utf-8")
