"""Dependency-free terminal colors with NO_COLOR and non-TTY support."""

import os
import sys
from typing import Optional, TextIO


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


def enabled(stream: Optional[TextIO] = None) -> bool:
    output = stream or sys.stdout
    return (
        "NO_COLOR" not in os.environ
        and os.environ.get("TERM", "") != "dumb"
        and hasattr(output, "isatty")
        and output.isatty()
    )


def paint(text: object, *styles: str, stream: Optional[TextIO] = None) -> str:
    value = str(text)
    if not styles or not enabled(stream):
        return value
    return "{}{}{}".format("".join(styles), value, RESET)


def heading(text: object) -> str:
    return paint(text, BOLD, CYAN)


def success(text: object) -> str:
    return paint(text, GREEN)


def warning(text: object) -> str:
    return paint(text, YELLOW)


def danger(text: object) -> str:
    return paint(text, BOLD, RED)


def info(text: object) -> str:
    return paint(text, BLUE)


def muted(text: object) -> str:
    return paint(text, DIM)
