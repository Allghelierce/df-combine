"""Strings that came from firmware bytes, made safe to store and display.

File names are bytes on disk and in archives. Python decodes one that is not valid UTF-8 with
``surrogateescape`` (tarfile, ``os.walk``), which yields lone surrogates: SQLite, JSON responses and
reports cannot encode those, so a single such name used to fail the whole scan after the analysis
had finished. Such bytes are shown as ``\\xNN`` instead.
"""
from __future__ import annotations

import re
from typing import Any

_SURROGATE = re.compile("[\ud800-\udfff]")


def _repr(m: re.Match[str]) -> str:
    c = ord(m.group())
    return f"\\x{c - 0xDC00:02x}" if 0xDC80 <= c <= 0xDCFF else f"\\u{c:04x}"


def escape_surrogates(s: str) -> str:
    """``"user\\udc80dir"`` (the byte 0x80 decoded with surrogateescape) -> ``"user\\\\x80dir"``."""
    if s.isascii() or not _SURROGATE.search(s):
        return s
    return _SURROGATE.sub(_repr, s)


def clean_strings(obj: Any) -> Any:
    """Escape lone surrogates in every string (keys included) of a parsed JSON document.

    Iterative, so the depth of the document is not limited by the recursion limit."""
    if isinstance(obj, str):
        return escape_surrogates(obj)
    if not isinstance(obj, (dict, list)):
        return obj
    stack: list[Any] = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            for i, v in enumerate(node):
                if isinstance(v, str):
                    node[i] = escape_surrogates(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        else:
            for k in list(node):
                v = node[k]
                if isinstance(v, str):
                    v = escape_surrogates(v)
                elif isinstance(v, (dict, list)):
                    stack.append(v)
                nk = escape_surrogates(k) if isinstance(k, str) else k
                if nk != k:
                    del node[k]
                node[nk] = v
    return obj
