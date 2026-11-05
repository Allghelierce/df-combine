"""JSON from untrusted sources (firmware containers, the sandbox's manifest, tool output).

Python's ``json`` accepts ``NaN``, ``Infinity`` and ``-Infinity``, turns ``1e999`` into ``inf``, and
refuses integers of more than 4,300 digits with a ValueError. A non-finite float that reaches the
API breaks every response that includes it (Starlette's JSON responses reject them), and the
integer limit would make a whole ``.px4`` container unreadable, leaving its image unanalysed. Here
those values parse as ``None`` instead, so the rest of the document is kept.
"""
from __future__ import annotations

import json
import math
from typing import Any

MAX_INT_DIGITS = 40  # far beyond any size, address or ID in firmware metadata


def _float(text: str) -> float | None:
    v = float(text)
    return v if math.isfinite(v) else None


def _int(text: str) -> int | None:
    return int(text) if len(text) - text.startswith("-") <= MAX_INT_DIGITS else None


def _constant(_name: str) -> None:
    return None


def loads(data: str | bytes | bytearray) -> Any:
    """Like ``json.loads`` (same errors, including RecursionError for absurd nesting), but NaN, infinities,
    overflowing floats and over-long integers become ``None``."""
    return json.loads(data, parse_float=_float, parse_int=_int, parse_constant=_constant)


def finite(obj: Any) -> Any:
    """Copy of a JSON-like value with non-finite floats replaced by ``None`` (for values that did not come
    through ``loads``, e.g. computed ones). Iterative, so nesting depth is not limited by recursion."""
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if not isinstance(obj, (dict, list, tuple)):
        return obj
    root: list[Any] = [None]
    stack: list[tuple[Any, Any, Any]] = [(obj, root, 0)]
    while stack:
        src, parent, key = stack.pop()
        if isinstance(src, dict):
            out: Any = {}
            items = src.items()
        elif isinstance(src, (list, tuple)):
            out = [None] * len(src)
            items = enumerate(src)
        else:
            parent[key] = (src if math.isfinite(src) else None) if isinstance(src, float) else src
            continue
        parent[key] = out
        for k, v in items:
            out[k] = v  # nested values are replaced in place below, so dict order is kept
            if isinstance(v, (dict, list, tuple, float)):
                stack.append((v, out, k))
    return root[0]
