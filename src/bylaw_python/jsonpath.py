# Bylaw ALCV — minimal dotted-path extractor for evidence field mapping.
#
# Supports paths like ``result.dob``, ``args.customer_id``, ``data.items[0].id``.
# Intentionally tiny: no external dependency. A richer JSONPath engine
# (jsonpath-ng) can be swapped in later behind ``extract_path``.

from __future__ import annotations

import re
from typing import Any

_SEGMENT = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def extract_path(root: Any, path: str) -> Any:
    """Resolve a dotted/indexed *path* against *root*, or return ``None``.

    ``root`` is typically ``{"args": {...}, "result": {...}}``. Missing keys,
    out-of-range indices, and type mismatches all yield ``None`` rather than
    raising — extraction must never break the agent's tool call.
    """
    if not path:
        return None
    current = root
    for name, index in _SEGMENT.findall(path):
        if current is None:
            return None
        if name:
            if isinstance(current, dict):
                current = current.get(name)
            else:
                current = getattr(current, name, None)
        else:  # index
            i = int(index)
            if isinstance(current, (list, tuple)) and 0 <= i < len(current):
                current = current[i]
            else:
                return None
    return current
