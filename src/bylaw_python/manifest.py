# Bylaw ALCV — Manifest Layer
# Schema, loading, and pattern matching for config-driven auto-instrumentation.

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MANIFEST_FILENAMES = ("bylaw.yaml", "bylaw.yml", "bylaw.json")


@dataclass(frozen=True)
class ManifestRule:
    """A single enforcement rule declared in the manifest.

    Attributes:
        tool: Glob pattern matched against function names (e.g. ``"stripe_*"``).
        policy_id: Policy to enforce for matching tools.
        context: Extra key/value pairs forwarded to the clearance request context.
    """

    tool: str
    policy_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def matches(self, name: str) -> bool:
        """Return ``True`` if *name* matches this rule's glob pattern."""
        return fnmatch.fnmatch(name, self.tool)


@dataclass
class Manifest:
    """Parsed enforcement manifest.

    Contains an ordered list of :class:`ManifestRule` objects.  Rules are
    evaluated in declaration order — the first match wins.
    """

    rules: list[ManifestRule]
    source: str = "<inline>"

    def match(self, name: str) -> ManifestRule | None:
        """Return the first rule whose pattern matches *name*, or ``None``."""
        for rule in self.rules:
            if rule.matches(name):
                return rule
        return None

    def __repr__(self) -> str:
        return f"Manifest(rules={len(self.rules)}, source={self.source!r})"


def load_manifest(
    source: str | Path | dict[str, Any] | None = None,
) -> Manifest:
    """Load an enforcement manifest from a file, an inline dict, or auto-discovery.

    Supported file formats:

    * **YAML** (``.yaml`` / ``.yml``) — requires ``pyyaml`` (``pip install pyyaml``
      or ``pip install 'bylaw-python[yaml]'``)
    * **JSON** (``.json``) — no extra dependencies

    When *source* is ``None`` the function searches the current working
    directory for ``bylaw.yaml``, ``bylaw.yml``, then ``bylaw.json`` in
    that order.

    Manifest schema::

        enforce:
          - tool: "stripe_*"
            policy_id: "financial-high-risk"
          - tool: "db_write*"
            policy_id: "data-mutation"
            context:
              risk_level: "high"
          - tool: "*"               # catch-all (optional)
            policy_id: "default"

    Args:
        source: File path, inline ``dict``, or ``None`` for auto-discovery.

    Returns:
        Parsed :class:`Manifest`.

    Raises:
        FileNotFoundError: If *source* is ``None`` and no manifest file exists,
            or if an explicit path does not exist.
        ImportError: If a YAML file is given but ``pyyaml`` is not installed.
        ValueError: If the file extension is not ``.yaml``, ``.yml``, or ``.json``.
    """
    if source is None:
        path = _find_default_manifest()
        data = _parse_file(path)
        src_label = str(path)
    elif isinstance(source, dict):
        data = source
        src_label = "<inline>"
    else:
        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"Bylaw manifest not found: {path}")
        data = _parse_file(path)
        src_label = str(path)

    rules = [
        ManifestRule(
            tool=entry["tool"],
            policy_id=entry.get("policy_id"),
            context=entry.get("context") or {},
        )
        for entry in data.get("enforce", [])
    ]
    return Manifest(rules=rules, source=src_label)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_default_manifest() -> Path:
    cwd = Path.cwd()
    for name in MANIFEST_FILENAMES:
        candidate = cwd / name
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "No Bylaw manifest found in the current directory. "
        f"Create one of: {', '.join(MANIFEST_FILENAMES)}"
    )


def _parse_file(path: Path) -> dict[str, Any]:
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to load YAML manifests. "
                "Install it with: pip install pyyaml  "
                "or: pip install 'bylaw-python[yaml]'"
            ) from exc
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    raise ValueError(
        f"Unsupported manifest format: {path.suffix!r}. "
        "Use .yaml, .yml, or .json."
    )
