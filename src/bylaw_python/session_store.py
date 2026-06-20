# Bylaw ALCV — Session Evidence Store
#
# Keeps the mapping (session, customer, field) -> fact_id so the SDK can carry
# fact references into check-action calls WITHOUT ever exposing fact IDs to the
# agent's reasoning loop. Also tracks active obligations per (session, customer)
# so they can be carried forward and violations prevented.
#
# V0 backing is in-memory (this module). The `SessionEvidenceStore` protocol is
# the seam for a future Redis/Postgres backing for multi-worker / hosted runs.

from __future__ import annotations

import threading
from typing import Protocol


def _key(session_id: str, customer_id: str) -> str:
    return f"{session_id}\x1f{customer_id}"


class SessionEvidenceStore(Protocol):
    """Pluggable per-session evidence store."""

    def put_fact(self, session_id: str, customer_id: str, field: str, fact_id: str) -> None: ...

    def get_fact(self, session_id: str, customer_id: str, field: str) -> str | None: ...

    def fact_ids(
        self, session_id: str, customer_id: str, fields: list[str] | None = None
    ) -> list[str]: ...

    def add_obligations(self, session_id: str, customer_id: str, codes: list[str]) -> None: ...

    def obligations(self, session_id: str, customer_id: str) -> set[str]: ...


class InMemorySessionStore:
    """Thread-safe in-memory :class:`SessionEvidenceStore` (V0 default)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> {field: fact_id}
        self._facts: dict[str, dict[str, str]] = {}
        # key -> set[obligation_code]
        self._obligations: dict[str, set[str]] = {}

    def put_fact(self, session_id: str, customer_id: str, field: str, fact_id: str) -> None:
        with self._lock:
            self._facts.setdefault(_key(session_id, customer_id), {})[field] = fact_id

    def get_fact(self, session_id: str, customer_id: str, field: str) -> str | None:
        with self._lock:
            return self._facts.get(_key(session_id, customer_id), {}).get(field)

    def fact_ids(
        self, session_id: str, customer_id: str, fields: list[str] | None = None
    ) -> list[str]:
        with self._lock:
            mapping = self._facts.get(_key(session_id, customer_id), {})
            if fields is None:
                return list(mapping.values())
            return [mapping[f] for f in fields if f in mapping]

    def add_obligations(self, session_id: str, customer_id: str, codes: list[str]) -> None:
        if not codes:
            return
        with self._lock:
            self._obligations.setdefault(_key(session_id, customer_id), set()).update(codes)

    def obligations(self, session_id: str, customer_id: str) -> set[str]:
        with self._lock:
            return set(self._obligations.get(_key(session_id, customer_id), set()))
