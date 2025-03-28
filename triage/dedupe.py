"""In-memory deduplication window (per process). Production would use Redis TTL."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class DedupeStore:
    window: timedelta = field(default_factory=lambda: timedelta(minutes=30))
    _seen: dict[str, datetime] = field(default_factory=dict)

    def check_duplicate(self, fingerprint: str) -> str | None:
        now = datetime.now(timezone.utc)
        cutoff = now - self.window
        stale = [k for k, t in self._seen.items() if t < cutoff]
        for k in stale:
            del self._seen[k]
        if fingerprint in self._seen:
            return fingerprint
        self._seen[fingerprint] = now
        return None

    def clear(self) -> None:
        self._seen.clear()
