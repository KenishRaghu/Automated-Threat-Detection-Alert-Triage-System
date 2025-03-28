#!/usr/bin/env python3
"""Optional Redis worker: drain triage:jobs for async processing / fan-out."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.queue import dequeue_job, get_redis  # noqa: E402
from app.settings import settings  # noqa: E402


def main() -> None:
    r = get_redis(settings.redis_url)
    print("worker listening on triage:jobs …", flush=True)
    while True:
        job = dequeue_job(r, timeout=30)
        if job:
            print(json.dumps({"handled": job}, default=str), flush=True)


if __name__ == "__main__":
    main()
