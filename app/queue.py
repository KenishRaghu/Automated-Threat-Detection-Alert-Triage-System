"""Redis-backed job queue for asynchronous triage/orchestration."""

from __future__ import annotations

import json
from typing import Any

import redis

QUEUE_KEY = "triage:jobs"


def get_redis(url: str) -> redis.Redis:
    return redis.from_url(url, decode_responses=True)


def enqueue_job(r: redis.Redis | None, payload: dict[str, Any]) -> bool:
    if r is None:
        return False
    try:
        r.rpush(QUEUE_KEY, json.dumps(payload))
        return True
    except redis.RedisError:
        return False


def dequeue_job(r: redis.Redis, timeout: int = 5) -> dict[str, Any] | None:
    item = r.blpop(QUEUE_KEY, timeout=timeout)
    if not item:
        return None
    _, raw = item
    return json.loads(raw)
