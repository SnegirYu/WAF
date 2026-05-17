"""Sliding-window rate limiter (10 requests / minute per key)."""
from __future__ import annotations

import time
from threading import Lock

from django.conf import settings
from django.core.cache import cache

_LOCAL_BUCKETS: dict[str, list[float]] = {}
_LOCAL_LOCK = Lock()


def _limit() -> int:
    return int(getattr(settings, "API_RATE_LIMIT", 10))


def _window() -> int:
    return int(getattr(settings, "API_RATE_LIMIT_WINDOW", 60))


def _prune(timestamps: list[float], now: float, window: int) -> list[float]:
    cutoff = now - window
    return [ts for ts in timestamps if ts > cutoff]


def _check_local(key: str, now: float, limit: int, window: int) -> bool:
    with _LOCAL_LOCK:
        bucket = _prune(_LOCAL_BUCKETS.get(key, []), now, window)
        if len(bucket) >= limit:
            _LOCAL_BUCKETS[key] = bucket
            return True
        bucket.append(now)
        _LOCAL_BUCKETS[key] = bucket
        return False


def is_rate_limited(key: str) -> bool:
    """
    Returns True when the key exceeded the configured request limit.
    Uses Redis cache when available, otherwise an in-process fallback.
    """
    limit = _limit()
    window = _window()
    now = time.time()
    cache_key = f"rl:{key}"

    try:
        raw = cache.get(cache_key)
        if raw is None:
            cache.set(cache_key, [now], timeout=window + 1)
            return False
        bucket = _prune(list(raw), now, window)
        if len(bucket) >= limit:
            cache.set(cache_key, bucket, timeout=window + 1)
            return True
        bucket.append(now)
        cache.set(cache_key, bucket, timeout=window + 1)
        return False
    except Exception:
        return _check_local(cache_key, now, limit, window)
