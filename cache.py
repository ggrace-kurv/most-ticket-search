"""Tiny in-memory TTL cache for search results.

Keyed on a stable hash of the filter dict. One process, one cache — fine for
single-worker dev/internal use; do not run multi-worker (each worker would
have its own cache and hammer MOST2).
"""
import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_lock = threading.Lock()
_store: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}


def _key(filters: Dict[str, Any]) -> str:
    canonical = json.dumps(filters, sort_keys=True, default=str)
    return hashlib.sha1(canonical.encode()).hexdigest()


def get(filters: Dict[str, Any], ttl_seconds: int) -> Optional[List[Dict[str, Any]]]:
    if ttl_seconds <= 0:
        return None
    k = _key(filters)
    with _lock:
        entry = _store.get(k)
        if entry is None:
            return None
        stored_at, rows = entry
        if time.time() - stored_at > ttl_seconds:
            _store.pop(k, None)
            return None
        return rows


def put(filters: Dict[str, Any], rows: List[Dict[str, Any]]) -> None:
    k = _key(filters)
    with _lock:
        _store[k] = (time.time(), rows)


def clear() -> None:
    with _lock:
        _store.clear()
