"""Google's attestation revocation list, kept fresh for the server.

Leaked or revoked factory keys produce chains that look genuine up to Google's root; this list is how they are refused.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from typing import Callable

from .attestation import load_revocations

STATUS_URL = "https://android.googleapis.com/attestation/status"
REFRESH_SECONDS = 12 * 3600
MAX_AGE_SECONDS = 48 * 3600


def fetch_status(url: str = STATUS_URL, timeout: float = 20) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


class RevocationList:
    """Thread-safe cache. `current()` returns None when the list is missing or too old, so callers can fail closed."""

    def __init__(self, source: Callable[[], dict] = fetch_status, max_age: float = MAX_AGE_SECONDS,
                 clock: Callable[[], float] = time.time):
        self._source = source
        self._max_age = max_age
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, str] | None = None
        self._loaded_at = 0.0

    def refresh(self) -> bool:
        try:
            entries = load_revocations(self._source())
        except Exception as e:  # network or parse error: keep the previous list until it is too old
            print(f"[revocation] refresh failed: {e}", flush=True)
            return False
        with self._lock:
            self._entries, self._loaded_at = entries, self._clock()
        return True

    def current(self) -> dict[str, str] | None:
        with self._lock:
            if self._entries is None or self._clock() - self._loaded_at > self._max_age:
                return None
            return self._entries

    def start_background_refresh(self, interval: float = REFRESH_SECONDS) -> threading.Thread:
        def loop():
            while True:
                time.sleep(interval)
                self.refresh()

        thread = threading.Thread(target=loop, name="revocation-refresh", daemon=True)
        thread.start()
        return thread
