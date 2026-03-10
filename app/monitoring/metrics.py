from collections import defaultdict, deque
from threading import Lock
from typing import Dict


class MetricsStore:
    """
    Thread-safe in-memory metrics store.

    Used for monitoring request statistics, errors,
    blocks, and response time analysis.
    """

    MAX_RESPONSE_SAMPLES = 10_000  # prevent memory growth

    def __init__(self) -> None:
        self._lock = Lock()

        self.total_requests: int = 0
        self.total_errors: int = 0
        self.blocked_requests: int = 0

        self.endpoint_hits: Dict[str, int] = defaultdict(int)
        self.response_times = deque(maxlen=self.MAX_RESPONSE_SAMPLES)

    # =====================================================
    # Record Methods
    # =====================================================

    def record_request(self, path: str) -> None:
        with self._lock:
            self.total_requests += 1
            self.endpoint_hits[path] += 1

    def record_error(self) -> None:
        with self._lock:
            self.total_errors += 1

    def record_block(self) -> None:
        with self._lock:
            self.blocked_requests += 1

    def record_time(self, duration: float) -> None:
        """
        Duration expected in seconds.
        """
        with self._lock:
            self.response_times.append(duration)

    # =====================================================
    # Metrics Summary
    # =====================================================

    def summary(self) -> Dict[str, object]:
        with self._lock:
            if self.response_times:
                avg = sum(self.response_times) / len(self.response_times)
                max_time = max(self.response_times)
                min_time = min(self.response_times)
            else:
                avg = max_time = min_time = 0

            return {
                "total_requests": self.total_requests,
                "total_errors": self.total_errors,
                "blocked_requests": self.blocked_requests,
                "avg_response_time_ms": round(avg * 1000, 2),
                "max_response_time_ms": round(max_time * 1000, 2),
                "min_response_time_ms": round(min_time * 1000, 2),
                "endpoint_hits": dict(self.endpoint_hits),
            }

    # =====================================================
    # Reset Metrics (Optional Admin Use)
    # =====================================================

    def reset(self) -> None:
        with self._lock:
            self.total_requests = 0
            self.total_errors = 0
            self.blocked_requests = 0
            self.endpoint_hits.clear()
            self.response_times.clear()


# Global singleton
metrics = MetricsStore()
