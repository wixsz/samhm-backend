from collections import defaultdict
from datetime import datetime
from typing import Dict


class MetricsEngine:

    def __init__(self):
        self.start_time = datetime.utcnow()

        self.counters = defaultdict(int)
        self.endpoints = defaultdict(int)
        self.ips = defaultdict(int)
        self.security_events = defaultdict(int)

    # ---------- Counters ----------
    def inc(self, name: str):
        self.counters[name] += 1

    # ---------- Endpoint tracking ----------
    def track_endpoint(self, path: str):
        self.endpoints[path] += 1

    # ---------- IP tracking ----------
    def track_ip(self, ip: str):
        self.ips[ip] += 1

    # ---------- Security events ----------
    def security(self, event: str):
        self.security_events[event] += 1

    # ---------- Snapshot ----------
    def snapshot(self) -> Dict:
        uptime = datetime.utcnow() - self.start_time

        return {
            "uptime_seconds": int(uptime.total_seconds()),
            "counters": dict(self.counters),
            "top_endpoints": dict(
                sorted(self.endpoints.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "top_ips": dict(
                sorted(self.ips.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "security_events": dict(self.security_events),
        }


metrics_engine = MetricsEngine()
