"""Recolección de métricas en vivo de SIAM (módulo reutilizable).

Mismo módulo drop-in que en CORE OPS: un middleware registra cada request en una
ventana rodante en memoria y de ahí se derivan throughput (rps), percentiles de
latencia (p50/p95/p99) y tasa de error. Se expone en
``GET /v1/metrics/scalability`` para que el panel de praxialabs/admin lo agregue
junto al resto de servicios monitorizados.

Requiere un proceso uvicorn de larga vida (SIAM corre así: `python -m siem.main`,
puerto 8001). En ese modo la ventana agrega tráfico real entre requests.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Any

WINDOW_SECONDS = 300.0
MAX_SAMPLES = 20000


@dataclass
class _Sample:
    ts: float
    latency_ms: float
    status: int
    path: str


class MetricsCollector:
    """Ventana rodante de requests, segura para hilos."""

    def __init__(self, window: float = WINDOW_SECONDS) -> None:
        self._samples: deque[_Sample] = deque(maxlen=MAX_SAMPLES)
        self._lock = Lock()
        self._window = window
        self._total_requests = 0
        self._total_errors = 0

    def record(self, latency_ms: float, status: int, path: str) -> None:
        with self._lock:
            self._samples.append(_Sample(time.monotonic(), latency_ms, status, path))
            self._total_requests += 1
            if status >= 500 or status == 0:
                self._total_errors += 1

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self._window
        while self._samples and self._samples[0].ts < cutoff:
            self._samples.popleft()

    def snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            self._prune_locked(now)
            samples = list(self._samples)
            total_requests = self._total_requests
            total_errors = self._total_errors

        if not samples:
            return {
                "window_seconds": self._window,
                "requests_in_window": 0,
                "rps": 0.0,
                "latency_ms": {"p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0},
                "error_rate": 0.0,
                "errors_in_window": 0,
                "top_paths": [],
                "total_requests": total_requests,
                "total_errors": total_errors,
            }

        latencies = sorted(s.latency_ms for s in samples)
        span = max(now - samples[0].ts, 1e-6)
        errors_in_window = sum(1 for s in samples if s.status >= 500 or s.status == 0)

        path_counts: dict[str, int] = {}
        for s in samples:
            path_counts[s.path] = path_counts.get(s.path, 0) + 1
        top_paths = sorted(path_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]

        return {
            "window_seconds": self._window,
            "requests_in_window": len(samples),
            "rps": round(len(samples) / span, 2),
            "latency_ms": {
                "p50": round(_percentile(latencies, 0.50), 1),
                "p95": round(_percentile(latencies, 0.95), 1),
                "p99": round(_percentile(latencies, 0.99), 1),
                "max": round(latencies[-1], 1),
            },
            "error_rate": round(errors_in_window / len(samples), 4),
            "errors_in_window": errors_in_window,
            "top_paths": [{"path": p, "count": c} for p, c in top_paths],
            "total_requests": total_requests,
            "total_errors": total_errors,
        }


def _percentile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(round(q * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


metrics = MetricsCollector()
