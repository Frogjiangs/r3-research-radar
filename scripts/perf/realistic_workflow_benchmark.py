from __future__ import annotations

import argparse
import ctypes
import hashlib
import http.client
import json
import math
import os
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r3radar.utils import atomic_write_text  # noqa: E402
from r3radar.web import RadarHttpServer  # noqa: E402
from tests.fixtures.synthetic_research_workflows import (  # noqa: E402
    seed_synthetic_research_workflows,
)
from tests.test_core import make_settings  # noqa: E402


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percentile) - 1)]


def _windows_rss_bytes() -> int | None:
    if os.name != "nt":
        return None

    class ProcessMemoryCountersEx(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCountersEx()
    counters.cb = ctypes.sizeof(counters)
    get_current_process = ctypes.windll.kernel32.GetCurrentProcess
    get_current_process.restype = ctypes.c_void_p
    get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
    get_process_memory_info.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ProcessMemoryCountersEx),
        ctypes.c_ulong,
    ]
    get_process_memory_info.restype = ctypes.c_int
    process = get_current_process()
    ok = get_process_memory_info(
        process,
        ctypes.byref(counters),
        counters.cb,
    )
    return int(counters.WorkingSetSize) if ok else None


def _request(port: int, path: str) -> tuple[bytes, dict[str, Any]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    connection.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
    response = connection.getresponse()
    body = response.read()
    status = int(response.status)
    connection.close()
    if status != 200:
        raise RuntimeError(f"GET {path} returned HTTP {status}: {body[:300]!r}")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise RuntimeError("expected object response")
    return body, payload


def measure_scale(count: int, repeats: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temporary:
        settings = make_settings(Path(temporary))
        rss_before = _windows_rss_bytes()
        seed_started = time.perf_counter()
        manifest = seed_synthetic_research_workflows(settings, count=count)
        seed_seconds = time.perf_counter() - seed_started
        database_bytes = settings.database_path.stat().st_size

        server = RadarHttpServer(("127.0.0.1", 0), settings)
        port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for _ in range(3):
                _request(port, "/api/works?limit=25")

            bodies: list[bytes] = []
            payloads: list[dict[str, Any]] = []
            durations_ms: list[float] = []
            for _ in range(repeats):
                started = time.perf_counter()
                body, payload = _request(port, "/api/works?limit=25")
                durations_ms.append((time.perf_counter() - started) * 1000.0)
                bodies.append(body)
                payloads.append(payload)
            default_body, default_payload = _request(port, "/api/works")
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        rss_after = _windows_rss_bytes()
        first_payload = payloads[0]
        works = first_payload.get("works") or []
        inline_analysis_count = sum(
            1 for work in works if isinstance(work, dict) and "analysis" in work
        )
        response_bytes = max(map(len, bodies))
        p50_ms = statistics.median(durations_ms)
        p95_ms = _percentile(durations_ms, 0.95)
        hashes = {hashlib.sha256(body).hexdigest() for body in bodies}
        gates = {
            "summary_payload_le_200kb": response_bytes <= 200 * 1024,
            "list_p95_le_750ms": p95_ms <= 750.0,
            "no_inline_analysis": inline_analysis_count == 0,
            "repeat_response_deterministic": len(hashes) == 1,
            "default_page_is_25": int(default_payload.get("limit", -1)) == 25,
            "does_not_default_load_entire_dataset": (
                count <= 25
                or len(default_payload.get("works") or []) < count
            ),
        }
        return {
            "scale": count,
            "fixture": manifest.as_dict(),
            "seed_seconds": round(seed_seconds, 6),
            "database_bytes": database_bytes,
            "requests": {
                "measured_repeats": repeats,
                "path": "/api/works?limit=25",
                "returned_items": len(works),
                "response_bytes_max": response_bytes,
                "p50_ms": round(p50_ms, 3),
                "p95_ms": round(p95_ms, 3),
                "response_hash_count": len(hashes),
                "inline_analysis_count": inline_analysis_count,
                "default_returned_items": len(default_payload.get("works") or []),
                "default_response_bytes": len(default_body),
            },
            "process": {
                "rss_before_bytes": rss_before,
                "rss_after_bytes": rss_after,
                "rss_delta_bytes": (
                    rss_after - rss_before
                    if rss_before is not None and rss_after is not None
                    else None
                ),
            },
            "gates": gates,
            "all_gates_pass": all(gates.values()),
            "dom_nodes": {
                "status": "not_measured_requires_browser_visual_acceptance",
                "reason": "this script intentionally exercises storage and HTTP only",
            },
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Measure R3 list behaviour with long, multi-domain, explicitly "
            "synthetic research workflow records."
        )
    )
    parser.add_argument(
        "--scales",
        default="16,500,1500",
        help="comma-separated dataset sizes (default: 16,500,1500)",
    )
    parser.add_argument("--repeats", type=int, default=15)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        help="write the same generated JSON receipt atomically to this path",
    )
    args = parser.parse_args()
    scales = [int(value.strip()) for value in args.scales.split(",") if value.strip()]
    if args.repeats < 3:
        parser.error("--repeats must be at least 3")

    receipt = {
        "schema": "r3/realistic-workflow-scale-receipt/v1",
        "synthetic_realistic": True,
        "model_calls": 0,
        "network_sources": 0,
        "future_cycle_claim": False,
        "reference_process": {
            "python": sys.version,
            "platform": sys.platform,
        },
        "results": [measure_scale(scale, args.repeats) for scale in scales],
    }
    receipt["all_gates_pass"] = all(
        result["all_gates_pass"] for result in receipt["results"]
    )
    rendered = json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output is not None:
        atomic_write_text(args.output.resolve(), rendered + "\n")
    print(rendered)
    return 1 if args.strict and not receipt["all_gates_pass"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
