"""Bucle de jobs para probar en local (`compose.yaml`). En Azure, los cron de Container Apps.

    python -m vs.jobs.loop

Cada `VS_LOOP_INTERVAL` segundos (300): `ingest` y después `publish`. Cada `VS_DAILY_INTERVAL`
segundos (3600): `daily`. Cada job corre en su propio proceso, como un job de Container Apps, y su
código de salida queda en el log. `VS_LOOP_CYCLES` > 0 para después de N ciclos (pruebas).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from vs.jobs.settings import log


def run_job(name: str) -> int:
    started = time.monotonic()
    rc = subprocess.run([sys.executable, "-m", f"vs.jobs.{name}"], check=False).returncode  # noqa: S603
    log("job_exit", job=name, code=rc, seconds=round(time.monotonic() - started, 1))
    return rc


def main() -> int:
    interval = float(os.environ.get("VS_LOOP_INTERVAL", "300"))
    daily_interval = float(os.environ.get("VS_DAILY_INTERVAL", "3600"))
    cycles = int(os.environ.get("VS_LOOP_CYCLES", "0"))
    last_daily: float | None = None
    cycle = 0
    while True:
        start = time.monotonic()
        cycle += 1
        log("cycle_start", cycle=cycle)
        run_job("ingest")
        run_job("publish")
        if last_daily is None or time.monotonic() - last_daily >= daily_interval:
            run_job("daily")
            last_daily = time.monotonic()
        log("cycle_end", cycle=cycle, seconds=round(time.monotonic() - start, 1))
        if cycles and cycle >= cycles:
            return 0
        time.sleep(max(0.0, interval - (time.monotonic() - start)))


if __name__ == "__main__":
    sys.exit(main())
