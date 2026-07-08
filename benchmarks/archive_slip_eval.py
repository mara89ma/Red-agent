#!/usr/bin/env python3
"""아카이브 경로순회(Zip Slip) 데모 — 신규 S39~S41 + §T 탐지.

    python benchmarks/archive_slip_eval.py

red 가 악성 아카이브(§N) 제작 → §T 샌드박스가 추출 전 escape 탐지. 결정론·무의존.
"""
from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.payloads import (                                          # noqa: E402
    craft_zip_slip, craft_zip_absolute, craft_tar_symlink, craft_tar_slip,
)
from redteam_core.sandbox import detonate_archive                            # noqa: E402


def _benign_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("firmware.bin", b"ok")
        z.writestr("manifest.json", b"{}")
    return buf.getvalue()


CASES = [
    ("S39 Zip Slip(../)", craft_zip_slip()),
    ("S41 절대경로", craft_zip_absolute()),
    ("S40 tar symlink 탈출", craft_tar_symlink()),
    ("S39 tar ../(안전param)", craft_tar_slip()),
]


def main():
    print("=== fried-pollack-ai · 아카이브 경로순회(S39~S41) + §T 탐지 ===\n")
    for label, p in CASES:
        r = detonate_archive(p.data, p.fmt)
        mark = {"malicious": "🔴", "benign": "🟢"}[r.verdict]
        print(f"{mark} [{label}] {r.verdict} · 봉인={r.contained}")
        print(f"     엔트리: {r.entries}")
        print(f"     탈출: {r.escaping}  ← {p.note}\n")

    r = detonate_archive(_benign_zip(), "zip")
    print(f"🟢 [정상 펌웨어 아카이브] {r.verdict} · 탈출 없음\n")

    print("판정: red 악성 아카이브의 경로순회/심링크 탈출을 §T가 추출 전 봉인·탐지.")
    print("      blue Sentinel 룰 사각지대(파일추출) → §T 샌드박스가 방어 seam.")


if __name__ == "__main__":
    main()
