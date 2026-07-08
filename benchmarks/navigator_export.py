#!/usr/bin/env python3
"""ATT&CK Navigator 레이어 export — §N 확장.

    python benchmarks/navigator_export.py

ics/enterprise/atlas 3개 도메인 레이어 JSON 을 out/ 에 쓰고 요약 출력.
attack-navigator(https://mitre-attack.github.io/attack-navigator/) 에 import.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.kpi.navigator import build_navigator_layer      # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "out"


def main() -> None:
    OUT.mkdir(exist_ok=True)
    print("=== fried-pollack-ai · ATT&CK Navigator 레이어 export ===\n")
    for domain in ("ics-attack", "enterprise-attack", "atlas"):
        layer = build_navigator_layer(domain)
        path = OUT / f"navigator_{domain}.json"
        path.write_text(json.dumps(layer, ensure_ascii=False, indent=2))
        n = len(layer["techniques"])
        blind = sum(1 for t in layer["techniques"] if t["color"] == "#e74c3c")
        print(f"  {domain:<18}: {n:>2}기법 (사각 {blind}) → {path.relative_to(OUT.parent)}")
    print("\nattack-navigator 에 import 하면 커버리지+탐지상태 히트맵.")


if __name__ == "__main__":
    main()
