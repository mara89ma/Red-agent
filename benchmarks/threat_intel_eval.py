#!/usr/bin/env python3
"""위협 인텔 연동 데모 — 고도화 §O (TI 프로파일링 + §F 연결).

    python benchmarks/threat_intel_eval.py

위협행위자 프로파일링 + TI 가중 표적 우선순위(JP 2-0→3-60). 결정론·무의존.
실 피드: env TAXII_URL/TAXII_COLLECTION.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.integrations import threat_intel as ti          # noqa: E402


def main() -> None:
    print("=== fried-pollack-ai · 위협 인텔 연동 §O ===\n")
    st = ti.status()
    print(f"① STIX/TAXII: {st['mode']} (시드 위협행위자 {st['actor_seed_count']}명)\n")

    print("② 위협행위자 프로파일 (활성)")
    for actor, spec in ti.THREAT_ACTORS.items():
        print(f"   {actor:<24}{spec['focus']:<22}→ {', '.join(spec['scenarios'])}")

    print("\n③ TI 가중 표적 우선순위 (JP 2-0 정보 → JP 3-60 표적)")
    print(f"   {'표적':<20}{'대표시나리오':<10}{'CARVER':<8}{'활성위협':<8}{'TI점수'}")
    for r in ti.ti_prioritized_targets():
        print(f"   {r['target']:<20}{r['scenario']:<10}{r['carver']:<8}"
              f"{r['active_threats']:<8}{r['ti_score']}")

    print("\n해석: 실 위협(활성 행위자 수)이 표적 가치를 끌어올림 → "
          "여러 행위자가 노리는 자산이 고가치표적(HPT). '정보가 표적을 이끈다'(교리).")


if __name__ == "__main__":
    main()
