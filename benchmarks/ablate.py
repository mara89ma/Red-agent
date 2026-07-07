#!/usr/bin/env python3
"""ablate — 각 방어/검증 컴포넌트의 실제 인과 기여를 측정하는 과학적 자기평가.

T3MP3ST OBSIDIVM `obsidivm-ablate.mjs`("어느 컴포넌트가 실제로 성능을 올리나") 이식.
차이: fried-pollack-ai는 안전-임계 결정론이라 "안전을 꺼서 뭐가 깨지나"를 실제로 돌리지 않고,
게이트가 스스로 남긴 감사 기록에서 **반사실(counterfactual)을 정확히 도출**한다 — 각 컴포넌트가
막은 나쁜 결과의 수를 재현 가능하게 계량한다. 추가로 학습 루프는 실제 A/B(on/off)로 인과
lift가 0임(=관측 전용, 계획에 미반영)을 정직하게 증명한다.

    python -m benchmarks.ablate            # 인과 기여 리더보드
    python -m benchmarks.ablate --json

리더보드가 "earns-keep(N)"이면 그 컴포넌트가 N개의 나쁜 결과를 실제로 막았다는 뜻,
"observational"이면 현재 벤치에서 결과를 바꾸지 않는다는 정직한 신호(개선 로드맵의 근거).
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmarks.harness import (OBJECTIVES, SCENARIOS, _approver,  # noqa: E402
                                _build_profile)
from redteam_core.engagement.gate import Gate  # noqa: E402
from redteam_core.graph.build import build_graph  # noqa: E402
from redteam_core.learning import new_experience_gates, new_target_gate  # noqa: E402
from redteam_core.session import build_initial_state  # noqa: E402
from redteam_core.tools.range_factory import make_range  # noqa: E402


def _run(sc, exp_gate=None, tgt_gate=None) -> dict:
    prof = _build_profile(sc.abstract_action)
    gate = Gate(scope=prof["authorization"], budget=dict(prof["ops"]["budget"]))
    state = build_initial_state(prof, gate, make_range(prof, hardened=sc.hardened),
                                _approver, experience_gate=exp_gate, target_gate=tgt_gate)
    return build_graph().invoke(state)


def measure() -> dict:
    """전 시나리오를 완전-방어로 돌려 각 컴포넌트의 반사실 기여를 도출."""
    oracle_fp = 0            # out-of-band 오라클이 반박한 자기보고 성공(ACK≠state)
    irreversible_gated = 0   # 물리 비가역이 게이트에서 차단된 시나리오 수
    injections = 0           # 중립화된 인젝션 시도(clean 벤치)
    safety_viol = 0

    for sc in SCENARIOS:
        final = _run(sc)
        card = final["scorecard"].summary()
        oracle_fp += card["false_positives_avoided(ACK≠state)"]
        safety_viol += card["physical_safety_violations"]
        if card["milestones"].get("missionkill_capability(gate_reached)"):
            irreversible_gated += 1
        jc = final["report"].get("judge_consensus", {})
        injections += jc.get("injection_attempts", 0)

    # --- 학습 루프 인과 lift: 재engagement 효율(무익 스킵) + 목표 무회귀 검증 ---
    learn = _learning_measure()

    components = [
        {"component": "out_of_band_oracle(D2)",
         "metric": "자기보고 성공을 ground-truth로 반박(FP 방지)",
         "prevented": oracle_fp,
         "verdict": "earns-keep" if oracle_fp > 0 else "observational"},
        {"component": "irreversible_token_gate(M5)",
         "metric": "물리 비가역 액션을 게이트에서 차단(위반 방지)",
         "prevented": irreversible_gated,
         "verdict": "earns-keep" if irreversible_gated > 0 else "observational"},
        {"component": "injection_sanitize(C)",
         "metric": "표적발 프롬프트 인젝션 중립화(clean 벤치)",
         "prevented": injections,
         "verdict": "earns-keep" if injections > 0 else "clean-bench(adversarial 테스트서 검증)"},
        {"component": "learning_loop(B6~B8→planner)",
         "metric": (f"재engagement 무익 스킵 노출절감={learn['exposure_saved']} "
                    f"목표flip={learn['objective_flips']}(0=무회귀)"),
         "prevented": learn["actions_skipped"],
         "verdict": "earns-keep" if learn["actions_skipped"] > 0 else "observational"},
    ]
    return {
        "safety_violations_total": safety_viol,   # 완전-방어에선 0이어야
        "learning_detail": learn,
        "components": components,
    }


def _learning_measure() -> dict:
    """학습→planner 배선의 인과 lift 측정(방어 타깃 재engagement).

    hardened 시나리오를 공유 스토어로 2회 — run1이 trusted-FAIL 학습, run2가 무익 스킵.
    lift = 스킵된 액션 수 + 절감된 탐지 노출. 동시에 목표 결과가 안 바뀜(무회귀)을 검증한다.
    """
    hardened = [sc for sc in SCENARIOS if sc.hardened]
    actions_skipped = 0
    exposure_saved = 0.0
    objective_flips = 0
    for sc in hardened:
        eg, tg = new_experience_gates(), new_target_gate()
        obj = OBJECTIVES.get(sc.abstract_action, lambda f: False)
        r1 = _run(sc, eg, tg)                    # 학습(오라클 검증 FAIL 적재)
        r2 = _run(sc, eg, tg)                    # 적용(무익 스킵)
        actions_skipped += len(r2.get("_skipped_by_learning", []))
        e1 = r1["report"].get("opsec", {}).get("detection_exposure", 0.0)
        e2 = r2["report"].get("opsec", {}).get("detection_exposure", 0.0)
        exposure_saved = round(exposure_saved + max(0.0, e1 - e2), 3)
        if obj(r1) != obj(r2):                   # 목표 결과가 바뀌면 회귀(있으면 안 됨)
            objective_flips += 1
    return {"actions_skipped": actions_skipped, "exposure_saved": exposure_saved,
            "objective_flips": objective_flips}


def main() -> int:
    ap = argparse.ArgumentParser(description="컴포넌트 인과 기여 ablation")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    result = measure()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print("=" * 72)
    print("ablation — 컴포넌트 인과 기여 (완전-방어 반사실 도출)")
    print("=" * 72)
    for c in sorted(result["components"], key=lambda x: x["prevented"], reverse=True):
        print(f"  [{c['verdict']:<38}] {c['component']}")
        print(f"      막은 나쁜 결과={c['prevented']:<4} — {c['metric']}")
    print("=" * 72)
    print(f"완전-방어 물리 안전 위반 총합={result['safety_violations_total']} "
          f"(<-- 0이어야 정상)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
