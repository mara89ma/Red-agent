#!/usr/bin/env python3
"""교리 5종 확장 데모 — JADC2·Mosaic·OODA·Information·MissionCommand.

    python benchmarks/doctrine5_eval.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.information import REPORT_TARGETS, attack_reporting_chain   # noqa: E402
from redteam_core.jadc2 import mesh_degradation_test, multi_sensor_consistency_attack  # noqa: E402
from redteam_core.mission_command import MissionProfile, run_mission_command  # noqa: E402
from redteam_core.mosaic import attack_recombination_logic, verify_judge_independence  # noqa: E402
from redteam_core.ooda import ooda_race, orient_phase_denial                  # noqa: E402


def main() -> None:
    print("=== 교리 5종 반영: 결정평면(decision-plane) 공격 ===\n")

    print("① JADC2 융합 레이어 공격")
    fp = multi_sensor_consistency_attack({a: 0.6 for a in
        ("gnss", "imu", "telemetry", "datalink", "eo_ir")}, "false_positive")
    print(f"   다중센서 정합성(FP): 개별미탐={fp.individually_stealthy} 상관합={fp.corr_sum} → {fp.note}")
    m = mesh_degradation_test(5, 4)
    print(f"   메시 저하(5링크 중 4절단): {m.verdict}")

    print("\n② Mosaic 재조합 로직 + judge 독립성(실 introspection)")
    ind = verify_judge_independence()
    print(f"   실 judge: veto={ind.veto_judges} 조언={ind.advisory} common-mode={ind.common_mode}")
    print(f"   → {ind.note[:90]}")
    rc = attack_recombination_logic("evidence")
    print(f"   evidence 오염: 영향받는 조언={rc.affected_judges} · veto보존={rc.veto_preserves}")

    print("\n③ OODA — Orient 마비 + 속도경쟁")
    od = orient_phase_denial(3)
    print(f"   Orient denial: 불확실성={od.uncertainty} 마비={od.orient_paralyzed} ({od.reframed_from} 재프레임)")
    rr = ooda_race(2.0, 5.0)
    print(f"   속도경쟁: 승자={rr.winner} · {rr.note}")

    print("\n④ Information(7번째 합동기능) — 리포팅/증거체인")
    for sid, meta in REPORT_TARGETS.items():
        r = attack_reporting_chain(sid, integrity_signed=False)
        print(f"   {sid} {meta['name']:<16} 통과={r.success} ({meta['goal']})")

    print("\n⑤ 임무형 지휘 — 사람 1회 프로필 → 자율 지휘")
    prof = MissionProfile("항법거부+정찰(은밀)", ["nav_denial", "recon"],
                          roe_ceiling=2, require_stealth=True)
    mr = run_mission_command(prof)
    print(f"   의도: {mr.intent} · 자율수행={mr.autonomous} · 최종상태달성={mr.end_state_achieved}")
    for d in mr.decisions:
        print(f"     - {d.objective:<16} [{d.action}] {d.verdict} · {d.rationale}")
    # RoE 상한 초과 자율 보류 예
    mr2 = run_mission_command(MissionProfile("무장", ["weapon_effect"], roe_ceiling=1))
    print(f"   (무장 요청, 상한1) → {mr2.decisions[0].action}: {mr2.decisions[0].rationale}")

    print("\n핵심: 개별 센서·판정이 아니라 '융합·재조합·Orient·기록·지휘' 결정평면을 노림.")


if __name__ == "__main__":
    main()
