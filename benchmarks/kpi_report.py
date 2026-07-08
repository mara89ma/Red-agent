#!/usr/bin/env python3
"""KPI 대시보드 — 1~3순위 (방어공백·잔존·임계보정).

    python benchmarks/kpi_report.py

기존 층 원자값을 집계해 레드팀 KPI를 한 화면에 출력. 결정론·무의존(Tier-0).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.kpi import (                                     # noqa: E402
    assessment_quality, calibration, coverage_gap, dwell,
    mea_reliability, mission_impact, mitre_coverage, moe_indicators,
    reattack_efficiency, roe_compliance,
)


def main() -> None:
    print("=== fried-pollack-ai · 레드팀 KPI 대시보드 (1~10순위) ===\n")

    cg = coverage_gap()
    print("① 방어 공백 지표 (Blue Coverage Gap)")
    print(f"   사각지대율      : {cg['blind_spot_ratio']*100:.0f}%  "
          f"({len(cg['blind_spots'])}/{cg['total_scenarios']}) → {', '.join(cg['blind_spots'])}")
    print(f"   회피가능율      : {cg['evadable_ratio']*100:.0f}%  → {', '.join(cg['evadable'])}")
    print(f"   은밀관통 캠페인 : {cg['stealthy_campaign_ratio']*100:.0f}%  "
          f"({len(cg['stealthy_campaigns'])}/{cg['total_campaigns']}) → {', '.join(cg['stealthy_campaigns'])}")

    print("\n② 공격자 잔존 / 탐지까지 단계 (dwell)")
    for cid, steps in dwell().items():
        print(f"   {cid:<5}: {'∞ (미탐지)' if steps is None else f'{steps}단계에서 탐지'}")

    print("\n③ 임계 실측 보정 기여 (Calibration)")
    print(f"   {'룰':<28}{'param':<20}{'실측경계':>9}{'가상값':>9}{'오차':>9}")
    for r in calibration():
        print(f"   {r['rule']:<28}{r['param']:<20}"
              f"{_f(r['measured_boundary']):>9}{_f(r['blue_assumed']):>9}{_f(r['abs_error']):>9}")

    mc = mitre_coverage()
    print("\n④ 시나리오 MITRE 커버리지")
    print(f"   총 기법 {mc['total_techniques']}개 · 프레임워크 {mc['by_framework']} · "
          f"D3FEND 사각 {mc['d3fend_blind_ratio']*100:.0f}%({len(mc['d3fend_blind_actions'])}액션)")

    rc = roe_compliance()
    print("\n⑤ RoE 교리 준수 분포 (액션 " + str(rc['evaluated']) + "개)")
    print(f"   판정 {rc['verdicts']}")
    print(f"   요구권한 {rc['required_authority']}  ·  CDE {rc['cde_tier']}")

    re_ = reattack_efficiency()
    print("\n⑥ 재타격 효율")
    print(f"   달성 {re_['achieved_objectives']}/{re_['total_objectives']} 목표 · "
          f"평균 시도 {re_['avg_attempts_to_achieve']}회/달성")

    print("\n── DoD 교리 보강 KPI (7~10) ──")
    mea = mea_reliability()
    print(f"⑦ MEA(TTP 신뢰성): 전체 {mea['mea_overall']*100:.0f}% · "
          f"jam {mea['per_ttp']['jam']*100:.0f}% / spoof {mea['per_ttp']['gnss_spoof']*100:.0f}%")

    mi = mission_impact()
    print(f"⑧ 임무영향/MRT-C: 임무저하지수 {mi['mission_degradation_index']*100:.0f}% · "
          f"영향 임무효과 {len(mi['affected_mrt_c'])}종")

    moe = moe_indicators()
    print("⑨ MOE 지표계층:")
    print(f"   MOE1 효과: 임무저하 {moe['MOE1_effect_achievement']['mission_degradation_index']}")
    print(f"   MOE2 생존: 사각 {moe['MOE2_survivability']['blind_spot_ratio']} · "
          f"평균 탐지단계 {moe['MOE2_survivability']['avg_steps_to_detection']}")

    aq = assessment_quality()
    print(f"⑩ BDA신뢰 {aq['bda_confidence']} · OPSEC노출 {aq['opsec_exposure_ratio']*100:.0f}% · "
          f"데컨플릭션 위반(샘플) {aq['deconfliction_violations_sampled']}")

    print("\n요약(교리 정합): MOE/MOP·MEA·BDA·임무영향(MRT-C)·CDE/RoE·데컨플릭션까지 "
          "JP 3-60/3-12/5-0 평가 지표를 대부분 커버. 시간지표(MTTD)만 라이브(본선).")


def _f(x) -> str:
    return "-" if x is None else f"{x:g}"


if __name__ == "__main__":
    main()
