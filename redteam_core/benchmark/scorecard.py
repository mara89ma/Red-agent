"""레드팀 KPI 벤치마크 스코어카드 — 흩어진 10개 KPI를 7카테고리로 집계·채점.

kpi_scorecard() 한 번 실행 → 카테고리별 headline 지표 + 목표대비 rating(우수/양호/주의).
벤더/SW 종속 0(전부 §P KPI 결정론 산출). 발표용 헤드라인 3줄 포함.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..kpi import (
    assessment_quality, coverage_gap, dwell, mea_reliability, mission_impact,
    mitre_coverage, moe_indicators, reattack_efficiency, roe_compliance,
)
from .targets import TARGETS


@dataclass
class Metric:
    kpi: str
    value: float
    target: float
    higher_better: bool
    rating: str
    source: str = ""


def _rate(v: float, target: float, higher_better: bool = True) -> str:
    if higher_better:
        return "우수" if v >= target else "양호" if v >= 0.7 * target else "주의"
    return "우수" if v <= target else "양호" if v <= 1.3 * target else "주의"


def _m(kpi, value, target_key) -> Metric:
    """근거화 목표(targets.TARGETS)로 채점 — target·방향·출처를 정박."""
    t = TARGETS[target_key]
    v = round(float(value), 3)
    return Metric(kpi, v, t["value"], t["higher_better"],
                  _rate(v, t["value"], t["higher_better"]), t["source"])


def kpi_scorecard() -> dict:
    mi = mission_impact()["per_objective"]
    achieved = [o for o, d in mi.items() if d.get("achieved")]
    stealthy = [o for o, d in mi.items() if d.get("stealthy")]
    asr = len(achieved) / len(mi) if mi else 0.0
    stealth_rate = len(stealthy) / len(achieved) if achieved else 0.0

    cg = coverage_gap()
    moe = moe_indicators()
    mc = mitre_coverage()
    roe = roe_compliance()
    aq = assessment_quality()
    re = reattack_efficiency()["per_objective"]
    dw = dwell()

    # 파생 지표
    md = moe["MOE1_effect_achievement"]["mission_degradation_index"]
    mea = mea_reliability()["mea_overall"]
    blind = cg["blind_spot_ratio"]
    d3f = mc.get("d3fend_blind_ratio", 0.0)
    avg_steps = moe["MOE2_survivability"]["avg_steps_to_detection"]
    undetected = [k for k, v in dw.items() if v is None]
    undetected_rate = len(undetected) / len(dw) if dw else 0.0
    attempts = [d["attempts"] for d in re.values() if isinstance(d.get("attempts"), int)]
    avg_attempts = sum(attempts) / len(attempts) if attempts else 0.0
    blocked = roe["verdicts"].get("BLOCKED", 0)
    opsec = aq["opsec_exposure_ratio"]
    bda = aq["bda_confidence"]
    hi_conf = bda.get("High", 0) / max(1, sum(bda.values()))

    categories = [
        {"key": "effectiveness", "title": "효과성 (MOE)", "metrics": [
            _m("Attack Success Rate", asr, "attack_success_rate"),
            _m("Mission Degradation (MOE1)", md, "mission_degradation"),
            _m("MEA 신뢰도", mea, "mea_reliability"),
        ]},
        {"key": "stealth", "title": "은밀성·회피 (Evasion)", "metrics": [
            _m("실행 은밀 관통율", stealth_rate, "stealth_rate"),
            _m("방어 사각 비율(적 기회)", blind, "blind_spot_ratio"),
            _m("D3FEND 미대응 비율", d3f, "d3fend_blind_ratio"),
        ]},
        {"key": "mttd_dwell", "title": "탐지시간·체류 (MTTD/Dwell)", "metrics": [
            _m("평균 체류(탐지까지 단계)", avg_steps, "mttd_steps"),
            _m("미탐지 관통율(dwell=∞)", undetected_rate, "undetected_rate"),
        ]},
        {"key": "reattack", "title": "재타격 효율 (OODA)", "metrics": [
            _m("목표당 평균 시도수", avg_attempts, "reattack_attempts"),
        ]},
        {"key": "coverage", "title": "커버리지 (ATT&CK)", "metrics": [
            _m("MITRE 기법 수", mc["total_techniques"], "mitre_techniques"),
        ]},
        {"key": "compliance", "title": "RoE·OPSEC 통제", "metrics": [
            _m("비가역 차단 건수(BLOCKED)", blocked, "roe_blocked"),
            _m("OPSEC 노출 비율", opsec, "opsec_exposure"),
        ]},
        {"key": "assessment", "title": "평가 신뢰 (BDA)", "metrics": [
            _m("BDA 고신뢰 비율", hi_conf, "bda_high_conf"),
        ]},
    ]

    counts = {"우수": 0, "양호": 0, "주의": 0}
    for c in categories:
        for m in c["metrics"]:
            counts[m.rating] += 1
    overall = "우수" if counts["주의"] == 0 and counts["우수"] >= counts["양호"] else \
              "주의" if counts["주의"] >= 3 else "양호"

    headline = [
        f"은밀성: 방어 사각 {blind:.0%} · 은밀 관통 {stealth_rate:.0%} — 대부분 탐지 없이 성공",
        f"효과성: 임무저하 {md:.3f} · MEA {mea:.3f} — 효과 재현성 높음",
        f"통제: 비가역(무장) {blocked}건 RoE 차단 — 권한 게이트 작동",
    ]
    return {"categories": categories, "counts": counts, "overall": overall,
            "headline": headline}


def format_scorecard(sc: dict) -> str:
    out = ["레드팀 KPI 벤치마크 스코어카드", "=" * 52]
    for c in sc["categories"]:
        out.append(f"\n[{c['title']}]")
        for m in c["metrics"]:
            arrow = "↑" if m.higher_better else "↓"
            out.append(f"  {m.kpi:<24} {m.value:<8} (목표{arrow}{m.target})  {m.rating}")
    out.append(f"\n종합: {sc['overall']}  "
               f"(우수 {sc['counts']['우수']}·양호 {sc['counts']['양호']}·주의 {sc['counts']['주의']})")
    out.append("\n헤드라인:")
    out += [f"  • {h}" for h in sc["headline"]]
    out.append("\n목표 근거(출처):")
    seen = set()
    for c in sc["categories"]:
        for m in c["metrics"]:
            if m.source and m.source not in seen:
                seen.add(m.source)
                out.append(f"  - {m.source}")
    return "\n".join(out)
