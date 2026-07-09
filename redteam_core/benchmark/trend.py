"""레드팀 KPI 라운드별 추세 — 퍼플팀 갭클로저 투영.

정직: 우리 에이전트는 결정론 단일런이라 '라운드'는 실측 이력이 아니라 **투영**이다.
blue가 사각지대를 임무치명도 순으로 닫으면 KPI가 어떻게 이동하는지(사각비율↓·탐지율↑·
MTTD↓·red 은밀↓) 라운드별로 산출한다. 베이스라인=round 0.
"""
from __future__ import annotations

import math

from ..kpi import coverage_gap

# 사각지대 폐쇄 우선순위(임무 치명도) — 임무핵심부터 blue가 먼저 계측·룰 배포.
_PRIORITY = [
    "S30", "S31",                       # GNSS/C2 재밍(항법·통제 상실) 최우선
    "S32", "S33", "S8",                 # AI 계층(SOC LLM·모델추출·군집)
    "S38", "S35", "S36", "S37",         # 암호키·대량/은닉/스테이징 유출
    "S43", "S44", "S45", "S46",         # RC 링크·DShot 모터
    "S47",                              # anti-forensics
    "S39", "S40", "S41", "S42",         # WiFi 계층
    "S48", "S49", "S50", "S51", "S52",  # Web/Linux 권한상승
    "S53", "S54", "S55",                # archive
]


def _prioritize(blind):
    order = {s: i for i, s in enumerate(_PRIORITY)}
    return sorted(blind, key=lambda s: order.get(s, 999))


def project_rounds(n_rounds: int = 4) -> list:
    """베이스라인(round0) + n 라운드 갭클로저 투영."""
    cg = coverage_gap()
    blind = cg["blind_spots"]
    total = cg["total_scenarios"]
    prioritized = _prioritize(blind)
    batch = math.ceil(len(prioritized) / n_rounds) if n_rounds else len(prioritized)
    rounds, closed = [], set()
    for r in range(n_rounds + 1):
        if r > 0:
            for s in prioritized[(r - 1) * batch: r * batch]:
                closed.add(s)
        remaining = [s for s in blind if s not in closed]
        br = round(len(remaining) / total, 3) if total else 0.0
        rounds.append({
            "round": r,
            "closed": len(closed),
            "remaining_blind": len(remaining),
            "blind_ratio": br,
            "detection_rate": round(1 - br, 3),           # 대략 탐지율
            "red_stealth": round(len(remaining) / max(1, len(blind)), 3),  # red 은밀 잔존
            "mttd_steps": round(1 + 2 * br, 2),           # 사각↓ → 조기 탐지 프록시
        })
    return rounds


def trend_summary(rounds: list) -> dict:
    b, l = rounds[0], rounds[-1]
    return {
        "blind_ratio": (b["blind_ratio"], l["blind_ratio"]),
        "detection_rate": (b["detection_rate"], l["detection_rate"]),
        "mttd_steps": (b["mttd_steps"], l["mttd_steps"]),
        "red_stealth": (b["red_stealth"], l["red_stealth"]),
        "converged": l["remaining_blind"] == 0,
    }


def format_trend(rounds: list) -> str:
    out = ["레드팀 KPI 라운드별 추세 (퍼플팀 갭클로저 투영)", "=" * 52,
           "  R  닫힌사각  잔여사각  사각비율  탐지율  MTTD  red은밀"]
    for x in rounds:
        out.append(f"  {x['round']}   {x['closed']:>3}      {x['remaining_blind']:>3}      "
                   f"{x['blind_ratio']:.2f}    {x['detection_rate']:.2f}   {x['mttd_steps']:.1f}   "
                   f"{x['red_stealth']:.2f}")
    s = trend_summary(rounds)
    out.append(f"\n추세: 사각 {s['blind_ratio'][0]:.0%}→{s['blind_ratio'][1]:.0%} · "
               f"탐지율 {s['detection_rate'][0]:.0%}→{s['detection_rate'][1]:.0%} · "
               f"MTTD {s['mttd_steps'][0]}→{s['mttd_steps'][1]} · "
               f"red은밀 {s['red_stealth'][0]:.0%}→{s['red_stealth'][1]:.0%}")
    out.append("※ 투영(결정론 단일런) — 실측 이력 아님. 우선순위=임무 치명도순 사각 폐쇄.")
    return "\n".join(out)
