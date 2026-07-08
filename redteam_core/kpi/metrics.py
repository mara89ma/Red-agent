"""KPI 집계 — 방어공백·잔존·임계보정 (1~3순위).

원자값 출처:
  - 시나리오 탐지 분류: assessment.rules(action_to_rule) + replan(EFFECT_FLOOR)
  - 캠페인 탐지 프로파일: campaigns.run_chain
  - 임계 보정: assessment.probe_boundary
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..assessment import probe_boundary
from ..assessment.replan import EFFECT_FLOOR
from ..assessment.rules import action_to_rule
from ..campaigns.chains import CHAINS, _SCENARIO_ACTION, _SCENARIO_STATIC, run_chain


def _classify(action: str) -> str:
    """시나리오 대표 액션 → 방어 커버 분류."""
    spec = action_to_rule(action)
    if spec is None:
        return "blind"                                  # blue 미매핑 = 구조적 공백
    if spec.kind == "categorical":
        return "robust"                                 # 항상 탐지(회피 불가)
    floor = EFFECT_FLOOR.get(action, 0.0)
    thr = spec.threshold if spec.threshold is not None else 0.0
    return "evadable" if floor < thr else "detected_only"


# ── 1순위: 방어 공백 지표 ─────────────────────────────────────────────────────
def coverage_gap() -> dict:
    classes: Dict[str, str] = {}
    for sid, (action, _i) in _SCENARIO_ACTION.items():
        classes[sid] = _classify(action)
    for sid, det in _SCENARIO_STATIC.items():
        classes[sid] = "blind" if det is None else "robust"

    total = len(classes)
    blind = [s for s, c in classes.items() if c == "blind"]
    evadable = [s for s, c in classes.items() if c == "evadable"]

    chain_verdicts = {c: run_chain(c).verdict for c in CHAINS}
    stealthy = [c for c, v in chain_verdicts.items() if v == "stealthy"]

    return {
        "scenario_classes": classes,
        "total_scenarios": total,
        "blind_spots": blind,
        "blind_spot_ratio": round(len(blind) / total, 3) if total else 0.0,
        "evadable": evadable,
        "evadable_ratio": round(len(evadable) / total, 3) if total else 0.0,
        "total_campaigns": len(CHAINS),
        "stealthy_campaigns": stealthy,
        "stealthy_campaign_ratio": round(len(stealthy) / len(CHAINS), 3) if CHAINS else 0.0,
    }


# ── 2순위: 잔존/탐지까지 단계(dwell) ─────────────────────────────────────────
def dwell() -> Dict[str, Optional[int]]:
    """캠페인별 첫 탐지까지 단계 수. None = 끝까지 미탐지(∞ 잔존)."""
    out: Dict[str, Optional[int]] = {}
    for cid in CHAINS:
        r = run_chain(cid)
        first = next((i + 1 for i, (_s, _a, d) in enumerate(r.stages) if d is True), None)
        out[cid] = first
    return out


# ── 3순위: 임계 보정 기여 ─────────────────────────────────────────────────────
def calibration() -> List[dict]:
    rows: List[dict] = []
    starts = {"active_scan": 20.0, "spoof_telemetry": 16.0, "gnss_spoof": 0.8}
    for action, start in starts.items():
        rec = probe_boundary(action, start)
        boundary, assumed = rec.boundary, rec.blue_assumed
        err = (round(abs(boundary - assumed), 6)
               if boundary is not None and assumed is not None else None)
        rows.append({
            "rule": rec.rule_id, "param": rec.threshold_param,
            "measured_boundary": boundary, "blue_assumed": assumed, "abs_error": err,
        })
    return rows


def full_report() -> dict:
    return {"coverage_gap": coverage_gap(), "dwell": dwell(), "calibration": calibration()}
