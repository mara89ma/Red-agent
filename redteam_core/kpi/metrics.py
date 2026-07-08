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


# ── 4순위: 시나리오 MITRE 커버리지 ───────────────────────────────────────────
def mitre_coverage() -> dict:
    """동언님 mapping.attack_d3fend.MAP 기반 기법 커버리지·프레임워크 분포."""
    from ..mapping.attack_d3fend import MAP
    techniques = set()
    for spec in MAP.values():
        techniques.update(spec.get("attack_ics", []))
    ics = sorted(t for t in techniques if t.startswith("T0"))
    enterprise = sorted(t for t in techniques if t.startswith("T1"))
    atlas = sorted(t for t in techniques if t.startswith("AML"))
    blind = [a for a, s in MAP.items() if s.get("blind_spot")]
    return {
        "total_techniques": len(techniques),
        "by_framework": {"ICS": len(ics), "Enterprise": len(enterprise), "ATLAS": len(atlas)},
        "mapped_actions": len(MAP),
        "d3fend_blind_actions": blind,
        "d3fend_blind_ratio": round(len(blind) / len(MAP), 3) if MAP else 0.0,
    }


# ── 5순위: RoE 교리 준수 분포 ─────────────────────────────────────────────────
def roe_compliance() -> dict:
    from ..roe import evaluate_roe, load_roe_profile
    profile = load_roe_profile()
    ground = {"armed": False, "in_flight": False, "alt_rel": 0.0, "mode": "GUIDED"}
    target = {"sysid": 42, "pid": True}
    actions = ["recon_heartbeat", "set_mode", "force_arm", "gnss_spoof", "jam",
               "param_set_safety", "unauthorized_command", "active_scan"]
    verdicts: Dict[str, int] = {"PERMITTED": 0, "ESCALATE": 0, "BLOCKED": 0}
    authorities: Dict[str, int] = {}
    cde: Dict[str, int] = {}
    for a in actions:
        d = evaluate_roe(a, ground, target, profile)
        verdicts[d.verdict.value] = verdicts.get(d.verdict.value, 0) + 1
        authorities[d.required_authority] = authorities.get(d.required_authority, 0) + 1
        cde[d.cde_tier] = cde.get(d.cde_tier, 0) + 1
    return {"evaluated": len(actions), "verdicts": verdicts,
            "required_authority": authorities, "cde_tier": cde}


# ── 6순위: 재타격 효율 ────────────────────────────────────────────────────────
def reattack_efficiency() -> dict:
    from ..assessment import OBJECTIVES, adaptive_engage
    rows: Dict[str, dict] = {}
    total_attempts = 0
    achieved = 0
    for obj in OBJECTIVES:
        r = adaptive_engage(obj)
        attempts = len(r.trace)
        rows[obj] = {"verdict": r.verdict, "attempts": attempts, "winning_ttp": r.winning_ttp}
        if r.verdict == "achieved":
            achieved += 1
            total_attempts += attempts
    return {
        "per_objective": rows,
        "avg_attempts_to_achieve": round(total_attempts / achieved, 2) if achieved else None,
        "achieved_objectives": achieved, "total_objectives": len(OBJECTIVES),
    }


# ── 7순위: MEA (무장효과평가 = TTP 신뢰성) ───────────────────────────────────
def mea_reliability() -> dict:
    """각 TTP가 설계대로 효과를 낸 비율(JP 3-60 MEA). EW는 지오메트리별 반복."""
    from ..emso import plan_emso
    per: Dict[str, float] = {}
    jam_conds = [{"jammer_eirp_dbm": 40, "jammer_dist_m": 100},
                 {"jammer_eirp_dbm": 30, "jammer_dist_m": 800},
                 {"jammer_eirp_dbm": -10, "jammer_dist_m": 20000}]
    jr = [plan_emso("jam", {**c, "signal_eirp_dbm": 16, "signal_dist_m": 20000,
                            "freq_mhz": 2437}).effect.achieved for c in jam_conds]
    per["jam"] = round(sum(jr) / len(jr), 2)
    spoof_conds = [{"spoof_eirp_dbm": 20, "spoof_dist_m": 100},
                   {"spoof_eirp_dbm": 0, "spoof_dist_m": 5000},
                   {"spoof_eirp_dbm": -20, "spoof_dist_m": 20000}]
    sr = [plan_emso("gnss_spoof", {**c, "freq_mhz": 1575.42}).effect.achieved for c in spoof_conds]
    per["gnss_spoof"] = round(sum(sr) / len(sr), 2)
    for t in ("force_arm", "unauthorized_command", "active_scan",
              "ml_prompt_inject", "ml_extract_secret"):
        per[t] = 1.0                                    # 결정론 스텁/범주형 = 설계대로
    return {"per_ttp": per, "mea_overall": round(sum(per.values()) / len(per), 3)}


# ── 8순위: 임무영향 / MRT-C (임무 보증) ──────────────────────────────────────
# 목표 → (임무수준 효과, 임무 중요도). defender 임무를 실제로 저하시켰나.
MISSION_EFFECT = {
    "nav_denial": ("항법 상실(임무 이탈)", 5),
    "nav_jam_denial": ("항법 거부(재밍)", 5),
    "c2_jam_denial": ("통제 상실(통신 거부)", 5),
    "weapon_effect": ("비인가 무장", 5),
    "soc_llm_inject": ("SOC 판단 오염", 4),
    "model_extraction": ("모델 유출", 3),
    "recon_access": ("자격증명 유출", 3),
    "network_recon": ("정찰 노출", 2),
}


def mission_impact() -> dict:
    from ..assessment import adaptive_engage
    rows: Dict[str, dict] = {}
    ach_w = tot_w = 0
    for obj, (effect, crit) in MISSION_EFFECT.items():
        r = adaptive_engage(obj)
        ok = r.verdict == "achieved"
        stealthy = ok and r.trace[-1][2].detected is not True
        rows[obj] = {"mission_effect": effect, "criticality": crit,
                     "achieved": ok, "stealthy": stealthy}
        tot_w += crit
        ach_w += crit if ok else 0
    return {"per_objective": rows,
            "mission_degradation_index": round(ach_w / tot_w, 3) if tot_w else 0.0,
            "affected_mrt_c": [v["mission_effect"] for v in rows.values() if v["achieved"]]}


# ── 9순위: MOE 지표 계층 (JP 5-0) ─────────────────────────────────────────────
def moe_indicators() -> dict:
    cg = coverage_gap()
    mi = mission_impact()
    d = [v for v in dwell().values() if v is not None]
    return {
        "MOE1_effect_achievement": {
            "mission_degradation_index": mi["mission_degradation_index"],
            "affected_mrt_c_count": len(mi["affected_mrt_c"]),
        },
        "MOE2_survivability": {
            "blind_spot_ratio": cg["blind_spot_ratio"],
            "stealthy_campaign_ratio": cg["stealthy_campaign_ratio"],
            "avg_steps_to_detection": round(sum(d) / len(d), 2) if d else None,
        },
    }


# ── 10순위: BDA 신뢰수준 · 데컨플릭션 · OPSEC ────────────────────────────────
def assessment_quality() -> dict:
    from ..roe import check_deconfliction, load_roe_profile
    # BDA 신뢰수준: 범주형=High, 연속=Medium, 사각(미매핑)=Low.
    conf = {"High": 0, "Medium": 0, "Low": 0}
    detected = 0
    total = 0
    for sid, (action, _i) in _SCENARIO_ACTION.items():
        c = _classify(action)
        conf["High" if c in ("robust",) else "Low" if c == "blind" else "Medium"] += 1
        total += 1
        if c in ("robust", "detected_only"):
            detected += 1
    # 데컨플릭션: EW 를 no-strike 표적에 → 위반 집계.
    prof = load_roe_profile()
    viol = 0
    for a in ("jam", "gnss_spoof"):
        r = check_deconfliction(a, {"sysid": 1}, prof)   # sysid 1 = no-strike(우군)
        viol += len(r.conflicts)
    return {
        "bda_confidence": conf,
        "opsec_exposure_ratio": round(detected / total, 3) if total else 0.0,
        "deconfliction_violations_sampled": viol,
    }


def full_report() -> dict:
    return {
        "coverage_gap": coverage_gap(), "dwell": dwell(), "calibration": calibration(),
        "mitre_coverage": mitre_coverage(), "roe_compliance": roe_compliance(),
        "reattack_efficiency": reattack_efficiency(),
        "mea_reliability": mea_reliability(), "mission_impact": mission_impact(),
        "moe_indicators": moe_indicators(), "assessment_quality": assessment_quality(),
    }
