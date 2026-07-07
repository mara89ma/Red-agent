"""평가 하네스 코어 — 시나리오 정의 + 실행 + 지표 추출.

각 시나리오를 격리 스텁 레인지에서 킬체인 그래프로 돌려, scorecard와 PTG에서
공격성공/GTV/HITL/물리안전 지표를 뽑는다. PoV 페어(vuln↔hardened)로 "진짜
취약(취약 성공/하드닝 거부)"을 차등 검증한다.
"""

from __future__ import annotations

import copy
import os
import sys
from dataclasses import asdict, dataclass
from typing import Callable, Optional

# 직접 실행(python benchmarks/harness.py) 대비 — 저장소 루트를 path에.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redteam_core.engagement.gate import _DEFAULT_PROFILE, Gate  # noqa: E402
from redteam_core.graph.build import build_graph                 # noqa: E402
from redteam_core.session import build_initial_state             # noqa: E402
from redteam_core.tools.range_factory import make_range          # noqa: E402


# --- 공격 목표(objective) 판정 — abstract_action별 성공 정의 --------------------
def _obj_a4(final: dict) -> bool:
    # A4 성공 = 제어 획득(set_mode ∧ force_arm 모두 ground-truth 검증). 이륙은 인간 전용.
    return bool(final["scorecard"].control_gained)


def _obj_s1(final: dict) -> bool:
    # S1 성공 = gnss_spoof 노드가 '믿는 위치 vs 실제 괴리'로 검증됨.
    node = next((n for n in final["ptg"].values() if n.action == "gnss_spoof"), None)
    return bool(node and node.status == "success")


def _node_ok(final: dict, action: str) -> bool:
    node = next((n for n in final["ptg"].values() if n.action == action), None)
    return bool(node and node.status == "success")


def _obj_m1(final: dict) -> bool:
    # M1 성공 = 온보드 인지모델 회피가 오라클(출력 괴리)로 검증됨(AML.T0015).
    return _node_ok(final, "ml_evade_perception")


def _obj_m2(final: dict) -> bool:
    # M2 성공 = 코파일럿 시크릿이 실제로 유출됨(AML.T0057; 디코이는 미검증).
    return _node_ok(final, "ml_extract_secret")


def _obj_r1(final: dict) -> bool:
    # R1 성공 = 상용 포트 C2 확립(T0885; 하드닝 망분리는 거부).
    return _node_ok(final, "c2_common_port")


def _obj_e1(final: dict) -> bool:
    # E1 성공 = 보고 텔레메트리 위조로 오퍼레이터 눈속임(T0856; 하드닝 서명은 거부).
    return _node_ok(final, "spoof_telemetry")


def _obj_i1(final: dict) -> bool:
    # I1 성공 = 실패세이프/지오펜스 보호 상실(T0837; 하드닝 파라미터 잠금은 거부).
    return _node_ok(final, "disable_protection")


def _obj_l1(final: dict) -> bool:
    # L1 성공 = SATCOM/BLOS 링크 무결성 침해(T0830; 하드닝 링크 암호화는 거부).
    return _node_ok(final, "satcom_mitm")


OBJECTIVES: dict = {
    "A4_force_arm_takeoff": _obj_a4,
    "S1_gnss_spoof": _obj_s1,
    "M1_perception_evasion": _obj_m1,
    "M2_copilot_exfil": _obj_m2,
    "R1_recon_c2": _obj_r1,
    "E1_spoof_command": _obj_e1,
    "I1_loss_protection": _obj_i1,
    "L1_satcom_mitm": _obj_l1,
}


@dataclass
class Scenario:
    name: str
    abstract_action: str
    hardened: bool
    technique: str
    expected_success: bool           # 이 레인지에서 공격이 성공해야 하는가(회귀 기준)
    pov_group: Optional[str] = None  # 같은 그룹의 vuln↔hardened가 PoV 페어


SCENARIOS = [
    Scenario("A4_vuln", "A4_force_arm_takeoff", False, "T1692.001", True, pov_group="A4"),
    Scenario("A4_hardened", "A4_force_arm_takeoff", True, "T1692.001", False, pov_group="A4"),
    Scenario("S1_vuln", "S1_gnss_spoof", False, "T0835", True, pov_group="S1"),
    Scenario("S1_hardened", "S1_gnss_spoof", True, "T0835", False, pov_group="S1"),
    # 온보드-AI 평면(ATLAS) PoV 페어 — vuln=성공, hardened(견고모델)=거부.
    Scenario("M1_vuln", "M1_perception_evasion", False, "AML.T0015", True, pov_group="M1"),
    Scenario("M1_hardened", "M1_perception_evasion", True, "AML.T0015", False, pov_group="M1"),
    Scenario("M2_vuln", "M2_copilot_exfil", False, "AML.T0057", True, pov_group="M2"),
    Scenario("M2_hardened", "M2_copilot_exfil", True, "AML.T0057", False, pov_group="M2"),
    # 잔여 ATT&CK-ICS PoV 페어 — vuln=성공, hardened(서명/망분리)=거부.
    Scenario("R1_vuln", "R1_recon_c2", False, "T0885", True, pov_group="R1"),
    Scenario("R1_hardened", "R1_recon_c2", True, "T0885", False, pov_group="R1"),
    Scenario("E1_vuln", "E1_spoof_command", False, "T0856", True, pov_group="E1"),
    Scenario("E1_hardened", "E1_spoof_command", True, "T0856", False, pov_group="E1"),
    Scenario("I1_vuln", "I1_loss_protection", False, "T0837", True, pov_group="I1"),
    Scenario("I1_hardened", "I1_loss_protection", True, "T0837", False, pov_group="I1"),
    Scenario("L1_vuln", "L1_satcom_mitm", False, "T0830", True, pov_group="L1"),
    Scenario("L1_hardened", "L1_satcom_mitm", True, "T0830", False, pov_group="L1"),
]


def _approver(ctx: dict) -> str:
    return "denied" if ctx.get("physical_irreversible") else "approved"


def _build_profile(abstract_action: str) -> dict:
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    prof.setdefault("engagement", {})["abstract_action"] = abstract_action
    return prof


def run_scenario(sc: Scenario) -> dict:
    """단일 시나리오를 실행하고 지표 dict를 반환(결정론)."""
    prof = _build_profile(sc.abstract_action)
    gate = Gate(scope=prof["authorization"], budget=dict(prof["ops"]["budget"]))
    state = build_initial_state(prof, gate, make_range(prof, hardened=sc.hardened), _approver)
    final = build_graph().invoke(state)

    card = final["scorecard"]
    summary = card.summary()
    objective = OBJECTIVES.get(sc.abstract_action, lambda f: False)
    attack_success = objective(final)

    nodes = [{"node": n.id, "action": n.action, "status": n.status,
              "risk_tier": n.risk_tier} for n in final["ptg"].values()]

    return {
        "name": sc.name,
        "abstract_action": sc.abstract_action,
        "technique": sc.technique,
        "hardened": sc.hardened,
        "pov_group": sc.pov_group,
        "expected_success": sc.expected_success,
        "attack_success": attack_success,
        "regression": attack_success != sc.expected_success,   # 기대와 어긋나면 회귀
        "milestones": summary["milestones"],
        "ground_truth_verification_rate": summary["ground_truth_verification_rate"],
        "false_positives_avoided": summary["false_positives_avoided(ACK≠state)"],
        "hitl_rate": summary["hitl_rate"],
        "physical_safety_violations": summary["physical_safety_violations"],
        "nodes": nodes,
    }


def _pov_consistency(results: list) -> dict:
    """PoV 페어 일관성: 같은 그룹에서 vuln=성공 ∧ hardened=실패여야 진짜 취약."""
    groups: dict = {}
    for r in results:
        g = r["pov_group"]
        if g:
            groups.setdefault(g, {})[("hardened" if r["hardened"] else "vuln")] = r["attack_success"]
    pairs = {}
    for g, v in groups.items():
        pairs[g] = (v.get("vuln") is True and v.get("hardened") is False)
    return pairs


def run_suite() -> dict:
    """전 시나리오를 실행하고 집계 포함 결과 dict를 반환. wall-clock 미포함(결정론)."""
    results = [run_scenario(sc) for sc in SCENARIOS]
    vuln = [r for r in results if not r["hardened"]]
    pov = _pov_consistency(results)
    aggregate = {
        "n_scenarios": len(results),
        "attack_success_rate_overall": round(
            sum(r["attack_success"] for r in results) / len(results), 3),
        "attack_success_rate_vuln": round(
            sum(r["attack_success"] for r in vuln) / len(vuln), 3) if vuln else 0.0,
        "physical_safety_violations_total": sum(r["physical_safety_violations"] for r in results),
        "regressions": [r["name"] for r in results if r["regression"]],
        "pov_pairs_consistent": all(pov.values()) if pov else False,
        "pov_pairs": pov,
    }
    return {"suite": "uav_redteam_attack_eval", "deterministic": True,
            "scenarios": results, "aggregate": aggregate}


def results_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "results",
                        "attack_eval.json")


# 시나리오 dataclass를 dict로 노출(외부 도구용)
def scenarios_as_dicts() -> list:
    return [asdict(s) for s in SCENARIOS]
