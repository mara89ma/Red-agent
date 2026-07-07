#!/usr/bin/env python3
"""데모: A4 평문 인젝션 킬체인 — 무인증 5790 → 제어 획득 → (게이트 도달)미션킬 능력.

의존성 없이 순수 stdlib로 실행된다(langgraph/pydantic/pyyaml 미설치여도 OK).

    python demo.py

보여주는 것:
  1) Engagement Gate(비-LLM)가 scope/sysid/예산/토큰을 강제.
  2) 추상 액션 hijack이 원자 노드(set_mode→force_arm→takeoff)로 전개.
  3) 각 원자 노드가 실행 직전 라이브 상태로 재분류(TOCTOU) → 물리 비가역은 인간 전용.
  4) Validator가 ACK가 아닌 Gazebo ground truth로 효과 검증(ACK≠상태).
  5) PoV 페어레인지: 취약 인스턴스 성공 / 하드닝 인스턴스 거부.
  6) 물리 안전 위반율 = 0 (takeoff는 실집행 안 됨, 게이트 도달로만 능력 증명).
"""

from __future__ import annotations

import json
import os

from redteam_core.engagement.gate import load_gate
from redteam_core.graph.build import build_graph
from redteam_core.session import build_initial_state
from redteam_core.tools.range_factory import make_range

PROFILE = os.path.join(os.path.dirname(__file__), "engagement_profile.yaml")


def demo_approver(ctx):
    """데모 HITL 콜백(ctx=_hitl_context). 물리 비가역은 인간 전용 → 자동대응 보류(안전)."""
    if ctx.get("physical_irreversible"):
        return "denied"        # force-term/takeoff/비행중disarm = 인간 전용 hard
    return "approved"          # write_highrisk(force_arm 등)는 승인


def build_state(hardened: bool):
    gate, profile = load_gate(PROFILE)
    return build_initial_state(profile, gate,
                               make_range(profile, hardened=hardened),  # 스텁↔실SITL 자동 스왑
                               demo_approver)


def run(hardened: bool) -> dict:
    state = build_state(hardened)
    graph = build_graph()          # 기본 LangGraph(interrupt HITL), 미설치면 stdlib 폴백
    state = graph.invoke(state)
    return state


def main():
    print("=" * 72)
    print("UAV RedTeam Agent — A4 force-arm/takeoff 킬체인 (uav-sim-env / KUS-FS)")
    print("=" * 72)

    vuln = run(hardened=False)
    report = vuln["report"]

    print("\n[킬체인 원자 노드 결과]")
    for f in report["findings"]:
        print(f"  {f['node']:>3} {f['action']:<16} status={f['status']:<8} "
              f"tier={f['risk_tier']:<22} {','.join(f['attack_ics'])}")

    print("\n[탐지격차 1순위 (D3FEND 미커버 → custom)]")
    for b in report["detection_gap_priority"] or [{"note": "(없음)"}]:
        print(f"  - {b}")

    print("\n[핵심 권고]")
    print(" ", report["key_recommendation"])

    print("\n[스코어카드]")
    print(json.dumps(report["scorecard"], ensure_ascii=False, indent=2))

    # --- PoV 페어레인지 차등 (§2.9 M3) -----------------------------------
    hard = run(hardened=True)
    vuln_arm = _arm_verified(vuln)
    hard_arm = _arm_verified(hard)
    print("\n[PoV 페어레인지 — force_arm 차등]")
    print(f"  취약 인스턴스(ARMING_CHECK=0·무서명): arm_verified={vuln_arm}")
    print(f"  하드닝 인스턴스(서명 ON·ARMING_CHECK=1): arm_verified={hard_arm}  "
          f"(ACK=ACCEPTED이나 sim ground truth 무장 아님 → 오탐 회피)")
    print(f"  => is_real_vuln = {vuln_arm and not hard_arm}")

    violations = report["scorecard"]["physical_safety_violations"]
    print("\n" + "=" * 72)
    print(f"물리 안전 위반율: {violations}  ->  {'PASS ✅' if violations == 0 else 'FAIL ❌'}")
    print("미션킬 능력: 인간 전용 HITL 게이트 '도달'로 증명(실집행 아님, §2.9 achieved-state)")
    print("=" * 72)


def _arm_verified(state) -> bool:
    for node in state["ptg"].values():
        if node.action == "force_arm":
            return node.status == "success"
    return False


if __name__ == "__main__":
    main()
