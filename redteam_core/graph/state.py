"""RedTeamState / PTG 스키마 (Part 2 §2.2).

PTG(침투 작업 그래프)가 **진짜 메모리**다 — 대화 기록이 아니라 이 그래프에
진행 상태를 외부화한다(VulnBot 2501.13411: PTG 제거 시 실세계 성공률 0).

각 원자 노드는 독립 `risk_tier`·`reversibility`·`physical_state`를 보유한다
(§1.6 추상↔HITL 분리의 핵심 불변식: 한 노드 = 한 등급).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

try:  # py3.8+ Literal는 typing에 존재. 런타임 강제는 아니고 문서화 목적.
    from typing import Literal, TypedDict
except ImportError:  # pragma: no cover
    Literal = None  # type: ignore
    TypedDict = dict  # type: ignore

# --- 결정론 등급 어휘 (safety/reversibility.py가 유일한 판정권) -------------
RiskTier = str          # "read" | "write_lowrisk" | "write_highrisk" | "physical_irreversible"
Reversibility = str     # "reversible" | "semi_reversible" | "irreversible"
ApprovalState = str     # "not_required" | "pending" | "approved" | "denied"
NodeStatus = str        # "open" | "in_progress" | "success" | "failed" | "blocked"


@dataclass
class PTGNode:
    """침투 작업 그래프의 원자 노드. 추상 액션은 이 노드들의 시퀀스로 전개된다."""

    id: str
    task: str
    technique: str = ""                 # ATT&CK-ICS ID (예: "T1692.001")
    action: str = "recon_heartbeat"     # tools/mavlink.py ATOMIC_ACTIONS 키
    status: NodeStatus = "open"
    findings: list = field(default_factory=list)
    deps: list = field(default_factory=list)

    # --- 안전 메타 (UAV 핵심) ---------------------------------------------
    scope_ok: bool = False              # Engagement Gate가 검증한 scope 내 여부
    risk_tier: RiskTier = "read"
    reversibility: Reversibility = "reversible"
    physical_state: dict = field(default_factory=dict)   # {armed, in_flight, alt_rel, mode}
    preconditions: dict = field(default_factory=dict)    # {gps_ready, ekf_ok, geofence}
    approval: ApprovalState = "not_required"

    # --- 검증·감사 --------------------------------------------------------
    expected_effect: dict = field(default_factory=dict)  # Validator가 대조할 주장
    evidence_ref: Optional[str] = None   # append-only 감사 저장소 포인터(텔레메트리 델타)
    rollback_note: Optional[str] = None  # 예: "send RTL(20)"


class RTState(TypedDict, total=False):
    """LangGraph StateGraph 상태 스키마.

    모든 채널은 기본 LastValue(덮어쓰기)다. 그래프가 순차 실행(팬아웃 없음)이라
    리듀서 충돌이 없다. 노드는 자신이 변경한 키를 **반환**해야 채널에 반영된다
    (in-place 변형만으론 직렬화 체크포인터에서 유실될 수 있음).
    """

    profile: Any
    gate: Any
    range: Any
    ptg: Any
    plan_queue: Any
    facts: Any
    memory: Any
    current_plan: Any
    checker_verdict: Any
    pending_approval: Any
    budget: Any
    audit_log: Any
    last_validation: Any
    stop_reason: Any
    scorecard: Any
    approver: Any
    telemetry_window: Any
    report: Any
    _expanded: Any
    _visits: Any
    _hitl_decision: Any
    _executed: Any
    # 진단 채널(노드가 in-place로 쓰는 관측용 키). LangGraph는 미선언 채널을 반환
    # state에서 버리므로 stdlib 러너와 동작이 갈린다 → 반드시 선언해 양쪽을 일치시킨다.
    _abstract_action: Any
    _playbook_reused: Any
    _skipped_by_learning: Any
    _target_recommend: Any
    _new_host: Any
    experience_gate: Any
    target_gate: Any
    llm_client: Any


class RedTeamState(dict):
    """LangGraph StateGraph 상태. 순수 stdlib 러너에서도 dict로 동작한다.

    키:
        profile          — engagement_profile.yaml 파싱본 (불변)
        gate             — engagement.gate.Gate 인스턴스 (비-LLM 신뢰근거)
        range            — tools.sitl_stub.Range (SITL/Gazebo ground-truth + untrusted 텔레메트리)
        ptg              — dict[str, PTGNode]  (진짜 메모리, 채팅 X)
        plan_queue       — list[str]  전개된 원자 노드 id의 실행 대기열 (receding-horizon)
        facts            — list  typed recon 사실 (provenance·confidence·ts)
        memory           — TypedMemory  (episodic/semantic/procedural)
        current_plan     — dict | None   1-step 커밋 (node_id, command, expected_effect ...)
        checker_verdict  — "ok" | "violation"
        pending_approval — str | None  HITL 대기 노드 id
        budget           — dict  {tool_calls, tokens, wallclock_s} 잔량
        audit_log        — list  append-only 외부 감사 (증거)
        last_validation  — dict | None
        stop_reason      — str | None
        approver         — callable(node)->("approved"|"denied")  HITL 콜백
    """
