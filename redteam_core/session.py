"""엔게이지먼트 초기 상태 팩토리 — run.py/demo.py 공용(중복 제거).

RedTeamState의 채널 스키마를 한 곳에서만 정의한다. 과거엔 run.py와 demo.py가
동일 dict를 각각 복붙해 발산 위험이 있었다.
"""

from __future__ import annotations

from typing import Callable, Optional

from .eval.scorecard import Scorecard
from .learning import new_experience_gates, new_target_gate
from .llm import get_llm_client
from .memory.typed_memory import TypedMemory


def build_initial_state(profile: dict, gate, range_obj, approver: Callable,
                        experience_gate: Optional[object] = None,
                        target_gate: Optional[object] = None,
                        llm_client: Optional[object] = None) -> dict:
    """노드들이 기대하는 전체 채널을 갖춘 초기 RedTeamState를 만든다.

    Args:
        profile:  파싱된 engagement 프로파일(불변).
        gate:     초기화된 Engagement Gate.
        range_obj: 스텁/실 레인지 번들(make_range 산출).
        approver: HITL 콜백(ctx -> "approved"|"denied").
        experience_gate/target_gate: 학습 스토어(B6/B7). 미지정 시 per-run 인메모리.
            엔게이지먼트 간 재사용(자기개선)하려면 동일 객체를 여러 run에 주입한다.
        llm_client: 조언 LLM 클라이언트(B10). 미지정 시 설정 기반 팩토리(기본 Null=무-LLM).
            B5 judge 앙상블이 결정론 오라클 veto 하에 조언으로만 사용한다.
    """
    return {
        "profile": profile,
        "gate": gate,
        "range": range_obj,
        "ptg": {},
        "plan_queue": [],
        "facts": [],
        "memory": TypedMemory(),
        "current_plan": None,
        "checker_verdict": "ok",
        "pending_approval": None,
        "budget": gate.budget,          # gate.budget과 동일 참조(§2.5)
        "audit_log": [],
        "last_validation": None,
        "stop_reason": None,
        "scorecard": Scorecard(),
        "approver": approver,
        "experience_gate": experience_gate or new_experience_gates(),
        "target_gate": target_gate or new_target_gate(),
        "llm_client": llm_client or get_llm_client(),
    }
