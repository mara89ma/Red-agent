"""외부 레드팀 툴(PyRIT/Garak) 통합 seam — 스텁.

pollack-ai의 run_redteam_skeleton.py를 공격측이 '소유'하는 통합 지점으로 이식.
현재 하네스는 결정론 SITL 스텁을 대상으로 하지만, 동일 Protocol 뒤에 실제
PyRIT/Garak 오케스트레이션을 꽂을 수 있다(LLM 계층 레드팀). 여기서는 계약만
정의하고 실제 구동은 미구현(설치·인가 하에서만).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class AttackObjective:
    """공격 목표 1건 — 시나리오 YAML/외부 툴에서 로드 가능."""
    objective_id: str
    technique: str                      # ATT&CK-ICS / ATLAS ID
    pyrit_objective: str = ""           # PyRIT orchestrator 목표 프롬프트(선택)
    garak_probe: str = ""               # Garak probe 이름(선택)
    success_criterion: str = ""         # 사람이 읽는 성공 정의


@dataclass
class AttackResult:
    objective_id: str
    success: bool
    detail: dict = field(default_factory=dict)


@runtime_checkable
class RedTeamTarget(Protocol):
    """공격 대상 어댑터 계약 — SITL 스텁이든 LLM 엔드포인트든 동일 인터페이스."""

    def run_objective(self, objective: AttackObjective) -> AttackResult:
        ...


def pyrit_garak_integration_stub() -> str:
    """실제 PyRIT/Garak 배선 예시(문서용 스텁). 설치·인가 하에서만 활성화.

    예)
        from pyrit.orchestrator import PromptSendingOrchestrator   # 미설치
        from pyrit.prompt_target import PromptChatTarget
        # target = MyRedTeamTarget()  # RedTeamTarget 구현
        # for obj in load_objectives("scenarios.yaml"):
        #     result = target.run_objective(obj)
        #     ...  # ASR/저항률 집계 → harness와 동일 JSON 스키마로 산출
    """
    return ("PyRIT/Garak 통합은 [eval] extra 설치 + 인가 하에서만. "
            "RedTeamTarget Protocol 뒤에 오케스트레이션을 구현하라.")
