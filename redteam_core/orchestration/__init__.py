"""orchestration — 사이버전투임무팀(CMT) 직무 협업.

미군 사이버작전 조직(USCYBERCOM CMF)의 OCO 수행 CMT 로 구조화.
직무(work roles) 협업: MC(Mission Commander) → TDNA(Target Digital Network
Analyst) → ION(Interactive On-Net Operator) → BDA(All-Source/BDA Analyst).
결정론: 각 직무는 기존 층의 조합 래퍼. 판정권은 모델 밖.
"""
from .coordinator import (
    MultiAgentResult, RoleResult, run_cmt_campaign, run_multi_agent_campaign,
)

__all__ = ["MultiAgentResult", "RoleResult", "run_cmt_campaign",
           "run_multi_agent_campaign"]
