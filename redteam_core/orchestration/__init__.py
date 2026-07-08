"""orchestration — 멀티에이전트 레드팀 역할 분담 (고도화 §Q).

recon/exploit/C2 역할 에이전트가 각자 담당 층을 호출하며 킬체인을 협업 수행한다
(대화 초기 비전의 실현). 결정론: 각 역할은 기존 층의 조합 래퍼.
  - ReconAgent  : §F 표적개발 + TI 위협행위자 프로파일
  - ExploitAgent: §E 적응교전 + §C EMSO(효과)
  - C2Agent     : §O 연동(C2 채널)·§L 지속
판정권은 여전히 모델 밖(각 역할은 결정론 층 호출).
"""
from .coordinator import MultiAgentResult, RoleResult, run_multi_agent_campaign

__all__ = ["MultiAgentResult", "RoleResult", "run_multi_agent_campaign"]
