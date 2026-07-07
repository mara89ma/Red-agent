"""자기개선 학습 루프 (B7→B6→B8) — pollack-ai actor/experience/outcome 역전 이식.

방어측은 per-adversary 프로파일·경험을 쌓는다. 공격측은 이를 뒤집어 **per-target**
프로파일과 "어떤 playbook/TTP가 이 타깃에 통했는가" 경험을 쌓는다:

    • B7 target_profile — per-target 종단 인텔(관측 방어·시도 기법·playbook 효과 점수).
    • B6 experience    — 게이트·서명·dedup 경험 스토어(비대칭 신뢰: 위험 방향=고신뢰).
    • B8 outcome       — 환경검증(ground-truth) 결과만 durable 학습으로 fan-out.

전부 결정론·인메모리(스토어는 Protocol → 영속 백엔드로 스왑 가능). 판정권은
LLM이 아니라 out-of-band 오라클(validator)에서 온다 — RedTeam 설계 D2와 정합.
"""

from .experience import (  # noqa: F401
    CONFIRMED_FAIL,
    CONFIRMED_SUCCESS,
    INCONCLUSIVE,
    ExperienceRecord,
    MemoryReadGate,
    MemoryWriteGate,
    Sha256Signer,
    new_experience_gates,
)
from .fingerprint import resolve_target_id  # noqa: F401
from .outcome import Observation, ProbeEngine, learn_from_state, recommend  # noqa: F401
from .persistence import (  # noqa: F401
    JsonExperienceStore,
    JsonTargetStore,
    new_persistent_experience_gates,
    new_persistent_target_gate,
)
from .target_profile import TargetProfileGate, new_target_gate  # noqa: F401
