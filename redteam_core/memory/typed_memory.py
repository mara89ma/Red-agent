"""(7) 타입화 메모리 (§2.3).

메모리 서베이 2602.06052 / Skill-Pro(절차 메모리) 2602.01869 / FadeMem 2601.18642.
    • episodic  — 표적·호스트별 액션 timestamp 로그.
    • semantic  — 표적 사실(펌웨어·파라미터·geofence). **버전화로 stale 억제**.
    • procedural— 재사용 UAV 킬체인 playbook(효용 테스트 통과분만 편집 게이트).

외부 권위 상태: 표적 사실 저장소가 진짜 상태, LLM엔 스냅샷+최근 k≈10만
(InfiAgent 2601.03204). 생 텔레메트리는 항상 프롬프트 밖 append-only(증거).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class TypedMemory:
    episodic: list = field(default_factory=list)       # [{ts, host, action, ...}]
    semantic: dict = field(default_factory=dict)       # key -> {value, version, ts}
    procedural: dict = field(default_factory=dict)     # playbook_id -> {utility, uses}

    # --- episodic -----------------------------------------------------------
    def record_episode(self, host: str, action: str, outcome: str) -> None:
        self.episodic.append({"ts": time.time(), "host": host,
                              "action": action, "outcome": outcome})

    def recent(self, k: int = 10) -> list:
        return self.episodic[-k:]

    # --- semantic (버전화: 신규가 구식 억제, stale 방지) --------------------
    def set_fact(self, key: str, value) -> None:
        prev = self.semantic.get(key, {"version": 0})
        self.semantic[key] = {"value": value, "version": prev["version"] + 1, "ts": time.time()}

    def get_fact(self, key: str, default=None):
        entry = self.semantic.get(key)
        return entry["value"] if entry else default

    # --- procedural (효용 게이트) ------------------------------------------
    def promote_playbook(self, playbook_id: str, success: bool) -> None:
        p = self.procedural.setdefault(playbook_id, {"utility": 0.0, "uses": 0})
        p["uses"] += 1
        # 성공 시 효용 증가 — 효용 테스트 통과분만 재사용 편집 게이트를 넘는다.
        p["utility"] += 1.0 if success else -0.5
