"""OPSEC 스텔스 노출 예산 (B) — 공격측 자기 탐지가능성 모델링.

T3MP3ST `OpsecController` 이식(공격판): 킬체인이 누적하는 **예상 탐지 노출**을 스텔스
레벨별 예산과 대조해 초과 시 abort를 권고한다. 노출 산정은 **공격측 자기지식**만 쓴다 —
각 액션의 `mapping.attack_d3fend` blind_spot(D3FEND 미커버=일반적으로 탐지난망=은밀)과
validator가 낸 탐지 신호 수. **SOC 내부를 읽지 않음**(D8 무결합 유지) — 방어측이 아니라
"내 액션이 emit할 신호"라는 공격측 추론.

기본은 **조언 전용**(abort 권고만, 파이프라인 미변경 → 벤치 불변). profile.engagement.
opsec_enforce=True일 때만 실제 중단에 쓰도록 seam을 남긴다.
"""

from __future__ import annotations

# 스텔스 레벨별 탐지 노출 예산(T3MP3ST silent/covert/loud와 동형).
STEALTH_BUDGETS = {"silent": 1.0, "covert": 3.0, "loud": 20.0}
_DEFAULT_LEVEL = "covert"


def action_exposure(blind_spot: bool, n_signals: int) -> float:
    """한 액션의 탐지 노출 가중치.

    blind_spot(D3FEND 미커버, 예: GNSS 스푸핑·RF 재밍·온보드 AI) → 은밀(낮은 노출).
    관측 가능(무서명 MAVLink 인젝션 등) → 노출 큼, 예상 탐지 신호가 많을수록 증가.
    """
    if blind_spot:
        return 0.25
    return round(1.0 + 0.5 * n_signals, 3)


class OpsecController:
    """탐지 노출 누적 + 스텔스 예산 초과 시 abort 권고."""

    def __init__(self, level: str = _DEFAULT_LEVEL) -> None:
        self.level = level if level in STEALTH_BUDGETS else _DEFAULT_LEVEL
        self.budget = STEALTH_BUDGETS[self.level]
        self.exposure = 0.0
        self.timeline: list = []

    def observe(self, action: str, blind_spot: bool, n_signals: int) -> None:
        """실집행(=탐지 표면 발생)된 액션 1건의 노출을 누적한다."""
        delta = action_exposure(blind_spot, n_signals)
        self.exposure = round(self.exposure + delta, 3)
        self.timeline.append({
            "action": action,
            "detectable": not blind_spot,
            "exposure_delta": delta,
            "cumulative": self.exposure,
            "over_budget": self.exposure > self.budget,
        })

    @property
    def abort_recommended(self) -> bool:
        return self.exposure > self.budget

    def summary(self) -> dict:
        breach = next((t["action"] for t in self.timeline if t["over_budget"]), None)
        return {
            "level": self.level,
            "budget": self.budget,
            "detection_exposure": self.exposure,
            "abort_recommended": self.abort_recommended,
            "breach_action": breach,        # 예산을 처음 넘긴 액션(없으면 None)
            "timeline": self.timeline,
        }
