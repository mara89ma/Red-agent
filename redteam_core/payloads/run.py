"""페이로드 실행 배선 — §N 생성 페이로드를 탐지 파이프라인(§A)에 흘린다.

각 구체 페이로드를 assess_action 으로 관측해 탐지/우회를 기록한다. S32/S33/S7 은
blue 미매핑(사각지대)이라 우회율 100% 로 나오며, 이것이 방어 공백의 정량 지표다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ..assessment.bda import assess_action
from .adaptive import AdaptivePayloadGenerator, SituationContext
from .adversarial import generate_adversarial_specs
from .extraction import generate_extraction_ladder
from .prompt_inject import generate_prompt_injections


@dataclass
class PayloadOutcome:
    scenario: str
    action: str
    payload_id: str
    preview: str
    detected: Optional[bool]
    bypassed: bool           # 탐지 안 됨(사각/회피)


def _outcome(scenario, action, pid, preview) -> PayloadOutcome:
    det = assess_action(action).detected
    return PayloadOutcome(scenario, action, pid, preview[:48].replace("\n", " "),
                          det, det is not True)


def run_prompt_injection(target="GNSS 스푸핑", converters=None) -> List[PayloadOutcome]:
    converters = converters or ["none", "base64"]
    return [_outcome("S32", "ml_prompt_inject", p.pid, p.text)
            for p in generate_prompt_injections(target, converters)]


def run_model_extraction() -> List[PayloadOutcome]:
    return [_outcome("S33", "ml_extract_secret", f"Q{q.step}", q.query)
            for q in generate_extraction_ladder()]


def run_adversarial() -> List[PayloadOutcome]:
    return [_outcome("S7", "ml_craft_adversarial", a.sid, f"{a.patch_type}:{a.target_misclass}")
            for a in generate_adversarial_specs()]


def run_adaptive(ctx: SituationContext) -> List[PayloadOutcome]:
    """상황 맞춤 페이로드를 생성해 탐지 파이프라인에 흘린다."""
    action = "ml_extract_secret" if ctx.scenario == "S33" else "ml_prompt_inject"
    payloads = AdaptivePayloadGenerator().generate(ctx)
    return [_outcome(ctx.scenario, action, p.pid, p.text) for p in payloads]


def bypass_rate(outcomes: List[PayloadOutcome]) -> float:
    return sum(o.bypassed for o in outcomes) / len(outcomes) if outcomes else 0.0
