"""상황 맞춤 페이로드 생성 테스트 — 고도화 §N-adaptive. 결정론·무의존."""
from __future__ import annotations

from redteam_core.payloads import (
    AdaptivePayloadGenerator, SituationContext, run_adaptive, bypass_rate,
)


def test_injection_embeds_target_rule_exception_watchlist():
    ctx = SituationContext(scenario="S32", target_rule="S1_GNSS_Spoofing")
    ps = AdaptivePayloadGenerator().generate(ctx)
    joined = " ".join(p.text for p in ps)
    # S1의 실제 예외 워치리스트·필드가 페이로드에 박혀야 함(상황 특정).
    assert "GNSS_Exception_List" in joined and "PosHorizVariance" in joined


def test_injection_adapts_per_rule():
    s1 = " ".join(p.text for p in AdaptivePayloadGenerator().generate(
        SituationContext("S32", "S1_GNSS_Spoofing")))
    s6 = " ".join(p.text for p in AdaptivePayloadGenerator().generate(
        SituationContext("S32", "S6_Operator_BruteForce")))
    assert s1 != s6                                    # 룰마다 다른 페이로드
    assert "Approved_Operators_List" in s6             # S6 예외 워치리스트


def test_extraction_targets_real_watchlist_keys():
    ctx = SituationContext(scenario="S33", target_rule="S1_GNSS_Spoofing")
    ps = AdaptivePayloadGenerator().generate(ctx)
    joined = " ".join(p.text for p in ps)
    assert "UAV_Threshold_List" in joined and "MaxPosHorizVariance" in joined


def test_homoglyph_variant_attached_when_raw_matching():
    ctx = SituationContext(scenario="S32", target_rule="S1_GNSS_Spoofing", raw_matching=True)
    ps = AdaptivePayloadGenerator().generate(ctx)
    assert all(p.variants for p in ps)                 # 변형 부착


def test_run_adaptive_bypasses_blindspot():
    ctx = SituationContext(scenario="S32", target_rule="S1_GNSS_Spoofing")
    outs = run_adaptive(ctx)
    assert bypass_rate(outs) == 1.0                    # 사각지대 → 우회 100%


def test_deterministic_without_llm():
    ctx = SituationContext(scenario="S33", target_rule="S1_GNSS_Spoofing")
    a = [p.text for p in AdaptivePayloadGenerator().generate(ctx)]
    b = [p.text for p in AdaptivePayloadGenerator().generate(ctx)]
    assert a == b                                      # LLM 없이 결정론
