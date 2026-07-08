"""전투평가(JP 3-60 ⑥) 테스트 — 고도화 §D. 결정론·무의존."""
from __future__ import annotations

from redteam_core.assessment import assess_combat, run_engagement


def test_effective_when_effect_and_evaded():
    ca = assess_combat("gnss_spoof", executed=True, effect_achieved=True,
                       detected=False, adaptable=True)
    assert ca.effective is True and ca.reattack.needed is False


def test_reattack_lower_intensity_when_detected_continuous():
    ca = assess_combat("gnss_spoof", executed=True, effect_achieved=True,
                       detected=True, adaptable=True)
    assert ca.effective is False
    assert ca.reattack.needed and ca.reattack.adjustment == "lower_intensity"


def test_reattack_switch_ttp_when_detected_categorical():
    ca = assess_combat("force_arm", executed=True, effect_achieved=True,
                       detected=True, adaptable=False)
    assert ca.reattack.adjustment == "switch_ttp"


def test_reattack_raise_intensity_when_effect_insufficient():
    ca = assess_combat("gnss_spoof", executed=True, effect_achieved=False,
                       detected=False, adaptable=True)
    assert ca.reattack.adjustment == "raise_intensity"


def test_reattack_fix_delivery_when_not_executed():
    ca = assess_combat("active_scan", executed=False, effect_achieved=False,
                       detected=None, adaptable=True)
    assert ca.reattack.adjustment == "fix_delivery"


def test_blindspot_counts_as_survivable():
    ca = assess_combat("param_read", executed=True, effect_achieved=True,
                       detected=None, adaptable=False)
    assert ca.moe_survivability is True and ca.effective is True


def test_run_engagement_ties_emso_bda_assessment():
    # 근접 고출력 스푸핑: 효과 달성 + 탐지됨 → 재타격(강도 하향) 권고.
    ca = run_engagement("gnss_spoof", geometry={"spoof_eirp_dbm": 20, "spoof_dist_m": 100})
    assert ca.moe_effect is True and ca.detected is True
    assert ca.reattack.adjustment == "lower_intensity"


def test_run_engagement_weak_spoof_effect_fails():
    ca = run_engagement("gnss_spoof", geometry={"spoof_eirp_dbm": -20, "spoof_dist_m": 20000})
    assert ca.moe_effect is False and ca.reattack.adjustment == "raise_intensity"
