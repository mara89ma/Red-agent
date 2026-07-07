"""ablation 인과 기여 테스트 (C)."""

from benchmarks import ablate


def _by_name(result, name):
    return next(c for c in result["components"] if c["component"].startswith(name))


class TestAblation:
    def test_oracle_earns_its_keep(self):
        # 완전-방어 반사실: out-of-band 오라클이 자기보고 성공을 실제로 다수 반박해야 한다.
        r = ablate.measure()
        oracle = _by_name(r, "out_of_band_oracle")
        assert oracle["prevented"] > 0 and oracle["verdict"] == "earns-keep"

    def test_token_gate_earns_its_keep(self):
        r = ablate.measure()
        gate = _by_name(r, "irreversible_token_gate")
        assert gate["prevented"] > 0 and gate["verdict"] == "earns-keep"

    def test_learning_now_earns_keep_via_efficiency(self):
        # planner 배선 후 학습은 재engagement에서 무익 액션을 스킵해 인과 lift를 얻는다.
        r = ablate.measure()
        learn = _by_name(r, "learning_loop")
        assert learn["prevented"] > 0 and learn["verdict"] == "earns-keep"

    def test_learning_lift_has_no_asr_regression(self):
        # 인과 lift는 효율(노출·시도)만 — 목표 결과는 절대 바뀌지 않아야(무회귀).
        detail = ablate.measure()["learning_detail"]
        assert detail["actions_skipped"] > 0        # 실제로 스킵 발생
        assert detail["exposure_saved"] > 0.0       # 노출 절감
        assert detail["objective_flips"] == 0       # ASR 무회귀(안전 불변식)

    def test_full_defense_zero_safety_violations(self):
        assert ablate.measure()["safety_violations_total"] == 0
