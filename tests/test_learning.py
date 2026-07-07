"""자기개선 학습 루프 테스트 (B7/B6/B8)."""

import copy

from redteam_core.engagement.gate import _DEFAULT_PROFILE, Gate
from redteam_core.graph.build import build_graph
from redteam_core.learning import (CONFIRMED_FAIL, CONFIRMED_SUCCESS, INCONCLUSIVE,
                                    ExperienceRecord, Observation, ProbeEngine,
                                    new_experience_gates, new_target_gate, recommend,
                                    resolve_target_id)
from redteam_core.learning.experience import Sha256Signer
from redteam_core.session import build_initial_state
from redteam_core.tools.range_factory import make_range


def _approver(ctx):
    return "denied" if ctx.get("physical_irreversible") else "approved"


# ============================ B7: fingerprint + profile =====================
class TestTargetProfile:
    def test_explicit_id(self):
        tid, explicit = resolve_target_id(_DEFAULT_PROFILE)
        assert tid == "av-muav" and explicit is True

    def test_inferred_id_when_no_host(self):
        prof = {"target_profile": {"services": [{"ip": "10.50.0.20", "port": 5790}]}}
        tid, explicit = resolve_target_id(prof)
        assert tid.startswith("fp:") and explicit is False

    def test_running_avg_and_kill_chain(self):
        tg = new_target_gate()
        tg.record_attempt("t1", "set_mode", "T1692.001", 1.0)
        tg.record_attempt("t1", "set_mode", "T1692.001", 0.0)
        p = tg.get("t1")
        assert p.pb_scores["set_mode"] == {"avg_effect": 0.5, "n": 2}
        assert p.kill_chain == ["set_mode", "set_mode"]
        assert p.techniques_attempted == ["T1692.001"]

    def test_tamper_detected_on_read(self):
        tg = new_target_gate()
        tg.record_attempt("t1", "set_mode", "T1", 1.0)
        p = tg._store.get("t1")
        p.pb_scores["set_mode"]["avg_effect"] = 999.0        # 서명 없이 변조
        assert tg.get("t1") is None                          # 서명 불일치 → 거부


# ============================ B6: experience gate ===========================
class TestExperienceGate:
    def test_write_policy(self):
        g = new_experience_gates()
        ok = g.write.write(ExperienceRecord("t", "T1", "set_mode", CONFIRMED_SUCCESS, 1.0,
                                            "validator"))
        assert ok is True
        # dedup
        assert g.write.write(ExperienceRecord("t", "T1", "set_mode", CONFIRMED_SUCCESS, 1.0,
                                              "validator")) is False
        # INCONCLUSIVE 폐기
        assert g.write.write(ExperienceRecord("t", "T1", "a", INCONCLUSIVE, 0.0,
                                              "validator")) is False
        # 비신뢰 provenance의 suppression(FAIL) 거부
        assert g.write.write(ExperienceRecord("t", "T1", "b", CONFIRMED_FAIL, 0.0,
                                              "recon")) is False
        # 신뢰 provenance의 FAIL 허용
        assert g.write.write(ExperienceRecord("t", "T1", "b", CONFIRMED_FAIL, 0.0,
                                              "validator")) is True

    def test_recall_asymmetric_trust(self):
        g = new_experience_gates()
        g.write.write(ExperienceRecord("t", "T1", "set_mode", CONFIRMED_SUCCESS, 1.0, "validator"))
        assert [r.action for r in g.read.recall("t", "success")] == ["set_mode"]

        # 방어심층: 비신뢰 FAIL을 스토어에 직접 주입(서명 유효) → 위험 방향 회수는 제외
        signer = Sha256Signer(salt="redteam-exp-v1")
        rec = ExperienceRecord("t", "T1", "z", CONFIRMED_FAIL, 0.0, "recon")
        rec.signature = signer.sign(rec.fingerprint())
        g.store.add(rec)
        assert g.read.recall("t", "failure") == []           # 비신뢰 FAIL 회수 차단


# ============================ B8: probe + loop ==============================
class TestOutcomeProbe:
    def test_decide_matrix(self):
        assert ProbeEngine.decide(Observation("t", "T", "a", "success")) == (CONFIRMED_SUCCESS, 1.0)
        assert ProbeEngine.decide(Observation("t", "T", "a", "failed")) == (CONFIRMED_FAIL, 0.0)
        assert ProbeEngine.decide(Observation("t", "T", "a", "blocked")) == (INCONCLUSIVE, 0.0)


def _engage(eg=None, tg=None):
    prof = copy.deepcopy(_DEFAULT_PROFILE)
    gate = Gate(scope=prof["authorization"], budget=dict(prof["ops"]["budget"]))
    state = build_initial_state(prof, gate, make_range(prof), _approver,
                                experience_gate=eg, target_gate=tg)
    return build_graph().invoke(state)


class TestSelfImprovementLoop:
    def test_learn_populates_report(self):
        final = _engage()
        learning = final["report"]["learning"]
        assert learning["target_id"] == "av-muav"
        assert learning["experiences_written"] == 2         # set_mode + force_arm (takeoff blocked)
        assert set(learning["prior_success_recall"]) == {"set_mode", "force_arm"}

    def test_cross_engagement_accumulates(self):
        eg, tg = new_experience_gates(), new_target_gate()
        r1 = _engage(eg, tg)
        r2 = _engage(eg, tg)
        assert r1["report"]["learning"]["experiences_written"] == 2
        assert r2["report"]["learning"]["experiences_written"] == 0   # dedup(재관측)
        # 타깃 프로파일은 두 run에 걸쳐 누적
        assert tg.get("av-muav").pb_scores["set_mode"]["n"] == 2
        rec = recommend("av-muav", eg, tg)
        assert "set_mode" in rec["proven_actions"] and "force_arm" in rec["proven_actions"]
        assert "takeoff" not in rec["proven_actions"]        # blocked → 미검증
