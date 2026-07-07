"""학습 영속 seam(2a) + 실 SITL 어댑터 seam(2b) 테스트.

2a: JSON 파일 백엔드가 InMemory와 동일 Protocol을 구현하고, 프로세스 간 재적재로
    자기개선이 이어지며, 파일 변조는 서명으로 걸러진다.
2b: range_factory가 range_mode로 스텁↔실 어댑터를 스왑하고, pymavlink 부재 시
    연결 시점(속성 접근)에 명확히 실패한다(import 시점 아님).
"""

import copy
import json
import os

import pytest

from redteam_core.engagement.gate import _DEFAULT_PROFILE
from redteam_core.learning import (CONFIRMED_FAIL, CONFIRMED_SUCCESS, ExperienceRecord,
                                    new_persistent_experience_gates, new_persistent_target_gate)
from redteam_core.learning.persistence import JsonExperienceStore, JsonTargetStore
from redteam_core.tools.mavlink_adapter import MavlinkRange
from redteam_core.tools.range_factory import make_range
from redteam_core.tools.sitl_stub import Range


# ============================ 2a: 영속 seam ================================
class TestPersistence:
    def _paths(self, tmp_path):
        return str(tmp_path / "exp.json"), str(tmp_path / "tgt.json")

    def test_experience_roundtrip(self, tmp_path):
        ep, _ = self._paths(tmp_path)
        eg = new_persistent_experience_gates(ep)
        eg.write.write(ExperienceRecord("t", "T1", "set_mode", CONFIRMED_SUCCESS, 1.0, "validator"))
        eg.write.write(ExperienceRecord("t", "T1", "force_arm", CONFIRMED_SUCCESS, 1.0, "validator"))
        # 새 프로세스 모사 — 동일 path로 fresh 게이트
        eg2 = new_persistent_experience_gates(ep)
        assert sorted(r.action for r in eg2.read.recall("t", "success")) == ["force_arm", "set_mode"]

    def test_experience_dedup_survives_reload(self, tmp_path):
        ep, _ = self._paths(tmp_path)
        rec = ExperienceRecord("t", "T1", "set_mode", CONFIRMED_SUCCESS, 1.0, "validator")
        assert new_persistent_experience_gates(ep).write.write(rec) is True
        # 재적재 후 같은 경험 재기록 → dedup(파일에 이미 존재)
        assert new_persistent_experience_gates(ep).write.write(
            ExperienceRecord("t", "T1", "set_mode", CONFIRMED_SUCCESS, 1.0, "validator")) is False

    def test_target_profile_roundtrip_and_accumulate(self, tmp_path):
        _, tp = self._paths(tmp_path)
        tg = new_persistent_target_gate(tp)
        tg.record_attempt("av-muav", "set_mode", "T1", 1.0)
        tg2 = new_persistent_target_gate(tp)             # 재적재
        tg2.record_attempt("av-muav", "set_mode", "T1", 0.0)   # 누적
        p = new_persistent_target_gate(tp).get("av-muav")
        assert p.pb_scores["set_mode"] == {"avg_effect": 0.5, "n": 2}

    def test_file_tamper_rejected_on_reload(self, tmp_path):
        _, tp = self._paths(tmp_path)
        new_persistent_target_gate(tp).record_attempt("t", "set_mode", "T1", 1.0)
        raw = json.load(open(tp, encoding="utf-8"))
        raw["t"]["pb_scores"]["set_mode"]["avg_effect"] = 999.0   # 서명 없이 변조
        json.dump(raw, open(tp, "w", encoding="utf-8"))
        assert new_persistent_target_gate(tp).get("t") is None    # 서명 불일치 → 거부

    def test_corrupt_file_starts_empty(self, tmp_path):
        ep, _ = self._paths(tmp_path)
        with open(ep, "w", encoding="utf-8") as fh:
            fh.write("{ this is not json")
        store = JsonExperienceStore(ep)
        assert store.all() == []                          # 파일 자체 손상 → 빈 시작(오염 차단)

    def test_one_bad_record_does_not_discard_all(self, tmp_path):
        # 리뷰 FINDING 4 회귀: 한 건이 스키마 불일치라도 나머지 누적 학습은 보존.
        ep, _ = self._paths(tmp_path)
        good = {"target_id": "t", "technique": "T", "action": "set_mode",
                "verdict": "CONFIRMED_SUCCESS", "effect": 1.0, "provenance": "validator",
                "signature": "x"}
        bad = {"target_id": "t", "UNKNOWN_FIELD": 1}       # 스키마 불일치
        json.dump([good, bad, good], open(ep, "w", encoding="utf-8"))
        store = JsonExperienceStore(ep)
        assert len(store.all()) == 2                       # 불량 1건만 스킵, good 2건 보존

    def test_stores_implement_protocol_shape(self, tmp_path):
        ep, tp = self._paths(tmp_path)
        es, ts = JsonExperienceStore(ep), JsonTargetStore(tp)
        assert hasattr(es, "all") and hasattr(es, "add")
        assert hasattr(ts, "get") and hasattr(ts, "put")


# ============================ 2b: 실 어댑터 seam ============================
class TestRangeFactorySwap:
    def _profile(self, mode=None):
        prof = copy.deepcopy(_DEFAULT_PROFILE)
        if mode:
            prof.setdefault("engagement", {})["range_mode"] = mode
        return prof

    def test_container_mode_uses_stub(self):
        assert isinstance(make_range(self._profile("container")), Range)

    def test_sitl_mode_swaps_to_real_adapter(self):
        r = make_range(self._profile("sitl"))
        assert isinstance(r, MavlinkRange)
        assert r.conn_str == "tcp:10.50.0.20:5790"       # 프로파일 services에서 조립

    def test_adapter_interface_parity(self):
        # 노드 코드가 쓰는 3속성을 실 어댑터도 노출(속성 디스크립터 존재 — 호출 안 함).
        for attr in ("ground_truth", "telemetry", "transport"):
            assert isinstance(getattr(MavlinkRange, attr, None), property)

    def test_missing_pymavlink_fails_at_connect_not_import(self):
        # import·make_range·from_profile은 성공하고, 실제 연결(속성 접근) 시점에 명확히 실패.
        r = make_range(self._profile("sitl"))            # 여기까진 성공
        try:
            import pymavlink  # noqa: F401
            connected = True
        except Exception:
            connected = False
        if not connected:
            with pytest.raises(RuntimeError):
                _ = r.transport.apply("set_mode", [1, 4])


# ============================ run.py --persist-learning 배선 ================
class TestRunPersistWiring:
    def test_cli_persist_accumulates_across_runs(self, tmp_path):
        import run
        ldir = str(tmp_path / "learn")
        r1 = run.run_engagement(run.DEFAULT_PROFILE, persist_learning=ldir)
        r2 = run.run_engagement(run.DEFAULT_PROFILE, persist_learning=ldir)
        l1, l2 = r1["report"]["learning"], r2["report"]["learning"]
        assert l1["experiences_written"] == 2            # 첫 run: set_mode+force_arm 기록
        assert l2["experiences_written"] == 0            # 둘째 run: 디스크 dedup
        # pb_scores는 두 run에 걸쳐 디스크에서 누적
        assert l2["target_profile"]["pb_scores"]["set_mode"]["n"] == 2
        assert os.path.exists(os.path.join(ldir, "experience.json"))
        assert os.path.exists(os.path.join(ldir, "target_profile.json"))

    def test_no_persist_flag_uses_ephemeral(self):
        import run
        final = run.run_engagement(run.DEFAULT_PROFILE)   # persist 미지정
        assert final["report"]["learning"]["experiences_written"] == 2  # per-run 인메모리
