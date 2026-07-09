"""개선 4종 테스트 — 검증감사·judge introspection·Information 실행·레지스트리."""
from __future__ import annotations

import os

from redteam_core.audit import format_audit, verification_audit
from redteam_core.capabilities import capability_index, domain_of
from redteam_core.information import execute_real


def test_audit_separates_real_from_model():
    a = verification_audit()
    # 실행검증 = execute 25 + groundseg 14 + information 3 = 42
    assert a["real_exec_scenarios"] == 42
    assert a["self_model_scenarios"] > 0          # 자기충족도 정직하게 집계
    assert "판정했다" in a["honesty_note"]


def test_audit_renders():
    txt = format_audit(verification_audit())
    assert "real_exec" in txt and "self_model" in txt


def test_information_execute_real_writes_file(tmp_path, monkeypatch):
    monkeypatch.setenv("INFO_TARGET_DIR", str(tmp_path))
    r = execute_real("S100")                       # SOCReport 위조
    assert r["sent"] is True and os.path.exists(r["path"])
    assert b"true_state" in open(r["path"], "rb").read()   # 거짓 보고 실 생성


def test_information_signed_blocks(monkeypatch, tmp_path):
    monkeypatch.setenv("INFO_TARGET_DIR", str(tmp_path))
    assert execute_real("S102", integrity_signed=True)["sent"] is False


def test_information_no_target_fails_closed(monkeypatch):
    monkeypatch.delenv("INFO_TARGET_DIR", raising=False)
    assert execute_real("S100")["sent"] is False


def test_capability_index_covers_domains():
    idx = capability_index()
    assert "결정평면(교리)" in idx["domains"] and "지능 코어" in idx["domains"]
    assert domain_of("mission_command") == "조직·기만·지속"
    assert domain_of("jadc2") == "결정평면(교리)"
    assert idx["overlaps"]                          # 중복 명시
