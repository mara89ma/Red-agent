"""캠페인 체인 상세 러너 C14~C18 테스트. 결정론·무의존."""
from __future__ import annotations

from redteam_core.campaigns import chain_detail


def test_c14_stages_have_payload_and_detection():
    d = chain_detail("C14")
    assert d.verdict == "detected" and d.first_detected == "S4"
    s = {x.sid: x for x in d.stages}
    assert s["S53"].layer == "IT" and s["S53"].detected is None       # 아카이브 전달 사각
    assert "GPS_INPUT" in s["S1"].payload and s["S1"].escalation == "🔴"


def test_c15_it_to_ot_layers_and_escalation():
    d = chain_detail("C15")
    layers = [x.layer for x in d.stages]
    assert layers == ["IT", "IT", "OT", "OT"]                         # IT→OT 브릿지
    assert d.first_detected == "S12"                                  # OT 임무층서 탐지


def test_c16_all_it_stealthy():
    d = chain_detail("C16")
    assert d.verdict == "stealthy" and d.first_detected is None
    assert all(x.layer == "IT" and x.detected is None for x in d.stages)


def test_c18_idor_to_arming():
    d = chain_detail("C18")
    s = {x.sid: x for x in d.stages}
    assert s["S48"].detected is None and s["S11"].detected is True    # 우회 사각, 무장 탐지


def test_every_stage_has_technique():
    for c in ("C14", "C15", "C16", "C17", "C18"):
        for st in chain_detail(c).stages:
            assert st.technique and st.payload                        # 페이로드·기법 채워짐
