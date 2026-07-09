"""빈 번호 채움 시나리오 테스트 — S22·S28·S63~S65·S74~S85. 결정론·무의존."""
from __future__ import annotations

import glob
import re

from redteam_core.assessment import OBJECTIVES, adaptive_engage
from redteam_core.campaigns import run_chain
from redteam_core.extended import EXTENDED_SCENARIOS, run_extended, themes

_GAPS = {"S22", "S28", "S63", "S64", "S65"} | {f"S{n}" for n in range(74, 86)}


def test_fills_exactly_the_gaps():
    assert set(EXTENDED_SCENARIOS) == _GAPS
    assert len(EXTENDED_SCENARIOS) == 17


def test_objectives_registered_and_achievable():
    for sid, (obj, *_ ) in EXTENDED_SCENARIOS.items():
        assert obj in OBJECTIVES
        r = adaptive_engage(obj)
        assert r.verdict == "achieved" and r.trace[-1][2].detected is None  # 사각지대


def test_themes_grouped():
    t = themes()
    assert set(t) == {"공중", "정찰", "기체", "공급망", "미들웨어"}
    assert "S77" in t["공급망"]


def test_fill_campaigns_run():
    for cid in ("C21", "C22"):
        assert run_chain(cid).verdict in ("stealthy", "detected")


def test_no_gaps_remain_S1_to_S102():
    # 전 소스에서 정의된 S번호 → S1~S102 연속(빈 번호 0) 확인.
    ids = set()
    for f in glob.glob("redteam_core/**/*.py", recursive=True):
        ids |= set(re.findall(r'"(S\d{1,3})"\s*:', open(f, encoding="utf-8").read()))
    nums = {int(x[1:]) for x in ids}
    missing = [n for n in range(1, 103) if n not in nums]
    assert missing == [], f"남은 빈 번호: {['S%d' % n for n in missing]}"
