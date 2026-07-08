"""Navigator 레이어 테스트 — §N 확장. 결정론·무의존."""
from __future__ import annotations

from redteam_core.kpi.navigator import build_navigator_layer


def test_layer_structure_valid():
    layer = build_navigator_layer("ics-attack")
    assert layer["domain"] == "ics-attack" and layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) > 0
    for t in layer["techniques"]:
        assert t["techniqueID"].startswith("T0") and "color" in t and "comment" in t


def test_atlas_domain_has_ai_techniques():
    layer = build_navigator_layer("atlas")
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert any(i.startswith("AML") for i in ids)


def test_blind_spots_colored_red():
    # 사각지대 기법은 적색(#e74c3c).
    layer = build_navigator_layer("atlas")
    reds = [t for t in layer["techniques"] if t["color"] == "#e74c3c"]
    assert len(reds) >= 1                         # AI 계층 사각지대 존재
