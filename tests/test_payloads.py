"""ML 공격 페이로드 생성 테스트 — 고도화 §N. 결정론·무의존."""
from __future__ import annotations

import base64

from redteam_core.payloads import (
    CONVERTERS, generate_prompt_injections, generate_extraction_ladder,
    generate_adversarial_specs,
)


def test_prompt_injection_seeds_generate():
    ps = generate_prompt_injections(target="GNSS 스푸핑")
    assert len(ps) >= 6
    assert all(p.technique == "AML.T0051" for p in ps)
    assert any("benign" in p.text or "무시" in p.text for p in ps)


def test_base64_converter_roundtrips():
    ps = generate_prompt_injections(converters=["base64"], n=1)
    decoded = base64.b64decode(ps[0].text).decode()
    assert "OVERRIDE" in decoded or "benign" in decoded


def test_converters_produce_distinct_output():
    raw = generate_prompt_injections(converters=["none"], n=1)[0].text
    leet = CONVERTERS["leetspeak"](raw)
    assert leet != raw and "4" in leet or "3" in leet


def test_deterministic_generation():
    a = [p.pid for p in generate_prompt_injections(converters=["none", "base64"])]
    b = [p.pid for p in generate_prompt_injections(converters=["none", "base64"])]
    assert a == b                       # 결정론(무작위 없음)


def test_extraction_ladder_is_progressive():
    ladder = generate_extraction_ladder()
    intents = [q.intent for q in ladder]
    assert intents[0] == "recon" and "watchlist_exfil" in intents
    assert all(q.technique == "AML.T0057" for q in ladder)


def test_adversarial_specs_cover_eo_and_ir():
    specs = generate_adversarial_specs()
    types = {s.patch_type for s in specs}
    assert "sticker" in types and "ir_flare" in types
