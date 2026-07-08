#!/usr/bin/env python3
"""RoE 교전권한 게이트 데모 — 고도화 §B.

    python benchmarks/roe_eval.py

여러 액션을 RoE 게이트에 통과시켜 교전권한·CDE·조건·데컨플릭션 판정을 표로 출력.
결정론·무의존(Tier-0). engagement_roe.yaml 로드(없으면 보수적 기본).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_core.roe import evaluate_roe, load_roe_profile      # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_GROUND = {"armed": False, "in_flight": False, "alt_rel": 0.0, "mode": "GUIDED"}
_TGT = {"sysid": 42, "pid": True}

CASES = [
    ("recon_heartbeat", _TGT),                         # 정찰 → 허용
    ("set_mode", _TGT),                                # 저위험 조작
    ("param_set_safety", {"sysid": 42, "pid": False}), # PID 없음 → BLOCK
    ("gnss_spoof", _TGT),                              # EW, JCEOI 미승인 → BLOCK
    ("force_arm", _TGT),                               # Deny(Destroy) ∉ ConOps → BLOCK
    ("set_mode", {"sysid": 1, "pid": True}),           # 우군(sysid 1) → fratricide BLOCK
]


def main() -> None:
    prof = load_roe_profile(str(_ROOT / "engagement_roe.yaml"))
    print("=== fried-pollack-ai · RoE 교전권한 게이트 — 고도화 §B ===")
    print(f"위임권한={prof.get('available_authority')} · ConOps 허용효과={prof.get('conops',{}).get('permitted_effects')}")
    print(f"스펙트럼 JCEOI 승인={prof.get('spectrum',{}).get('jceoi_deconflicted')}\n")
    print(f"  {'action':<18}{'effect':<14}{'CDE':<9}{'req권한':<10}{'판정':<10}사유")
    for action, tgt in CASES:
        d = evaluate_roe(action, _GROUND, tgt, prof)
        why = "; ".join(d.unmet_conditions + d.deconfliction_conflicts) or d.rationale
        print(f"  {d.action:<18}{d.effect:<14}{d.cde_tier:<9}{d.required_authority:<10}"
              f"{d.verdict.value:<10}{why}")
    print("\n교리: SROE(PID) · JP 3-60 ④(권한) · CJCSM 3160(CDE) · JP 3-85(스펙트럼) · DoDD 3000.09(결정론 판정)")


if __name__ == "__main__":
    main()
