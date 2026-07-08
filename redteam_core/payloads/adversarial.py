"""적대 패치 페이로드 스펙 (S7, AML.T0043) — 온보드 표적인식 회피.

실 이미지 생성은 본선(EO/IR 데이터셋 필요). 여기서는 결정론적 '패치 스펙'을
산출한다: 위치·크기·왜곡유형·목표오분류. sim_bridge(황준식 독립 SOC)로 전달 가능.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class AdversarialSpec:
    sid: str
    patch_type: str        # sticker | dazzle | decoy | ir_flare
    location: str          # 표적 상 부착 위치
    target_misclass: str   # 목표 오분류(예: tank→clutter)
    technique: str = "AML.T0043"


_SPECS = [
    ("sticker", "포탑 상면", "tank→clutter"),
    ("dazzle", "차체 측면", "vehicle→background"),
    ("decoy", "표적 인근 지면", "single→multiple(포화)"),
    ("ir_flare", "엔진 배기부", "hot_target→none(IR 회피)"),
]


def generate_adversarial_specs() -> List[AdversarialSpec]:
    return [AdversarialSpec(f"ADV-{i:02d}", t, loc, mis)
            for i, (t, loc, mis) in enumerate(_SPECS)]
