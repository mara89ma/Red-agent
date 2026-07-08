"""전달·설치지속·C2 능력 — 은밀/탐지 기법 대안.

각 기법의 탐지는 blue 실제 룰에 매핑(D8: 공유 산출물 참조). 은밀 기법(사각지대)과
탐지 기법(견고한 룰)의 대비가 킬체인 은밀 관통 가능성을 정한다.
"""
from __future__ import annotations

# 전달 벡터 — 표적 도달 수단(전달 자체는 저신호, 탐지는 후속 단계에서).
DELIVERY_VECTORS = {
    "rf": "RF 근접(EW 전달)",
    "network": "네트워크 측면(측면이동 경유)",
    "supply_chain": "공급망(정비·펌웨어 유입)",
}

# 설치/지속(Installation, ATT&CK Persistence) — 발판 유지 기법.
PERSISTENCE_TECHNIQUES = {
    "credential_foothold": {
        "detect_rule": None, "detected": False, "durable": True,
        "note": "유효계정 발판 재사용(은밀) — 신규 시그니처 없음",
    },
    "firmware_implant": {
        "detect_rule": "S4_Firmware_Tampering", "detected": True, "durable": True,
        "note": "펌웨어/정비 임플란트 — blue S4/S21 탐지",
    },
}

# C2(Command & Control) — 제어채널 수립 기법.
C2_TECHNIQUES = {
    "common_port": {
        "detect_rule": None, "detected": False,
        "note": "상용 포트 은닉 C2(T0885) — 미매핑 사각지대",
    },
    "rogue_router": {
        "detect_rule": "S26_Router_Endpoint_Rogue", "detected": True,
        "note": "불량 라우터 엔드포인트 — blue S26 탐지",
    },
}
