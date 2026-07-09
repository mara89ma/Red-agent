"""capabilities — 전 모듈 단일 인덱스(레지스트리) + 중복 지도.

파편화 완화: 30+ 모듈을 기능 도메인으로 묶고, 개념 중복을 명시한다. 코드 이동 없이
'무엇이 어디에·무엇과 겹치는지'를 한 곳에서 조회.
"""
from __future__ import annotations

# 도메인 → 모듈
DOMAINS = {
    "공격면": ["emso", "targeting", "maneuver", "transport", "persistence",
              "payloads", "dronesploit", "advanced", "simtest", "groundseg"],
    "킬체인·실행": ["killchain", "campaigns", "execute"],
    "적응·폐루프": ["assessment"],
    "평가·KPI·벤치마크": ["kpi", "benchmark", "audit"],
    "안전·통제": ["roe", "command", "sandbox"],
    "조직·기만·지속": ["orchestration", "tempo", "deception", "sustainment",
                     "mission_command"],
    "연동·발견": ["integrations", "toolsearch"],
    "결정평면(교리)": ["jadc2", "mosaic", "ooda", "information"],
    "지능 코어": ["graph", "nodes", "judge", "learning", "memory", "rag",
                "llm", "safety", "opsec", "intel", "bridge", "mapping"],
}

# 개념 중복(향후 통합 후보) — 코드는 그대로, 관계만 명시.
OVERLAPS = [
    ("tempo", "ooda", "둘 다 시간/템포 — tempo=효과시간·MTTD, ooda=Orient마비·속도경쟁. 상보"),
    ("orchestration", "mission_command", "orchestration=CMT 직무협업, mission_command=상위 자율지휘(orchestration 호출자)"),
    ("kpi", "benchmark", "kpi=원지표 10종, benchmark=이를 스코어카드/목표대비 채점. 소비 관계"),
    ("emso", "dronesploit(wifi_jam)", "재밍 물리 vs WiFi 계층 재밍 — 계층 다름"),
]


def capability_index() -> dict:
    modules = sorted({m for ms in DOMAINS.values() for m in ms})
    return {"domains": DOMAINS, "total_modules": len(modules),
            "modules": modules, "overlaps": OVERLAPS}


def domain_of(module: str) -> str:
    for d, ms in DOMAINS.items():
        if module in ms:
            return d
    return "?"
