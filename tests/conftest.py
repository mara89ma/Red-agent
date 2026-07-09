"""테스트 러너 리포터 — 무슨 기능·어떤 시나리오를 테스트하는지 콘솔 출력 + 로그 저장.

- 각 테스트마다: [기능] 테스트명 · 시나리오(S/C 번호) · 실표적/모델 · PASS/FAIL·시간
- 세션 로그를 out/test_logs/test-run-<타임스탬프>.log 로 별도 저장(콘솔과 동일 내용)
- 종료 시 기능별 집계 + 로그 경로 출력
"""
from __future__ import annotations

import datetime
import pathlib
import re

# 테스트 파일 → 한글 기능명
_FEATURE = {
    "test_execute": "시나리오 실 실행기 §U (MAVLink·HTTP·유출)",
    "test_groundseg": "지상 세그먼트 공격 (GCS·ROS·데이터링크·클라우드)",
    "test_groundseg_exec": "지상 세그먼트 실 실행 (loopback 실증)",
    "test_realistic_range": "실 상황 유사 통합 레인지 (loopback 실공격)",
    "test_doctrine5": "결정평면 5종 (JADC2·Mosaic·OODA·Information·MissionCmd)",
    "test_improve": "검증감사·judge introspection·정보 실행·레지스트리",
    "test_dronesploit": "WiFi 계층 공격 (dronesploit)",
    "test_advanced": "고급 드론 공격 (RC·DShot·anti-forensics)",
    "test_simtest": "다중센서 폴트인젝션 (AutoSim)",
    "test_exfil": "데이터 유출 시나리오",
    "test_campaigns": "캠페인 체인 실행",
    "test_kpi": "레드팀 KPI", "test_kpi2": "레드팀 KPI",
    "test_benchmark": "능력 벤치마크(xbow식)",
    "test_scorecard": "KPI 스코어카드", "test_kpi_improve": "KPI 개선(목표근거·추세)",
    "test_assessment": "폐루프 전투평가(BDA)", "test_combat": "전투평가 MOE/MOP",
    "test_replan": "적응 재계획(OODA)", "test_roe": "RoE 교전권한",
    "test_emso": "전자전(EMSO)", "test_transport": "실 전송(C2·프레임)",
    "test_persistence_infra": "지속(임플란트)", "test_persistence_adapter": "지속 어댑터",
    "test_killchain": "킬체인 오케스트레이션", "test_maneuver": "기동·측면이동",
    "test_targeting": "표적개발(CARVER)", "test_orchestration": "CMT 직무 오케스트레이션",
    "test_integrations": "외부 도구 연동", "test_msf_cve": "Metasploit·CVE 연동",
    "test_apt_emulation": "APT 그룹 모사", "test_toolsearch": "GitHub 툴 자동검색",
    "test_llm_judge": "Judge 앙상블", "test_learning": "자기개선 학습",
    "test_navigator": "ATT&CK Navigator", "test_deception": "군사기만(MILDEC)",
    "test_command_chain": "승인 체인(EXORD)", "test_opsec": "OPSEC",
}
# 실 표적(loopback/실 파일·소켓·HTTP) 검증 파일
_REALISTIC = {"test_execute", "test_groundseg_exec", "test_realistic_range",
              "test_transport", "test_persistence_infra", "test_improve"}

_S = {"log": None, "path": None, "tr": None, "feat": {}}
_DOCS: dict = {}


def _module(nodeid: str) -> str:
    return nodeid.split("::")[0].split("/")[-1][:-3]


def _emit(msg: str) -> None:
    """로그 파일 기록(+요약은 콘솔에도)."""
    if _S["log"] is not None:
        _S["log"].write(msg + "\n")
        _S["log"].flush()


def _feat_tag(nodeid: str):
    mod = _module(nodeid)
    feat = _FEATURE.get(mod, mod.replace("test_", ""))
    tag = "🎯실표적" if mod in _REALISTIC else "🧪모델"
    name = nodeid.split("::")[-1]
    desc = _DOCS.get(nodeid, "")
    scn = sorted(set(re.findall(r"[SC]\d{1,3}", name + " " + desc)))
    return feat, tag, scn


def pytest_report_teststatus(report, config):
    """콘솔 per-test 라인 커스터마이즈: [기능] 실표적/모델 · 시나리오."""
    if report.when != "call":
        return None
    feat, tag, scn = _feat_tag(report.nodeid)
    scn_s = (" S:" + ",".join(scn)) if scn else ""
    icon = {"passed": "✅", "failed": "❌", "skipped": "⏭"}.get(report.outcome, "?")
    word = f"{icon}{tag} [{feat}]{scn_s}"
    short = {"passed": ".", "failed": "F", "skipped": "s"}.get(report.outcome, "?")
    return report.outcome, short, word


def pytest_configure(config) -> None:
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    d = pathlib.Path(str(config.rootdir)) / "out" / "test_logs"
    d.mkdir(parents=True, exist_ok=True)
    _S["path"] = d / f"test-run-{ts}.log"
    _S["log"] = open(_S["path"], "w", encoding="utf-8")
    _S["tr"] = config.pluginmanager.getplugin("terminalreporter")
    _emit("=" * 70)
    _emit(f"레드팀 AI 에이전트 — 테스트 실행  {ts}")
    _emit("목표: 최대한 실제 상황과 유사한 검증 (🎯=실표적 loopback / 🧪=모델 판정)")
    _emit("=" * 70)


def pytest_collection_modifyitems(config, items) -> None:
    for it in items:
        fn = getattr(it, "function", None)
        doc = (fn.__doc__ or "").strip() if fn else ""
        _DOCS[it.nodeid] = doc.splitlines()[0] if doc else ""


def pytest_runtest_logreport(report) -> None:
    if report.when != "call":
        return
    mod = _module(report.nodeid)
    feat = _FEATURE.get(mod, mod.replace("test_", ""))
    tag = "🎯실표적" if mod in _REALISTIC else "🧪모델"
    icon = {"passed": "✅", "failed": "❌", "skipped": "⏭"}.get(report.outcome, "?")
    name = report.nodeid.split("::")[-1]
    desc = _DOCS.get(report.nodeid, "")
    # 시나리오 번호 추출(S12·C3 등) — 이름·설명에서
    scn = sorted(set(re.findall(r"[SC]\d{1,3}", name + " " + desc)))
    scn_s = (" · 시나리오 " + ",".join(scn)) if scn else ""
    _emit(f"{icon} [{feat}] {name}  {tag}{scn_s}  ({report.duration:.3f}s)")
    if desc:
        _emit(f"     ↳ {desc}")
    _S["feat"].setdefault(feat, [0, 0, 0])
    _S["feat"][feat][0 if report.passed else 1 if report.failed else 2] += 1


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    def both(msg):
        terminalreporter.write_line(msg)   # 콘솔
        _emit(msg)                          # 로그 파일
    both("=" * 70)
    both("기능별 집계 (통과/실패/스킵)  🎯=실표적 loopback / 🧪=모델")
    both("=" * 70)
    for feat, (p, f, s) in sorted(_S["feat"].items()):
        mark = "✅" if f == 0 else "❌"
        both(f"  {mark} {feat:<46} {p}/{f}/{s}")
    both(f"📄 테스트 로그 저장: {_S['path']}")
    if _S["log"]:
        _S["log"].close()
