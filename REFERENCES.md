# REFERENCES — 참고 논문·이식 출처와 설계 매핑

이 문서는 fried-pollack-ai가 참고한 **학술 논문(17편)**, **자매/참조 프로젝트에서 이식한 패턴**,
그리고 **프레임워크 표준(MITRE ATT&CK/ATLAS/D3FEND)** 을 각 설계결정·코드 위치에 1:1로 매핑한다.
"근거 없는 주장은 싣지 않는다"는 원칙(→ [`verify_claims`](benchmarks/verify_claims.py))의
문서판 — **§1의 17편은 전부 코드의 실제 인용 주석에서 도출**했다(코드 `grep '2[0-9]{3}\.[0-9]{4,5}'`
= 17개로 검증). 상위 프레임워크는 핸드북(~250편 리뷰)의 9-STEP 계보이나, 저장소가 *실제로*
인용·구현한 것만 여기 싣는다.

> **문서 자립성**: 이 문서는 저장소만 클론해도 완결된다. 과거 외부(`arch/`·`uav_mitre_attack/`)에
> 있던 설계원문·탐지계약은 **§3에 요지 내장 + [`ARCHITECTURE.md`](ARCHITECTURE.md) §11·§15로
> 크로스워크**했다. 외부 파일 의존 없음.

---

## 1. 학술 논문 (arxiv) → 설계결정 매핑

각 논문은 코드 주석에 인라인으로 인용돼 있다. 아래는 그 통합 색인이다(검증된 실제 주제 포함).

| # | 논문(약칭) · arxiv | 코드 위치 | 검증된 핵심 내용 → 무엇을 근거했나 |
|---|---|---|---|
| 1 | **VulnBot** 2501.13411 | `graph/state.py` | 멀티에이전트 PTG(침투 작업 그래프); PTG 제거 시 실세계 성공률 붕괴 → PTG가 **진짜 메모리**(대화기록 아님, 그래프에 상태 외부화) |
| 2 | **Incalmo** 2501.16466 | `rag/playbook.py` | 고수준 추상 액션+attack-graph로 약한 모델도 다호스트 성공 → **추상 액션=계획 단위**; Planner가 `hijack` 1노드 추론 후 **원자 시퀀스로 즉시 전개** |
| 3 | **FLARE** 2601.22311 | `nodes/planner.py` | lookahead+value propagation으로 탐욕 trap 방지 → **receding-horizon**(1 스텝만 커밋, reflection이 다음 스텝 결정) |
| 4 | **AutoAttacker** 2403.01038 | `nodes/checker.py` | planner/summarizer/experience + **Command Checker** → `target_sysid ∉ allowlist`면 차단(하드 경계) |
| 5 | **TAFC** 2601.18282 | `nodes/checker.py`·`tools/mavlink.py` | think-augmented 함수호출, 실행 전 think 제거 → `think`는 실행 페이로드에서 제거, 감사 로그로만 보존 |
| 6 | **TOOLQP** 2601.07782 | `tools/mavlink.py` | 대규모 툴셋 쿼리계획 retrieval 라우팅 → **카테고리 우선 라우팅**(전체 툴 스키마 프롬프트 주입 금지) |
| 7 | **tool-memory conflict** 2601.09760 | `nodes/recon.py` | 툴 출력 vs 파라메트릭 메모리 충돌 → **결정론 파싱 > LLM 추측**(HEARTBEAT 등 규칙 파서, 환각 방지) |
| 8 | **AgentDoG** 2601.18491 | `nodes/reflection.py` | 궤적 진단 가드레일(한 스텝 unsafe면 전체 unsafe) → **궤적 로그로 안전 진단**(실패분류·루프탐지) |
| 9 | **ArduPilot control-aware** 2512.01164 | `nodes/validator.py` | ArduPilot 역공학; **COMMAND_ACK 위조 가능** → 자기보고 신뢰 금지, **out-of-band ground truth**로 효과 검증(설계 핵심 D2) |
| 10 | **AgenTRIM** 2601.12449 | `nodes/broker.py` | 스텝별 최소권한·상태인지 게이팅 → **read/write 분할**; write는 등급 상승(HITL 라우팅) |
| 11 | **Mantis** 2410.20911 | `safety/channels.py` | 방어자가 공격 LLM에 프롬프트 인젝션 역공(tarpit) 가능 → **채널 격리** 필요, 표적발=untrusted |
| 12 | **간접 인젝션 방어** 2601.04795 | `safety/toolparse.py` | 스키마 제약 추출로 간접 인젝션 방어(논문 ASR 26%→0.5%) → **생 툴 출력 재투입 금지** |
| 13 | **공격→방어 distillation** 2602.02595 | `mapping/attack_d3fend.py` | "방어하려면 AI에 해킹을 가르쳐야"; 능력등급 릴리스 → Reporter가 **"탐지격차 → 방어 산물"** 산출 |
| 14 | **메모리 서베이** 2602.06052 | `memory/typed_memory.py` | working/episodic/semantic/procedural 타이폴로지 → 에이전트 메모리 3분류(episodic/semantic/procedural) |
| 15 | **Skill-Pro** 2602.01869 ※ | `memory/typed_memory.py` | 경험에서 재사용 스킬 학습 → **절차 메모리**(playbook 효용/사용횟수) |
| 16 | **FadeMem** 2601.18642 ※ | `memory/typed_memory.py` | decay 기반 망각으로 stale 억제 → 메모리 감쇠(episodic 최근 k) |
| 17 | **InfiAgent** 2601.03204 | `memory/typed_memory.py` | 무한-horizon, 파일시스템=권위 상태 → **생 텔레메트리는 프롬프트 밖 append-only**(증거로만, LLM엔 스냅샷+최근 k≈10) |

**정정 노트 (※ — 실재하나 핸드북 인용과 명칭/초점 상이):**
- `2602.01869` — 핸드북 "ProcMEM" → 실제 **"Skill-Pro: Learning Reusable Skills from
  Experience"**. 절차/재사용 스킬 메모리 주제는 일치.
- `2601.18642` — **FadeMem** 맞으나 실제는 *생물학적 망각(decay) 기반*("버전화" 아님). stale
  억제 의도는 일치.

> 상세 §-참조(§1.4·§2.5·§2.7 등)는 [`ARCHITECTURE.md`](ARCHITECTURE.md) **§15 크로스워크**로
> 저장소 안에서 해소된다.

---

## 2. 이식 패턴 — 자매/참조 프로젝트

### 2.1 pollack-ai (방어측 SOC) → **공격판 역전 이식** (B 시리즈)

**핵심 불변식 D8: fried-pollack-ai와 pollack-ai는 별개 프로젝트 — 코드 결합 없음.**
유일한 접점은 단방향 `UAV*_CL`/`soc_alert.json` 브릿지([`ARCHITECTURE.md`](ARCHITECTURE.md) §12).
아래는 방어측 *패턴*을 공격측으로 **역전**해 재구현한 것이지 import가 아니다.

| pollack 원본(방어) | RedTeam 이식(공격, 역전) | 코드 |
|---|---|---|
| `core/settings.py`(SecretStr 마스킹) | 중앙 설정 + stdlib 폴백 | `settings.py` (B4) |
| 구조적 로깅 | `get_logger("redteam.*")` | `logging_util.py` (B3) |
| 결정론 평가 하네스 | PoV 페어 회귀 게이트 | `benchmarks/` (B2) |
| TI 피드 수집 | STIX/ATLAS/KEV 오프라인 시드 | `intel/` (B9) |
| `core/actors.py`(per-adversary 프로파일) | **per-target** 프로파일(역전) | `learning/target_profile.py` (B7) |
| `core/experience.py` | 게이트·서명·dedup 경험 | `learning/experience.py` (B6) |
| `core/outcome.py`·`outcome_probe_agent.py` | 결과 프로브(환경검증만 학습) | `learning/outcome.py` (B8) |
| LLM-as-Judge | judge 앙상블(오라클 veto 하) | `judge/ensemble.py` (B5) |
| LLM 추상화 | 선택적 LLM seam | `llm/` (B10) |

### 2.2 T3MP3ST (공격측 멀티에이전트 플랫폼) → **이식 6종 + 학습 배선**

`references/T3MP3ST/`(TypeScript). 4개 서브시스템 정독 후, fried-pollack-ai 제약(Python·UAV·
Tier-0·단일 파이프라인)에 **맞는 것만 재검토해 이식**했다. (부적합·이미보유는 정직하게 제외.)

| T3MP3ST 원본 | RedTeam 이식 | 코드 |
|---|---|---|
| `redactCredential` | 시크릿 유출 콘텐츠 redaction | `safety/redact.py` (E) |
| `no-phantom-tools` | no-phantom-action 가드 (⚡`satcom_mitm` phantom 적발→실제 T0830/T0831 배선) | `tests/test_no_phantom_action.py` (F) |
| `verify-claims`+anti-fitting+Integrity Ledger | 문서 수치 재파생 가드 | `benchmarks/verify_claims.py` (A) |
| `OpsecController` | 스텔스 탐지 노출 예산(공격측 자기지식) | `opsec.py` (B) |
| OBSIDIVM `obsidivm-ablate` | 컴포넌트 인과기여 계량 | `benchmarks/ablate.py` (C) |
| OBSIDIVM 자기진화(current.md 누적) | 학습→planner 배선(재engagement 무익-스킵 lift) | `nodes/planner.py` |
| refuter 패널(온도 다양성·엄격 다수결) | judge N-skeptic 패널 | `judge/ensemble.py` (D) |

**재검토로 제외**(정직성): refuter cite-check·approve-once(내 오라클 veto·노드 토큰이 더 강함),
context-pack·PackBoard·decomposition orchestrator(단일 파이프라인/무-LLM-계획으로 부적합).

---

## 3. 프레임워크 표준 · 탐지 계약 (요지 내장)

### 3.1 표준
- **MITRE ATT&CK (Enterprise + ICS)** — 공격 기법 어휘. `mapping/attack_d3fend.py`가 각 원자
  액션에 `attack_ics` ID를 매핑. 카탈로그(`intel/catalog.py`)는 23종 커버(런타임검증 22).
- **MITRE ATLAS (AML.T####)** — AI/ML 시스템 공격. ML 평면(`tools/ml_target.py`)이 커버
  (AML.T0043·T0015·T0051·T0057 런타임 + T0020 스테이징).
- **MITRE D3FEND v1.4.0** — 방어 대응. `mapping`이 각 기법에 D3FEND 처방·blind_spot을 동반.
  전술 표기: **Harden**(D3-MAN 서명·D3-MENCR 암호화·D3-ACH 파라미터·D3-PH 호스트/펌웨어) ·
  **Isolate**(D3-NI 격리·**D3-ET 링크암호화/터널**·D3-CF 필터·D3-APA 2인통제) · **Detect**
  (D3-NTA·D3-UBA·D3-PM) · **Model**(D3-OAM) · **Evict**(D3-PE). ※ `D3-ET`는 재검증에서
  Harden→**Isolate**로 정정. **RF/GNSS(S1·JAM)는 D3FEND 미커버 → custom.**

### 3.2 탐지 계약 요지 (이전 `uav_mitre_attack/` 원본 → 여기 내장)

탐지 계약 권위 문서는 Enterprise+ICS를 UAV 환경에 통합한 매트릭스로, `mapping/attack_d3fend.py`와
`engagement_profile.yaml`의 `observables:`가 그 표를 근거한다. **전체 공격→로그→D3FEND 매핑
테이블은 [`ARCHITECTURE.md`](ARCHITECTURE.md) §11에 내장**됐다. 핵심 요지만:

- **관측 로그**: `UAV*_CL` Sentinel 테이블(PascalCase 컬럼) — `UAVOperator_CL`(SourceSystemId·
  Command), `UAVMavsec_CL`(UnsignedCount·FailedCount), `UAVConfigAudit_CL`(ParamId·
  ParamValueAfter), `UAVTelemetry_CL`(PosHorizVariance·FixType), `UAVSatcomLink_CL`
  (IntegrityStatus·Seq·SessionId), `UAVDatalinkConn_CL`(LocalPort·PeerIp), `UAVFailsafe_CL`
  (ModeAfter), `UAVPgse_CL`(HashMatch·SbomForbiddenCount) 등.
- **탐지 커버리지 실측**(원본 요약): Enterprise+ICS 111 기법 중 ✅ 탐지가능 80 · 🔜 배포예정 0 ·
  ❌ 탐지불가 31. ❌ 다수는 *수동 도청·읽기·외부 스테이징*(로그 미발생) → **예방(Harden/Isolate)**
  으로만 대응.
- **사각지대 우선 결론**: D3FEND 미커버(S1 GNSS·JAM)·무서명 인젝션(A4)이 **탐지격차 1순위** →
  보고서 핵심 권고 = "D3-MAN 서명 + RF/GNSS 커스텀 대응".
- **ID 표기 규약**: 비인가 명령 주입 = **T1692.001**(historical `T0855`와 동일 행위, 카탈로그는
  둘 다 보유) · S1 GNSS = **T0835 Manipulate I/O Image**(T0830은 SATCOM S3에 배정).

### 3.3 설계원문 (이전 저장소 밖 → 크로스워크로 대체)

과거 코드 주석의 `§1.4`·`§2.5` 등은 외부 설계원문(`arch/UAV_RedTeam_Agent_Implementation.md`)
기준이었다. 저장소 자립을 위해 각 §를 [`ARCHITECTURE.md`](ARCHITECTURE.md) **§15 크로스워크**로
내부 절에 매핑했다(§2.7 신뢰근거 오라클→ARCHITECTURE §6, §1.6 추상↔HITL→§3.1, §1.7 가역성
테이블→§4.1 등). 원문 전체 편입이 필요하면 **개인정보 스캔 후** `docs/DESIGN.md`를 검토한다.

---

## 4. 재현·검증 포인터

문서의 모든 정량 주장은 커밋된 아티팩트에서 재파생 가능하다:

```bash
python benchmarks/verify_claims.py     # 11 주장 재파생(커버100%·런타임95.7%·ASR1.0·안전위반0…)
python -m pytest -q                     # 182 tests green
python -m benchmarks.check_gates --run  # G1~G4 회귀 게이트
```

- 규모 수치(모듈 68·원자액션 22·기법 23·PoV 8): `find redteam_core -name '*.py' | wc -l` /
  `redteam_core.tools.mavlink.ATOMIC_ACTIONS` / `redteam_core.intel.catalog.coverage()`.
- 논문 인용(17): `grep -rhoE '2[0-9]{3}\.[0-9]{4,5}' redteam_core benchmarks | sort -u`.
