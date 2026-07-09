# 교리 정박 아키텍처 — fried-pollack-ai 레드팀 에이전트

> **문서 목적**: 예선 보고서 6장(AI 에이전트 설계 및 구현)의 근거 문서.
> 미군 사이버작전 교리에 정박한 자율 레드팀 에이전트의 아키텍처·역할·기능·검증을 정리한다.
> **기준일**: DAH 2026 예선 · **산출**: `mara89ma/Red-agent @ feat/closed-loop-bda` (326 tests green)

---

## 0. 한 줄 정의

결정론 레드팀 코어(scaffold/oracle/gate) 위에 **미군 사이버작전 교리에 정박한 26개 고도화 모듈(7개 기능 도메인)**을 코어 불변으로 얹어, red 가 방어자(blue SOC)를 상대로 **완전한 사이버 킬체인 + JP 3-60 타게팅 사이클 + JP 3-0 합동기능**을 수행하는 자율 에이전트. §M~§Z 는 신규 시나리오/캠페인(§M)·ML 페이로드 생성(§N)·승인 체인/임무분리(§O)·KPI 집계(§P)·외부 도구 연동/APT 에뮬레이션(§Q)·공격 템포(§R)·CMT 직무 오케스트레이션(§S)·악성코드 detonation 샌드박스(§T)·시나리오 실 실행기(§U)·WiFi/COTS 드론 공격(§V, dronesploit)·고급 드론 공격(§W, RC링크/DShot/anti-forensics)·GitHub 툴 자동검색(§X)·xbow식 능력/KPI 벤치마크(§Y)·시뮬 기반 센서/환경 공격(§Z, AutoSim)를 더한다. 신규 시나리오는 S35~S71(유출·WiFi·RC·Web/Linux 권한상승·아카이브·다중센서 폴트인젝션)까지 확장된다. 전체 조직은 `docs/CYBER_ORG.md`(USCYBERCOM CMF/CMT 직무)로 오버레이된다.

---

## 1. 설계 철학

- **판정은 모델 밖에 산다(DoDD 3000.09)**: 물리 비가역·교전권한 판정은 LLM 이 아니라 결정론 게이트/오라클에 있다. LLM 은 조언 전용, 오라클 veto 하.
- **3 기둥**: scaffold(능력)=무엇을 할 수 있나 · oracle(진위)=정말 일어났나 · gate(안전)=해도 되나.
- **불변식 D8**: red(fried-pollack-ai) ↔ blue(pollack-ai, SOC)는 **코드 결합 없음**(동언님 `ARCHITECTURE.md:93`). 유일 접점은 단방향 `UAV*_CL` 브릿지. 교리상 OCO/DCO 권한 분리와 정합.
- **탐지 임계의 위치(정정)**: blue 룰의 탐지 임계는 **대부분 `UAV_Threshold_List` watchlist 로 외부화**(S3·S9·S15·S16·S22·S25·C2·C3·C5 등 — `ThresholdKey/Value` 행, 쿼리 무수정 튜닝). 예외적으로 S6(`FailCount>=5/3`)·S1(`zScoreThreshold=3.0`·`gateMultiplier=1.5`)은 쿼리 리터럴. §A 는 이 룰 정의에서 임계를 **수동 씨앗 복사**할 뿐 pollack-ai/룰 repo 에 런타임 의존하지 않는다(D8 준수).
- **결정론 Tier-0**: 전 층이 LLM/네트워크/SITL 없이 실행·검증 가능(§K 전송·§L 지속만 실 소켓/FS, loopback 실검증).

---

## 2. 아키텍처 스택 (기능 도메인)

> 레이어는 순차 알파벳(§A~§Z) 대신 **기능 도메인**으로 조직한다. 모듈 디렉토리명이 곧
> 조직이며, §-라벨은 초기 색인의 잔재다(기존 docstring/커밋의 §-표기는 무해, 신규 모듈엔 미부여).

```
┌──────────────────────────────────────────────────────────────┐
│ 킬체인 오케스트레이션 (7단계 end-to-end 관통)                │  통합
├──────────────────────────────────────────────────────────────┤
│ 표적개발(CARVER/HPTL) │ 기동/측면이동 │ 작전지속력          │  계획·기동·지속
│ 적응 재계획(OODA)     │ MILDEC(기만)                        │
├──────────────────────────────────────────────────────────────┤
│ 폐루프 BDA(탐지관측·임계보정) │ 전투평가(MOE/MOP·재타격)    │  관측·평가
├──────────────────────────────────────────────────────────────┤
│ RoE 교전권한 게이트(권한·PID·ConOps·CDE·JCEOI)              │  교전통제
├──────────────────────────────────────────────────────────────┤
│ EMSO(J/S·포획) │ 실전송(C2·전달) │ 설치/지속(발판)          │  효과·전송·지속
├──────────────────────────────────────────────────────────────┤
│ [동언 코어] recon→planner→checker→broker→hitl→executor→     │  결정론 실행
│             validator→reflection→reporter · 3기둥 · 22액션  │
└──────────────────────────────────────────────────────────────┘
   D8: blue 와 코드 결합 없음 — 공유 산출물(룰)만 참조
```

### 기능 도메인별 모듈

#### 공격면 (Attack Surface)
| 모듈 | 기능 | 교리 근거 |
|---|---|---|
| `emso/` | 전자공격(EA): 재밍 J/S 번스루·GNSS 포획마진 → PosHorizVariance 강도 | JP 3-85 JEMSO |
| `targeting/` | CARVER 표적가치 → HPTL, 교전결과(사각/차단)로 동적 재우선순위화 | JP 3-60 ② |
| `maneuver/` | 사이버 지형 순회: 초기접근→측면이동→효과, 차단시 재경로 | JP 3-12·ATT&CK |
| `transport/` | 실 전송: TCP C2 비콘 + UDP(GPS/PARAM/MISSION)/HTTP, loopback 검증 | 킬체인 3·6단계 |
| `persistence/` | FileImplant(재부팅 생존)·ParamImplant(EEPROM)·Foothold | 킬체인 5단계 |
| `payloads/` | ML 공격 페이로드 생성기(PyRIT/Garak식)+AdaptivePayloadGenerator+exploits | ATLAS |
| `dronesploit/` | WiFi(deauth·evil twin·재밍·기본자격 S39~S42)+COTS 표적+모듈+CVE | 802.11 |
| `advanced/` | RC 링크(DSMX/FrSky/ELRS)·DShot 모터·anti-forensics S43~S47+기법카탈로그 | Awesome-Drone |
| `simtest/` | 다중센서 폴트인젝션 S56~S59(EKF 우회)+환경 증폭+인시던트KB+비행로그 오라클 | AutoSim |
| `groundseg/` | 지상 세그먼트 소프트웨어 공격 S86~S99(GCS 앱·ROS·데이터링크·클라우드). execute_real 실 실행 | 지상/클라우드 공격면 |

#### 킬체인·실행 (Kill Chain / Execution)
| 모듈 | 기능 | 교리 근거 |
|---|---|---|
| `killchain/` | 7단계 end-to-end 관통 판정(전달·지속·C2) | Lockheed Kill Chain |
| `campaigns/` | 신규 시나리오 + 캠페인 체인 C8~C18 실행·탐지 프로파일 | 시나리오 보강 |
| `execute/` | 시나리오 실 실행기: 카테고리별 실 아티팩트 생성·전송(dry-run 기본, 실전송=샌드박스 fail-closed) | 실 공격 실행 |

#### 적응·폐루프 (Adaptive / Closed-loop)
| 모듈 | 기능 | 교리 근거 |
|---|---|---|
| `assessment/bda,loop` | red 방출을 blue 실룰로 평가 → 탐지 관측 → 강도 이분탐색 임계 실측 보정 | JP 3-60 ⑥ |
| `assessment/combat` | MOP(임무수행)·MOE(효과+생존성)·재타격 권고 | JP 3-60 ⑥ |
| `assessment/replan` | 재타격 실행: 회피창시 강도↓, 효과바닥≥탐지임계면 TTP 피벗(사각 노출) | Persistent Engagement·OODA |

#### 평가·KPI·벤치마크 (Assessment / Metrics)
| 모듈 | 기능 | 교리 근거 |
|---|---|---|
| `audit/` | 검증 강도 감사 — real_exec(실행검증)/grounded_model/self_model 분류(정직성 계층) | 자기기만 방지 |
| `kpi/` | KPI 10종(방어공백·dwell·임계보정·MITRE·RoE·재타격·MEA·임무영향·MOE·BDA) | JP 3-60/3-12/5-0 |
| `benchmark/` | xbow식 챌린지+탐지회피 채점(달성 AND 미탐지)+KPI 스코어카드(근거화·라운드 추세)+외부 어댑터 | xbow·MITRE Eval·M-Trends |

#### 안전·통제 (Safety / Command)
| 모듈 | 기능 | 교리 근거 |
|---|---|---|
| `roe/` | 교전권한(NONE→NATIONAL)·PID·ConOps·CDE·JCEOI 판정(PERMITTED/ESCALATE/BLOCKED) | SROE·JP 3-60/3-85·CJCSM 3160 |
| `command/` | 승인 체인(EXORD 프록시): 고권한 fail-closed + 임무분리 불변식 | SROE·지휘체계 |
| `sandbox/` | detonation 샌드박스(opt-in): FS 격리+롤백·egress default-deny·악성 판정 | 격리 시험환경 |

#### 조직·기만·지속 (Org / Deception / Sustainment)
| 모듈 | 기능 | 교리 근거 |
|---|---|---|
| `mission_command/` | 임무형 지휘 — 사람 1회 미션 프로필→오케스트레이터 자율 지휘(의도 분해·RoE 상한 자율보류) | Auftragstaktik·Mission Command |
| `orchestration/` | CMT 직무 협업 MC→TDNA→ION→BDA (USCYBERCOM CMF) | 사이버작전 조직 |
| `tempo/` | 공격 템포: low-and-slow(∞MTTD) vs smash(즉효·즉탐지) 시간지표 갭 | OODA 템포 |
| `deception/` | 미끼로 SOC 분석주의 포화 → 진짜 공격 은폐 | JP 3-13.4 MILDEC |
| `sustainment/` | TTP 소모(burn) 순환 → 목표별 지속력 산정 | JP 3-0/4-0 |

#### 연동·발견 (Integration / Discovery)
| 모듈 | 기능 | 교리 근거 |
|---|---|---|
| `integrations/` | 외부 도구 opt-in seam: AI공격·Caldera·SITL·TI·APT 에뮬레이션·Metasploit·CVE | 실 연동(env) |
| `toolsearch/` | 공격 막힐 때 GitHub 툴 자동검색(라이브 GITHUB_TOKEN/큐레이션 시드), 읽기전용 | 능력갭→도구발견 |

#### 결정평면 (Decision-Plane, 교리 5종)
> 개별 센서·판정이 아니라 '융합·재조합·Orient·기록·지휘' 결정평면을 노림.

| 모듈 | 기능 | 교리 근거 |
|---|---|---|
| `jadc2/` | 융합 레이어 공격 — 다중센서 정합성(개별미탐+거짓상관 FP/진짜를 노이즈 FN)+메시 저하 테스트 | JADC2 |
| `mosaic/` | 재조합 로직 공격 + judge **실 introspection** 독립성 검증(common-mode) | Mosaic Warfare/Kill Web |
| `ooda/` | Orient-phase denial(S29 재프레임)+red↔blue OODA 속도경쟁 스코어보드 | OODA(Boyd) |
| `information/` | 리포팅/증거체인 공격 S100~S102(SOCReport·OSCAL·PR 위조). execute_real 실 실행 | 정보(7번째 합동기능, JP 3-0) |

---

## 3. 통합 킬체인 제어 흐름

```
§F 표적개발(CARVER→HPTL)
 └→ §G 기동(지형 순회·측면이동, 차단시 재경로)
     └→ §B RoE 게이트(교전권한·PID·JCEOI) ──BLOCKED→ 중단
         └→ §C EMSO / §K 실전송(효과·전달)
             └→ §A BDA(blue 실룰로 탐지 관측)
                 └→ §D 전투평가(MOP·MOE·생존성)
                     └→ §E 적응(탐지시 강도↓ or TTP 피벗) ⟳
                         └→ §H MILDEC(미끼로 SOC 포화 은폐)
                             └→ §I 지속(TTP 소모 순환)
                                 └→ §F 재우선순위화 ⟲(표적 순환)
```

---

## 4. 교리 정합 — 3 렌즈 (구조·역할·기능)

### 4-1. 구조 (Structure) — 아키텍처 ↔ 사이버임무군(CMF)

에이전트 = **OCO 요소(CMT 유사체)**, 내부가 임무요소 편성을 닮음.

| 임무요소(교리) | 에이전트 모듈 |
|---|---|
| 지휘(Mission Cdr) | broker·hitl·reflection + §B RoE |
| 계획(Plans) | planner + §F 표적개발/HPTL |
| 작전(Ops) | executor + §C EMSO + §K 전송 |
| 정보(Intel) | recon + §A BDA + §F 표적정보 |
| 화력통제/권한 | 코어 gate + §B RoE·CDE·JCEOI |
| 평가(Assessment) | §D 전투평가 |

### 4-2. 역할 (Roles) — 모듈 ↔ DCWF/JP 3-60 직무

| 모듈 | 대응 직무 |
|---|---|
| planner·§F | Target Digital Network Analyst · Target Developer |
| §C EMSO·§K | Electronic Warfare Operator · Interactive On-Net Operator |
| recon·§A | Exploitation Analyst · BDA Analyst |
| §B·gate·HITL | Mission Cdr · Legal(RoE) · 무장해제권한 |
| reflection·§E | Ops(적응 재계획) |
| reporter/bridge | Dissemination(F3EAD-D) → DCO 핸드오프 |

### 4-3. 기능 (Functions) — ↔ 합동기능(JP 3-0, 7대)

| 합동기능 | 대응 층 | 충족 |
|---|---|---|
| 지휘통제 C2 | broker/hitl + §B | 🟢 |
| 정보 Intelligence | recon·§A·§F | 🟢 |
| 화력 Fires | executor·§C | 🟢 |
| 기동 Movement&Maneuver | §G | 🟢 |
| 방호 Protection | §B + safety | 🟢 |
| 지속 Sustainment | §I | 🟢 |
| 정보활동 Information | §H MILDEC·§C | 🟢 |

---

## 5. 킬체인 7단계 검증

| # | 단계 | 수행 | 근거 |
|---|---|---|---|
| 1 | 정찰 Recon | ✅ | recon·active_scan·§A·§F |
| 2 | 무기화 Weaponization | ✅ | 무기고 catalog(23기법)·§C |
| 3 | 전달 Delivery | ✅ 실전송 | §K UDP(GPS/PARAM/MISSION 프레임)·HTTP — loopback 실증 |
| 4 | 악용 Exploitation | ✅ | force_arm·gnss_spoof 포획·§C |
| 5 | 설치/지속 Installation | ✅ 실 메커니즘 | §L FileImplant(재부팅 생존)·ParamImplant(EEPROM 백도어)·§I |
| 6 | C2 | ✅ 실전송 | §K 실 TCP 지속비콘(자동 재접속, T0885) |
| 7 | 목표행동 Actions | ✅ | §E·§D·§H |

**관통 실증**: GNSS 표적 은밀기법 → 🥷 은밀 관통 / 소란기법 → 완전 관통(탐지) / 무장 표적 → 6단계 도달하나 목표행동 견고 차단(미완주).

---

## 6. 핵심 발견 (blue 방어 보강 산출)

레드 교전 결과가 곧 방어 진단이다:

- **무장 목표(범주형 룰 S11/S15)**: red 가 회피·지속·도달 **전부 실패** → blue 견고. (2인통제·비인가검사 유효)
- **항법(GNSS)**: 효과바닥(0.05) > blue S1 게이트(0.0238) → 효과 내면 항상 탐지되나, **GNSS 재밍(jam)은 미매핑 사각지대** → red 피벗 성공. **⇒ blue 보강 1순위: GNSS 재밍 탐지룰 신설.**
- **정찰(S6)**: 연속임계(5)에 회피창 존재 → 강도 하향 회피 가능. **⇒ blue 보강: 저율 브루트포스 누적 탐지.**
- **임계 실측 보정(§A)**: S6 회피≤3/탐지≥6(가상값 5), S1 경계~0.0188(가상값 0.0238) — blue 가상값을 실측으로 대체 가능. **`UAV_Threshold_List` 로 외부화된 룰(다수)은 §A 보정값을 watchlist `Value` 갱신으로 반영(쿼리 무수정) = 깔끔한 퍼플팀 루프.** S6·S1 등 리터럴 룰만 쿼리 임계 수정 필요.

---

## 7. 검증 상태

- **442 테스트 green** (동언 코어 182 불변 + 고도화 260), 전부 결정론 Tier-0(§K/§L/§Q/§T/§U/§X만 실 소켓/FS·env seam).
- 층별 실행 데모 20+종: `benchmarks/*_eval.py` (closed_loop·roe·emso·combat·replan·targeting·maneuver·deception·sustainment·killchain·infra·campaign_chains·s30·s31_34·kpi_report·integrations·threat_intel·apt_emulation …).
- **§P KPI 요지**: 사각지대율·은밀관통 캠페인·임계보정·MEA·임무영향(MRT-C) 등 JP 3-60/3-12/5-0 평가 지표 커버(시간지표 MTTD만 라이브).
- **§Q 외부연동**: 전부 opt-in seam(env→real / 미지정→결정론 폴백). APT 에뮬레이션 8종(한국 방산 관련 Lazarus·Kimsuky 포함).
- **핵심 발견(§M~§Q)**: **AI 계층(RAG·온보드AI·프롬프트인젝션·모델추출·군집)이 전부 blue 미배포 = 유일한 완전 은밀 관통 APT(AML)**. 방어 보강 1순위=AI 계층, 2순위=GNSS/C2 재밍(S30/S31).
- 산출: `github.com/mara89ma/Red-agent @ feat/closed-loop-bda`, 12 커밋.

## 8. 남은 작업 (본선)

- **라이브 스모크만 잔여**: §K 전송·§L 지속의 코드 경로·전송은 완성(loopback 실증). 실제 uav-sim-env SITL/mavlink-router/FastAPI 스텁 엔드포인트로 env 지정(`MAVLINK_ENDPOINT`/`C2_HOST`/`STUB_URL`) 후 1회 라이브 스모크만 남음(SITL 클러스터 필요).
- 실 Sentinel 관측: §A BDA 의 관측 채널을 오프라인 룰-평가에서 라이브 Log Analytics Incident 조회로 스왑.
