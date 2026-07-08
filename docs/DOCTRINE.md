# 교리 정박 아키텍처 — fried-pollack-ai 레드팀 에이전트

> **문서 목적**: 예선 보고서 6장(AI 에이전트 설계 및 구현)의 근거 문서.
> 미군 사이버작전 교리에 정박한 자율 레드팀 에이전트의 아키텍처·역할·기능·검증을 정리한다.
> **기준일**: DAH 2026 예선 · **산출**: `mara89ma/Red-agent @ feat/closed-loop-bda` (244 tests green)

---

## 0. 한 줄 정의

결정론 레드팀 코어(scaffold/oracle/gate) 위에 **미군 사이버작전 교리에 정박한 11개 고도화 층(§A~§K)**을 코어 불변으로 얹어, red 가 방어자(blue SOC)를 상대로 **완전한 사이버 킬체인 + JP 3-60 타게팅 사이클 + JP 3-0 합동기능**을 수행하는 자율 에이전트.

---

## 1. 설계 철학

- **판정은 모델 밖에 산다(DoDD 3000.09)**: 물리 비가역·교전권한 판정은 LLM 이 아니라 결정론 게이트/오라클에 있다. LLM 은 조언 전용, 오라클 veto 하.
- **3 기둥**: scaffold(능력)=무엇을 할 수 있나 · oracle(진위)=정말 일어났나 · gate(안전)=해도 되나.
- **불변식 D8**: red(fried-pollack-ai) ↔ blue(pollack-ai, SOC)는 **코드 결합 없음**(동언님 `ARCHITECTURE.md:93`). 유일 접점은 단방향 `UAV*_CL` 브릿지. 교리상 OCO/DCO 권한 분리와 정합.
- **탐지 임계의 위치(정정)**: blue 룰의 탐지 임계는 **대부분 `UAV_Threshold_List` watchlist 로 외부화**(S3·S9·S15·S16·S22·S25·C2·C3·C5 등 — `ThresholdKey/Value` 행, 쿼리 무수정 튜닝). 예외적으로 S6(`FailCount>=5/3`)·S1(`zScoreThreshold=3.0`·`gateMultiplier=1.5`)은 쿼리 리터럴. §A 는 이 룰 정의에서 임계를 **수동 씨앗 복사**할 뿐 pollack-ai/룰 repo 에 런타임 의존하지 않는다(D8 준수).
- **결정론 Tier-0**: 전 층이 LLM/네트워크/SITL 없이 실행·검증 가능(§K 전송만 loopback).

---

## 2. 11층 아키텍처 스택

```
┌──────────────────────────────────────────────────────────────┐
│ §J 킬체인 오케스트레이션 (7단계 end-to-end 관통)              │  통합
├──────────────────────────────────────────────────────────────┤
│ §F 표적개발(CARVER/HPTL) │ §G 기동/측면이동 │ §I 작전지속력   │  계획·기동·지속
│ §E 적응 재계획(OODA)     │ §H MILDEC(기만)                    │
├──────────────────────────────────────────────────────────────┤
│ §A 폐루프 BDA(탐지관측·임계보정) │ §D 전투평가(MOE/MOP·재타격)│  관측·평가
├──────────────────────────────────────────────────────────────┤
│ §B RoE 교전권한 게이트(권한·PID·ConOps·CDE·JCEOI)            │  교전통제
├──────────────────────────────────────────────────────────────┤
│ §C EMSO 전자전(J/S·포획) │ §K 실 전송(TCP C2·UDP/HTTP 전달)  │  효과·전송
├──────────────────────────────────────────────────────────────┤
│ [동언 코어] recon→planner→checker→broker→hitl→executor→       │  결정론 실행
│             validator→reflection→reporter · 3기둥 · 22액션    │
└──────────────────────────────────────────────────────────────┘
   D8: blue 와 코드 결합 없음 — 공유 산출물(룰)만 참조
```

### 층별 요약

| 층 | 모듈 | 기능 | 교리 근거 |
|---|---|---|---|
| §A | `assessment/bda,loop` | red 방출 `UAV*_CL` 을 blue 실제 S1~S28 룰로 평가 → 탐지 관측 → 강도 이분탐색으로 blue 가상값 임계 실측 보정 | JP 3-60 ⑥ (전투평가) |
| §B | `roe/` | 교전권한 레벨(NONE→NATIONAL)·PID·ConOps 범위·CDE 부수효과·JCEOI 스펙트럼 데컨플릭션 판정(PERMITTED/ESCALATE/BLOCKED) | SROE·JP 3-60 ④·CJCSM 3160·JP 3-85 |
| §C | `emso/` | 전자공격(EA): 재밍 J/S 번스루·GNSS 포획마진 → PosHorizVariance 강도. blue counter-uas RF 모델과 대칭 | JP 3-85 JEMSO |
| §D | `assessment/combat` | MOP(임무수행)·MOE(효과+생존성)·재타격권고(강도↓/상향/TTP전환) | JP 3-60 ⑥ (MOE/MOP) |
| §E | `assessment/replan` | 재타격 실행: 회피창 있으면 강도 하향, 효과바닥≥탐지임계면 TTP 피벗(사각지대 노출) | Persistent Engagement·OODA |
| §F | `targeting/` | CARVER 표적가치 → HPTL. 교전결과(사각/차단)로 취약성 갱신 → 동적 재우선순위화 | JP 3-60 ② |
| §G | `maneuver/` | 사이버 지형 그래프 순회: 초기접근→측면이동→효과, 차단시 재경로 | JP 3-12·ATT&CK Lateral Movement |
| §H | `deception/` | 미끼로 SOC 분석주의 포화 → 진짜 공격 은폐. blue S8/S9 임계 역이용 | JP 3-13.4 MILDEC |
| §I | `sustainment/` | TTP 소모(burn) 순환: 탐지된 TTP 는 시그니처 노출로 소진 → 목표별 지속력 산정 | JP 3-0/4-0 Sustainment |
| §J | `killchain/` | 7단계 오케스트레이션: 전달 벡터·지속성(발판/임플란트)·C2(상용포트/불량라우터) 채워 end-to-end 관통 판정 | Lockheed Kill Chain |
| §K | `transport/` | 실 전송: TCP C2 비콘 채널 + UDP(mavlink-router)/HTTP(스텁) 전달. loopback 실검증 | 킬체인 3·6단계 실체화 |

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
| 3 | 전달 Delivery | ✅ | §J 도달성 + §K 실전송(UDP/HTTP) |
| 4 | 악용 Exploitation | ✅ | force_arm·gnss_spoof 포획·§C |
| 5 | 설치/지속 Installation | ✅ | §J 지속성(발판/임플란트)·§I |
| 6 | C2 | ✅ | §J + §K 실 TCP 비콘(T0885) |
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

- **244 테스트 green** (동언 코어 182 불변 + 고도화 62), 전부 결정론 Tier-0.
- 층별 실행 데모 11종: `benchmarks/{closed_loop,roe,emso,combat,replan,targeting,maneuver,deception,sustainment,killchain}_eval.py`.
- 산출: `github.com/mara89ma/Red-agent @ feat/closed-loop-bda`, 12 커밋.

## 8. 남은 작업 (본선)

- 실 인프라 라이브 검증: §K 실전송을 실제 uav-sim-env SITL/mavlink-router/FastAPI 스텁 엔드포인트로 연결(env 지정). 현재는 loopback 실검증.
- 실 Sentinel 관측: §A BDA 의 관측 채널을 오프라인 룰-평가에서 라이브 Log Analytics Incident 조회로 스왑.
