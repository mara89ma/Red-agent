# 미군 사이버작전 조직 구조 매핑 (USCYBERCOM CMF)

> 본 에이전트를 **USCYBERCOM 사이버임무군(Cyber Mission Force, CMF)**의 조직 구조로
> 정리한다. 파일/레이어(§-)는 그대로 두고, 각 기능을 **사이버작전 직무(work roles)**에
> 매핑하는 조직 오버레이다(교리: JP 3-12, DCWF/JCT&CS).

---

## 1. CMF 편성 속 위치

| CMF 팀 | 임무 | 대응 |
|---|---|---|
| **CMT** (Cyber Combat Mission Team) | **OCO**(공격) — 전투사령부 지원 | ← **본 에이전트(red)** |
| CPT (Cyber Protection Team) | **DCO**(방어) — DoD망 보호 | blue SOC(pollack-ai) |
| NMT (National Mission Team) | 국가급 공세 | (상급) |
| CST (Cyber Support Team) | 분석·기획 지원 | 인텔/평가 직무 |

> **본 에이전트 = OCO 수행 CMT.** blue(방어)와의 관계는 CMT↔CPT(OCO↔DCO) 권한 분리(D8).

---

## 2. CMT 직무(Work Roles) ↔ 에이전트 기능

| 직무 (DCWF/JCT&CS) | 코드 | 담당 기능(레이어) |
|---|---|---|
| **Mission Commander** | MC | 교전 권한·승인(§B RoE·gate·HITL·command 승인체인) |
| **Cyber Operations Planner** | COP | 작전 기획(planner·§F HPTL·campaigns·CMT orchestration) |
| **Target Digital Network Analyst** | TDNA | 표적개발·정보(§F targeting·TI 위협행위자·recon) |
| **Exploitation Analyst** | EA | 취약점·효과 분석(§C EMSO·ML payloads) |
| **Interactive On-Net Operator** | ION | 온넷 실행(executor·§E 적응·§G 기동·killchain·transport·persistence·tempo) |
| **All-Source / BDA Analyst** | ASA/BDA | 전투피해평가·정보종합(§A BDA·§D 전투평가·KPI·APT 에뮬레이션) |

---

## 3. 작전 유형 (JP 3-12)

- **OCO** (Offensive Cyberspace Operations) — 본 에이전트. 효과: Deny(Degrade/Disrupt/Destroy)·Manipulate.
- **DCO** (Defensive) — blue SOC.
- **DODIN Ops** — 네트워크 운영(범위 밖).

---

## 4. CMT 협업 흐름 (orchestration 모듈이 실현)

```
MC(교전권한 §B) ──승인──▶ TDNA(표적개발·정보 §F·TI)
                              └▶ EA(효과분석 §C·payloads)
                                   └▶ ION(온넷 실행 §E·killchain)
                                        └▶ BDA(전투피해평가 §A·§D)
                                             └▶ (재타격/표적순환)
```
`redteam_core/orchestration` 이 이 직무 협업을 결정론으로 수행한다
(`run_cmt_campaign`). 판정권은 각 직무의 결정론 층에 있고 모델 밖이다(DoDD 3000.09).

---

## 5. 지휘체계·권한 (승인 체인)

- **Mission Commander(MC)** 가 교전 전 §B RoE 로 권한을 판정: PERMITTED/ESCALATE/BLOCKED.
- 고권한 액션(물리 비가역·고 CDE)은 상급 승인(EXORD 프록시, command 층) 없이 **fail-closed**.
- 임무분리(separation of duties) 불변식으로 단일 직무의 독단 실행을 차단.

> 즉 본 CMT 는 "권한은 모델 밖·상급 승인 필수"라는 미군 사이버작전 지휘체계를
> 결정론 게이트로 구현한다.
