"""campaigns — 캠페인 체인(2층 상관) 실행 (고도화 §M).

개별 시나리오를 순서 시퀀스로 엮은 캠페인 체인(C1~C10)을 에이전트로 실행해,
각 단계의 탐지 여부로 체인의 '은밀 관통/탐지 관통/차단'을 판정한다.
핵심 산출: 어느 단계에서 blue 가 체인을 잡는가(= 방어 상관룰 유효성).
"""
from .chains import CHAINS, ChainResult, run_chain
from .detail import ChainDetail, StageDetail, chain_detail

__all__ = ["CHAINS", "ChainResult", "run_chain",
           "ChainDetail", "StageDetail", "chain_detail"]
