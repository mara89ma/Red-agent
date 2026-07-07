"""구조화 로깅 — 단일 `get_logger` 팩토리 (§방어측 utils/logging.py 이식).

라이브러리 진단은 `print()`가 아니라 `get_logger("<name>")`로. CLI 표/리포트
같은 사용자 대면 stdout 출력은 예외(그건 UI다). 네임스페이스는 `redteam.*`,
레벨은 `Settings.log_level`(env `REDTEAM_LOG_LEVEL`)에서 온다.
"""

from __future__ import annotations

import logging
import sys

from .settings import get_settings

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def get_logger(name: str) -> logging.Logger:
    """`redteam.<name>` 로거. 핸들러 1회 부착, 레벨은 설정에서."""
    logger = logging.getLogger(f"redteam.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(handler)
        logger.propagate = False
    level_name = str(get_settings().log_level).upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))
    return logger
