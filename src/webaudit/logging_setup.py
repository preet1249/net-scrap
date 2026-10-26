"""Structured (JSON-lines) logging with a defensive redaction filter."""
from __future__ import annotations

import json
import logging
import re
import sys
import time

_SECRET_IN_MSG = re.compile(r"(?i)(authorization|cookie|set-cookie|token|secret|password)\s*[:=]\s*(?:(?:bearer|basic)\s+)?\S+")


class _RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _SECRET_IN_MSG.sub(lambda m: f"{m.group(1)}=[REDACTED]", str(record.getMessage()))
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": round(time.time(), 3),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "ctx", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: str = "INFO", log_file: str | None = None) -> None:
    root = logging.getLogger("webaudit")
    root.handlers.clear()
    root.setLevel(level)
    for h in ([logging.StreamHandler(sys.stderr)] + ([logging.FileHandler(log_file, encoding="utf-8")] if log_file else [])):
        h.setFormatter(JsonFormatter())
        h.addFilter(_RedactFilter())
        root.addHandler(h)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"webaudit.{name}")
