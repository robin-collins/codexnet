"""Secret-safe structured application logging."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from field_discovery.redaction import Redactor

_STANDARD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)


class StructuredFormatter(logging.Formatter):
    """Render deterministic fields as JSON or plain, ANSI-free text."""

    def __init__(self, *, json_mode: bool, run_id: str, redactor: Redactor | None = None) -> None:
        super().__init__()
        self.json_mode = json_mode
        self.run_id = run_id
        self.redactor = redactor or Redactor()

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")
        event = self.redactor.text(record.getMessage())
        raw_fields = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _STANDARD_FIELDS and key not in {"message", "asctime"}
        }
        fields = self.redactor.value(raw_fields)
        if record.exc_info and record.exc_info[1] is not None:
            fields["error"] = self.redactor.exception(record.exc_info[1])
        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname.lower(),
            "event": event,
            "run_id": self.run_id,
        }
        payload.update(fields)
        if self.json_mode:
            return json.dumps(payload, sort_keys=True, separators=(",", ":"))
        suffix = "" if not fields else f" {json.dumps(fields, sort_keys=True)}"
        return f"{timestamp} {record.levelname.lower()} run_id={self.run_id} {event}{suffix}"


def configure_logging(*, json_mode: bool, run_id: str) -> logging.Logger:
    """Configure the application logger without changing the root logger."""
    logger = logging.getLogger("field_discovery")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter(json_mode=json_mode, run_id=run_id))
    logger.addHandler(handler)
    return logger
