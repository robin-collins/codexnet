"""Tests for structured, redacted application logging."""

from __future__ import annotations

import json
import logging

from field_discovery.logging import StructuredFormatter, configure_logging
from field_discovery.redaction import REDACTED, Redactor


def record(message: str, **fields: object) -> logging.LogRecord:
    result = logging.LogRecord("test", logging.INFO, __file__, 1, message, (), None)
    for key, value in fields.items():
        setattr(result, key, value)
    return result


def test_json_formatter_has_stable_structure_and_redacts() -> None:
    formatter = StructuredFormatter(
        json_mode=True, run_id="run-123", redactor=Redactor(["synthetic-secret"])
    )
    output = formatter.format(
        record("request token=synthetic-secret", target="fixture", password="hidden")
    )
    payload = json.loads(output)
    assert payload["run_id"] == "run-123"
    assert payload["level"] == "info"
    assert payload["event"] == f"request token={REDACTED}"
    assert payload["password"] == REDACTED
    assert payload["timestamp"].endswith("+00:00")
    assert "\x1b" not in output


def test_human_formatter_includes_fields_and_safe_exception() -> None:
    formatter = StructuredFormatter(json_mode=False, run_id="run-456")
    log_record = record("collector_failed", command="collect snmp")
    try:
        raise ValueError("password=synthetic")
    except ValueError:
        log_record.exc_info = __import__("sys").exc_info()
    output = formatter.format(log_record)
    assert "run_id=run-456 collector_failed" in output
    assert '"command": "collect snmp"' in output
    assert f"ValueError: password={REDACTED}" in output


def test_human_formatter_without_fields_and_logger_configuration(capsys: object) -> None:
    formatter = StructuredFormatter(json_mode=False, run_id="fixed")
    assert formatter.format(record("ready")).endswith("run_id=fixed ready")
    logger = configure_logging(json_mode=True, run_id="configured")
    logger.info("started")
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert json.loads(captured.err)["run_id"] == "configured"
    assert not captured.out
