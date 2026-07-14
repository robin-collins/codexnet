"""Central structural and textual secret redaction contract."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"(?:password|passphrase|token|api[_-]?key|community|authorization|cookie|secret|private[_-]?key)",
    re.IGNORECASE,
)
_AUTH = re.compile(r"(?i)\b(authorization\s*[:=]\s*)([^\s,;]+)")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passphrase|token|api[_-]?key|community|cookie|client_secret)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
_URI_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/:@]+:)([^\s/@]+)(@)", re.IGNORECASE)


class Redactor:
    """Redact known values, common encodings, and structural secret fields."""

    def __init__(self, secrets: Sequence[str] = ()) -> None:
        variants: set[str] = set()
        for secret in secrets:
            if len(secret) < 4:
                continue
            raw = secret.encode()
            variants.update(
                {
                    secret,
                    quote(secret, safe=""),
                    base64.b64encode(raw).decode(),
                    base64.urlsafe_b64encode(raw).decode(),
                }
            )
        self._variants = tuple(sorted(variants, key=len, reverse=True))

    def text(self, value: object) -> str:
        """Return text with known and structural secret forms removed."""
        result = str(value)
        for variant in self._variants:
            result = result.replace(variant, REDACTED)
        result = _AUTH.sub(r"\1" + REDACTED, result)
        result = _ASSIGNMENT.sub(r"\1\2" + REDACTED, result)
        return _URI_USERINFO.sub(r"\1" + REDACTED + r"\3", result)

    def value(self, value: Any) -> Any:
        """Recursively redact mappings and sequences before output boundaries."""
        if isinstance(value, Mapping):
            return {
                str(key): REDACTED if _SENSITIVE_KEY.search(str(key)) else self.value(child)
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [self.value(child) for child in value]
        if isinstance(value, tuple):
            return tuple(self.value(child) for child in value)
        if isinstance(value, str):
            return self.text(value)
        return value

    def exception(self, exc: BaseException) -> str:
        """Render an exception without traceback arguments or unredacted content."""
        return f"{type(exc).__name__}: {self.text(exc)}"
