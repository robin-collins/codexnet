"""Central structural and textual secret redaction contract."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"^(?:password|passwd|pwd|passphrase|token|access_token|api[_-]?key|community|"
    r"authorization|authentication|cookie|secret|client_secret|auth_key|priv_key|private_key)$",
    re.IGNORECASE,
)
_QUOTED_AUTH_DOUBLE = re.compile(
    r'(?i)((?:b)?"(?:authorization|authentication)"\s*:\s*(?:b)?)(")'
    r'((?:\\.|[^"\\])*)(")'
)
_QUOTED_AUTH_SINGLE = re.compile(
    r"(?i)((?:b)?'(?:authorization|authentication)'\s*:\s*(?:b)?)(')"
    r"((?:\\.|[^'\\])*)(')"
)
_ESCAPED_AUTH_DOUBLE = re.compile(
    r'(?i)(\\"(?:authorization|authentication)\\"\s*:\s*)(\\")'
    r'((?:(?!\\").)*)(\\")'
)
_AUTH_HEADER = re.compile(
    r"(?i)\b((?:authorization|authentication)\s*[:=]\s*)"
    r"([^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)"
)
_STRUCTURED_FIELD = re.compile(
    r",\s*(?P<quote>[\"']?)(?P<key>[a-z_][a-z0-9_-]*)(?P=quote)\s*[:=]",
    re.IGNORECASE,
)
_SEMICOLON_FIELD = re.compile(r";(?=\s)")
_AUTH_PARAMETERS = {
    "algorithm",
    "cnonce",
    "credential",
    "nc",
    "nonce",
    "opaque",
    "qop",
    "realm",
    "response",
    "signature",
    "signedheaders",
    "uri",
    "username",
}
_ASSIGNMENT = re.compile(
    r"(?im)\b(password|passwd|pwd|passphrase|token|access_token|api[_-]?key|community|"
    r"cookie|client_secret|secret|auth_key|priv_key|private_key)"
    r"(\s*[:=]\s*)"
    r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    r'|"(?:\\.|[^"\\\r\n;])*(?=;|\r?$)'
    r"|'(?:\\.|[^'\\\r\n;])*(?=;|\r?$)|[^\s,;]+)"
)
_URI_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/:@]*:)([^\s/@]+)(@)", re.IGNORECASE)


def _redact_quoted_authorization(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}{REDACTED}{match.group(4)}"


def _redact_authorization_header(match: re.Match[str]) -> str:
    value = match.group(2)
    boundary = len(value)
    semicolon = _SEMICOLON_FIELD.search(value)
    if semicolon:
        boundary = semicolon.start()
    parameterized = False
    for field in _STRUCTURED_FIELD.finditer(value):
        if field.start() >= boundary:
            break
        parameterized = parameterized or "=" in value[: field.start()]
        if field.group("quote"):
            boundary = field.start()
            break
        if not parameterized and field.group("key").lower() not in _AUTH_PARAMETERS:
            boundary = field.start()
            break
        parameterized = True
    suffix = _AUTH_HEADER.sub(_redact_authorization_header, value[boundary:])
    return f"{match.group(1)}{REDACTED}{suffix}"


class Redactor:
    """Redact known values, common encodings, and structural secret fields."""

    def __init__(self, secrets: Sequence[str] = ()) -> None:
        variants: set[str] = set()
        for secret in secrets:
            if len(secret) < 4:
                continue
            raw = secret.encode()
            percent = quote(secret, safe="")
            percent_lower = re.sub(r"%[0-9A-F]{2}", lambda match: match.group().lower(), percent)
            double_percent = quote(percent, safe="")
            encoded = {
                base64.b64encode(raw).decode(),
                base64.urlsafe_b64encode(raw).decode(),
            }
            variants.update(
                {
                    secret,
                    secret.casefold(),
                    percent,
                    percent_lower,
                    double_percent,
                    quote(percent_lower, safe=""),
                    re.sub(
                        r"%[0-9A-F]{2}",
                        lambda match: match.group().lower(),
                        double_percent,
                    ),
                    raw.hex(),
                    raw.hex().upper(),
                }
            )
            variants.update(encoded)
            variants.update(value.rstrip("=") for value in encoded)
        self._variants = tuple(sorted(variants, key=len, reverse=True))

    def text(self, value: object) -> str:
        """Return text with known and structural secret forms removed."""
        result = str(value)
        for variant in self._variants:
            result = result.replace(variant, REDACTED)
        result = _QUOTED_AUTH_DOUBLE.sub(_redact_quoted_authorization, result)
        result = _QUOTED_AUTH_SINGLE.sub(_redact_quoted_authorization, result)
        result = _ESCAPED_AUTH_DOUBLE.sub(_redact_quoted_authorization, result)
        result = _AUTH_HEADER.sub(_redact_authorization_header, result)
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
