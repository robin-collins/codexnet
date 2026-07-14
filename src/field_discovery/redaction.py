"""Central structural and textual secret redaction contract."""

from __future__ import annotations

import ast
import base64
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote, quote_plus, unquote_plus

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"^(?:password|passwd|pwd|passphrase|token|access_token|api[_-]?key|community|"
    r"authorization|authentication|cookie|secret|client_secret|auth_key|priv_key|private_key|"
    r"refresh_token|id_token|snmp_community|community_string)$",
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
_JSON_FIELD = re.compile(
    r'(?P<key>"(?:\\.|[^"\\])*")(?P<separator>\s*:\s*)'
    r'(?P<value>"(?:\\.|[^"\\])*")'
)
_ESCAPED_JSON_FIELD = re.compile(
    r'(?P<key>\\"(?:(?!\\").)*\\")(?P<separator>\s*:\s*)'
    r'(?P<value>\\"(?:(?!\\").)*\\")'
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
    r"cookie|client_secret|secret|auth_key|priv_key|private_key|refresh_token|id_token|"
    r"snmp_community|community_string)"
    r"(\s*(?:=>|->|::|[:=])\s*)"
    r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    r'|"(?:\\.|[^"\\\r\n;])*(?=;|\r?$)'
    r"|'(?:\\.|[^'\\\r\n;])*(?=;|\r?$)|[^\s,;]+)"
)
_URI_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s/:@]*:)([^\s/@]+)(@)", re.IGNORECASE)
_PERCENT_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.~%+\-])[A-Za-z0-9_.~%+\-]*[%+][A-Za-z0-9_.~%+\-]*(?![A-Za-z0-9_.~%+\-])"
)
_HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8,}(?![0-9A-Fa-f])")
_MAX_DECODE_PASSES = 2
_MAX_SEQUENCE_DEPTH = 16
_MAX_SEQUENCE_CHARS = 65_536
_AUTH_SEQUENCE_START = re.compile(
    r"(?P<key>(?:b)?\"(?:\\.|[^\"\\])*\"|(?:b)?'(?:\\.|[^'\\])*')"
    r"(?P<separator>\s*:\s*)(?P<open>[\[(])",
    re.IGNORECASE,
)


def _redact_quoted_authorization(match: re.Match[str]) -> str:
    return f"{match.group(1)}{match.group(2)}{REDACTED}{match.group(4)}"


def _redact_json_authorization(match: re.Match[str]) -> str:
    key = json.loads(match.group("key"))
    if key.casefold() not in {"authorization", "authentication"}:
        return match.group(0)
    return f"{match.group('key')}{match.group('separator')}{json.dumps(REDACTED)}"


def _redact_escaped_json_authorization(match: re.Match[str]) -> str:
    key = json.loads(f'"{match.group("key")[2:-2]}"')
    if key.casefold() not in {"authorization", "authentication"}:
        return match.group(0)
    return f'{match.group("key")}{match.group("separator")}\\"{REDACTED}\\"'


def _is_authorization_key(token: str) -> bool:
    try:
        key = ast.literal_eval(token)
    except (SyntaxError, ValueError):
        return False
    if isinstance(key, bytes):
        try:
            key = key.decode("ascii")
        except UnicodeDecodeError:
            return False
    return isinstance(key, str) and key.casefold() in {"authorization", "authentication"}


def _sequence_end(value: str, start: int) -> int | None:
    pairs = {"[": "]", "(": ")"}
    stack = [pairs[value[start]]]
    quote_character: str | None = None
    escaped = False
    limit = min(len(value), start + _MAX_SEQUENCE_CHARS)
    for index in range(start + 1, limit):
        character = value[index]
        if quote_character is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote_character:
                quote_character = None
            continue
        if character in {"'", '"'}:
            quote_character = character
        elif character in pairs:
            if len(stack) >= _MAX_SEQUENCE_DEPTH:
                return None
            stack.append(pairs[character])
        elif character in {
            "]",
            ")",
        }:
            if character != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return index + 1
    return None


def _malformed_sequence_boundary(value: str, start: int) -> int:
    boundary = len(value)
    newline = re.search(r"\r?\n", value[start:])
    if newline is None:
        return boundary
    boundary = start + newline.start()
    next_line = start + newline.end()
    while next_line < len(value) and value[next_line] in {" ", "\t"}:
        following = re.search(r"\r?\n", value[next_line:])
        if following is None:
            return len(value)
        boundary = next_line + following.start()
        next_line += following.end()
    return boundary


def _redact_authorization_sequences(value: str) -> str:
    output: list[str] = []
    cursor = 0
    while match := _AUTH_SEQUENCE_START.search(value, cursor):
        output.append(value[cursor : match.start()])
        if not _is_authorization_key(match.group("key")):
            output.append(value[match.start() : match.end()])
            cursor = match.end()
            continue
        end = _sequence_end(value, match.end() - 1)
        if end is None:
            end = _malformed_sequence_boundary(value, match.end() - 1)
        key = match.group("key")
        quote_character = '"' if '"' in key else "'"
        output.append(
            f"{key}{match.group('separator')}{quote_character}{REDACTED}{quote_character}"
        )
        cursor = end
    output.append(value[cursor:])
    return "".join(output)


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
        registered: set[str] = set()
        for secret in secrets:
            if len(secret) < 4:
                continue
            registered.add(secret.casefold())
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
                    quote_plus(secret, safe=""),
                }
            )
            variants.update(encoded)
            variants.update(value.rstrip("=") for value in encoded)
        self._variants = tuple(sorted(variants, key=len, reverse=True))
        self._registered = frozenset(registered)

    def _encoded(self, match: re.Match[str]) -> str:
        candidate = match.group(0)
        decoded = candidate
        for _ in range(_MAX_DECODE_PASSES):
            decoded = unquote_plus(decoded)
            if decoded.casefold() in self._registered:
                return REDACTED
        return candidate

    def _hex(self, match: re.Match[str]) -> str:
        try:
            decoded = bytes.fromhex(match.group(0)).decode()
        except (UnicodeDecodeError, ValueError):
            return match.group(0)
        return REDACTED if decoded.casefold() in self._registered else match.group(0)

    def text(self, value: object) -> str:
        """Return text with known and structural secret forms removed."""
        result = str(value)
        for variant in self._variants:
            result = result.replace(variant, REDACTED)
        result = _PERCENT_TOKEN.sub(self._encoded, result)
        result = _HEX_TOKEN.sub(self._hex, result)
        result = _redact_authorization_sequences(result)
        result = _JSON_FIELD.sub(_redact_json_authorization, result)
        result = _ESCAPED_JSON_FIELD.sub(_redact_escaped_json_authorization, result)
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
