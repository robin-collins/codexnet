from __future__ import annotations

import base64
import re
from urllib.parse import quote

import pytest

from field_discovery.redaction import REDACTED, Redactor


def test_text_redacts_raw_encoded_and_structural_forms() -> None:
    secret = "synthetic-value!"
    redactor = Redactor([secret, "abc"])
    rendered = redactor.text(
        " ".join(
            [
                secret,
                quote(secret, safe=""),
                base64.b64encode(secret.encode()).decode(),
                base64.urlsafe_b64encode(secret.encode()).decode(),
                "Authorization: BearerValue;",
                "password=another-value",
                "https://user:uri-value@example.invalid/path",
                "abc",
            ]
        )
    )
    for forbidden in (secret, quote(secret, safe=""), "BearerValue", "another-value", "uri-value"):
        assert forbidden not in rendered
    assert "abc" in rendered
    assert rendered.count(REDACTED) >= 6


def test_structured_redaction_preserves_shape_and_non_strings() -> None:
    source = {
        "password": "synthetic-value",
        "nested": [{"Authorization": "synthetic-header"}, "token=synthetic-token", 4],
        "tuple": ("safe",),
        "count": 2,
    }
    result = Redactor().value(source)
    assert result == {
        "password": REDACTED,
        "nested": [{"Authorization": REDACTED}, f"token={REDACTED}", 4],
        "tuple": ("safe",),
        "count": 2,
    }


def test_authorization_redacts_scheme_and_complete_credential() -> None:
    rendered = Redactor().text(
        "safe-before Authorization: Basic c3ludGhldGljOnNlY3JldA==; safe-middle; "
        "Authorization=Bearer synthetic.header.payload, safe_field=after"
    )
    assert rendered == (
        f"safe-before Authorization: {REDACTED}; safe-middle; "
        f"Authorization={REDACTED}, safe_field=after"
    )
    assert "Basic" not in rendered
    assert "Bearer" not in rendered
    assert "c3ludGhldGljOnNlY3JldA==" not in rendered
    assert "synthetic.header.payload" not in rendered


def test_generic_authorization_schemes_and_line_boundaries() -> None:
    rendered = Redactor().text(
        "Authorization: Token synthetic-token\r\n"
        "safe-crlf: visible\n"
        "Authorization: UnknownScheme synthetic unknown parameters\n"
        "safe-newline: visible"
    )
    assert rendered == (
        f"Authorization: {REDACTED}\r\n"
        "safe-crlf: visible\n"
        f"Authorization: {REDACTED}\n"
        "safe-newline: visible"
    )


def test_digest_and_aws_authorization_parameters_are_fully_redacted() -> None:
    rendered = Redactor().text(
        'Authorization: Digest username="synthetic", realm="private", nonce="nonce-value", '
        'uri="/private", response="response-value"; safe-digest: visible\n'
        "Authorization: AWS4-HMAC-SHA256 "
        "Credential=SYNTHETIC/20260715/ap-southeast-2/execute-api/aws4_request, "
        "SignedHeaders=host;x-amz-date, Signature=signature-value; safe_field=visible"
    )
    assert rendered == (
        f"Authorization: {REDACTED}; safe-digest: visible\n"
        f"Authorization: {REDACTED}; safe_field=visible"
    )
    for forbidden in ("synthetic", "private", "nonce-value", "response-value", "signature-value"):
        assert forbidden.casefold() not in rendered.casefold()


def test_unknown_parameterized_scheme_does_not_leak_unrecognized_parameters() -> None:
    rendered = Redactor().text(
        "Authorization: CustomScheme first=synthetic-one, custom=synthetic-two\n"
        "safe-next-line: visible"
    )
    assert rendered == f"Authorization: {REDACTED}\nsafe-next-line: visible"
    assert "synthetic" not in rendered


def test_quoted_authorization_fields_and_exception_text_are_bounded() -> None:
    json_text = (
        '{"authorization": "Bearer synthetic-json", "safe": "visible", '
        '"nested": {"Authorization": "Token nested-secret"}}'
    )
    assert Redactor().text(json_text) == (
        f'{{"authorization": "{REDACTED}", "safe": "visible", '
        f'"nested": {{"Authorization": "{REDACTED}"}}}}'
    )
    error = RuntimeError(
        "request failed: {'Authorization': 'Unknown synthetic-exception', 'status': 'safe'}"
    )
    rendered = Redactor().exception(error)
    assert rendered == (
        f"RuntimeError: request failed: {{'Authorization': '{REDACTED}', 'status': 'safe'}}"
    )
    assert "synthetic" not in rendered

    header_with_json_field = Redactor().text(
        'Authorization: Token synthetic-header, "safe": "visible"'
    )
    assert header_with_json_field == f'Authorization: {REDACTED}, "safe": "visible"'


def test_bytes_escaped_and_authentication_fields_are_redacted() -> None:
    bytes_repr = "{b'Authorization': b'Bearer synthetic-bytes', b'safe': b'visible'}"
    assert Redactor().text(bytes_repr) == (
        f"{{b'Authorization': b'{REDACTED}', b'safe': b'visible'}}"
    )
    escaped_json = r"{\"Authorization\": \"Bearer synthetic-escaped\", \"safe\": \"visible\"}"
    assert Redactor().text(escaped_json) == (
        rf"{{\"Authorization\": \"{REDACTED}\", \"safe\": \"visible\"}}"
    )
    folded = (
        "Authentication: Custom synthetic-first\r\n synthetic-continuation\r\nSafe-Header: visible"
    )
    assert Redactor().text(folded) == (f"Authentication: {REDACTED}\r\nSafe-Header: visible")
    unicode_key_json = (
        r"{\"Authoriz\u0061tion\": \"Bearer synthetic-unicode\", \"safe\": \"visible\"}"
    )
    assert Redactor().text(unicode_key_json) == (
        rf"{{\"Authoriz\u0061tion\": \"{REDACTED}\", \"safe\": \"visible\"}}"
    )
    safe_escaped_key = r"{\"authorization_status\": \"visible\"}"
    assert Redactor().text(safe_escaped_key) == safe_escaped_key


def test_quoted_assignments_redact_entire_multiword_value() -> None:
    rendered = Redactor().text(
        'safe-before password="synthetic double secret" safe-middle; '
        "secret: 'synthetic single secret' safe-after"
    )
    assert rendered == (
        f"safe-before password={REDACTED} safe-middle; secret: {REDACTED} safe-after"
    )
    assert "synthetic" not in rendered
    assert "double secret" not in rendered
    assert "single secret" not in rendered


def test_assignment_quotes_are_escape_aware_and_bounded() -> None:
    rendered = Redactor().text(
        r"""password="synthetic \"quoted\" and \\ path"; safe-double=visible; """
        r"auth_key='synthetic \'quoted\' and \\ path'; safe-single=visible"
    )
    assert rendered == (
        f"password={REDACTED}; safe-double=visible; auth_key={REDACTED}; safe-single=visible"
    )
    error = RuntimeError(r"failure pwd='synthetic \'repr\' value'; status=visible")
    assert Redactor().exception(error) == (f"RuntimeError: failure pwd={REDACTED}; status=visible")


def test_empty_and_unterminated_assignment_values_fail_closed() -> None:
    rendered = Redactor().text(
        'token="" safe-empty=visible\n'
        "passwd='synthetic unterminated words\n"
        "safe-next=visible\n"
        'pwd="; safe-semicolon=visible'
    )
    assert rendered == (
        f"token={REDACTED} safe-empty=visible\n"
        f"passwd={REDACTED}\n"
        "safe-next=visible\n"
        f"pwd={REDACTED}; safe-semicolon=visible"
    )


@pytest.mark.parametrize(
    "alias",
    [
        "access_token",
        "auth_key",
        "priv_key",
        "private_key",
        "passwd",
        "pwd",
        "refresh_token",
        "id_token",
        "snmp_community",
        "community_string",
    ],
)
def test_exact_assignment_aliases_redact(alias: str) -> None:
    assert Redactor().text(f"safe {alias}=synthetic-value; adjacent=visible") == (
        f"safe {alias}={REDACTED}; adjacent=visible"
    )


@pytest.mark.parametrize("separator", ["=>", "->", "::"])
def test_arrow_and_double_colon_assignments_do_not_leak_suffixes(separator: str) -> None:
    rendered = Redactor().text(f'access_token {separator} "synthetic quoted suffix"; safe=visible')
    assert rendered == f"access_token {separator} {REDACTED}; safe=visible"
    assert "suffix" not in rendered


def test_secret_key_lookalikes_are_not_over_redacted() -> None:
    safe = (
        "authorization_status=ok token_count=4 secretary=visible "
        "community_name=public authentication_result=passed"
    )
    assert Redactor().text(safe) == safe
    assert Redactor().value(
        {
            "authorization_status": "ok",
            "token_count": 4,
            "secretary": "visible",
            "community_name": "public",
        }
    ) == {
        "authorization_status": "ok",
        "token_count": 4,
        "secretary": "visible",
        "community_name": "public",
    }


@pytest.mark.parametrize("secret", ["abcd", "abcde", "abcdef", "safe࠿"])
def test_registered_secret_base64_padding_and_urlsafe_variants(secret: str) -> None:
    raw = secret.encode()
    variants = {
        base64.b64encode(raw).decode(),
        base64.b64encode(raw).decode().rstrip("="),
        base64.urlsafe_b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
    }
    redactor = Redactor([secret])
    for variant in variants:
        assert redactor.text(f"before {variant} after") == f"before {REDACTED} after"


def test_registered_secret_case_percent_and_hex_variants() -> None:
    secret = "SYNTHETIC /ÿ!"
    encoded = quote(secret, safe="")
    encoded_lower = re.sub(r"%[0-9A-F]{2}", lambda match: match.group().lower(), encoded)
    variants = {
        secret.casefold(),
        encoded,
        encoded_lower,
        quote(encoded, safe=""),
        quote(encoded_lower, safe=""),
        secret.encode().hex(),
        secret.encode().hex().upper(),
    }
    redactor = Redactor([secret])
    for variant in variants:
        assert redactor.text(f"before {variant} after") == f"before {REDACTED} after"


def test_registered_secret_form_mixed_percent_and_mixed_hex_variants() -> None:
    secret = "Synthetic Value /ÿ!"
    single = quote(secret, safe="").replace("%C3", "%c3").replace("%2F", "%2f")
    double = quote(single, safe="").replace("%2F", "%2f")
    form = quote(secret, safe="").replace("%20", "+")
    mixed_hex = "".join(
        character.upper() if index % 2 else character.lower()
        for index, character in enumerate(secret.encode().hex())
    )
    redactor = Redactor([secret])
    for variant in (single, double, form, mixed_hex):
        assert redactor.text(f"before {variant} after") == f"before {REDACTED} after"


def test_registered_secret_decoding_is_capped_at_two_passes() -> None:
    secret = "Synthetic Value!"
    once = quote(secret, safe="")
    twice = quote(once, safe="")
    three_times = quote(twice, safe="")
    redactor = Redactor([secret])
    assert redactor.text(twice) == REDACTED
    assert redactor.text(three_times) == three_times


def test_invalid_hex_candidate_is_preserved() -> None:
    assert Redactor(["synthetic-value"]).text("before deadbeef after") == "before deadbeef after"


def test_empty_user_uri_password_is_redacted() -> None:
    assert Redactor().text("before https://:synthetic-pass@example.invalid/path after") == (
        f"before https://:{REDACTED}@example.invalid/path after"
    )


def test_authorization_sequence_values_are_redacted_as_one_bounded_value() -> None:
    json_text = (
        '{"Authorization": ["Bearer synthetic-one", ["nested synthetic-two"], []], '
        '"safe": "visible", "Authentication": []}'
    )
    assert Redactor().text(json_text) == (
        f'{{"Authorization": "{REDACTED}", "safe": "visible", "Authentication": "{REDACTED}"}}'
    )
    python_text = (
        "{b'Authorization': (b'Basic synthetic-three', 'escaped \\' ] value'), 'safe': 'visible'}"
    )
    assert Redactor().text(python_text) == (
        f"{{b'Authorization': '{REDACTED}', 'safe': 'visible'}}"
    )


def test_multiple_and_nested_sequence_values_preserve_adjacent_syntax() -> None:
    value = (
        "{'Authorization': [('first',), ['second', ('third',)]], 'safe': 4, "
        "'Authentication': (b'fourth', b'fifth')}"
    )
    assert Redactor().text(value) == (
        f"{{'Authorization': '{REDACTED}', 'safe': 4, 'Authentication': '{REDACTED}'}}"
    )


def test_malformed_authorization_sequences_fail_closed_at_line_boundary() -> None:
    malformed = (
        '{"Authorization": ["synthetic first"\n'
        '  "synthetic continuation"\n'
        '"safe-next-line": "visible"}'
    )
    assert Redactor().text(malformed) == (
        f'{{"Authorization": "{REDACTED}"\n"safe-next-line": "visible"}}'
    )
    mismatched = "{'Authentication': ['synthetic')\nSafe: visible"
    assert Redactor().text(mismatched) == (f"{{'Authentication': '{REDACTED}'\nSafe: visible")
    no_newline = "{'Authorization': ['synthetic unterminated'"
    assert Redactor().text(no_newline) == f"{{'Authorization': '{REDACTED}'"
    terminal_continuation = "{'Authentication': ['synthetic'\n  'continued without newline'"
    assert Redactor().text(terminal_continuation) == (f"{{'Authentication': '{REDACTED}'")


def test_authorization_sequence_depth_and_size_are_bounded() -> None:
    too_deep = '"Authorization": ' + "[" * 17 + '"synthetic"' + "]" * 17 + "\nSafe: visible"
    assert Redactor().text(too_deep) == f'"Authorization": "{REDACTED}"\nSafe: visible'
    oversized = '"Authentication": ["' + ("x" * 65_536) + '"]\nSafe: visible'
    assert Redactor().text(oversized) == f'"Authentication": "{REDACTED}"\nSafe: visible'


def test_non_auth_and_malformed_sequence_keys_are_unchanged() -> None:
    safe = "{'authorization_status': ['visible'], b'\\xff': ['visible'], b'\\xZZ': ['visible']}"
    assert Redactor().text(safe) == safe


def test_exception_keeps_only_type_and_redacted_message() -> None:
    rendered = Redactor(["synthetic-value"]).exception(RuntimeError("token=synthetic-value"))
    assert rendered == f"RuntimeError: token={REDACTED}"
