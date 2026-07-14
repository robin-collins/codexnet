from __future__ import annotations

import base64
from urllib.parse import quote

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


def test_exception_keeps_only_type_and_redacted_message() -> None:
    rendered = Redactor(["synthetic-value"]).exception(RuntimeError("token=synthetic-value"))
    assert rendered == f"RuntimeError: token={REDACTED}"
