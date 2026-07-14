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
                "Authorization: BearerValue",
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


def test_exception_keeps_only_type_and_redacted_message() -> None:
    rendered = Redactor(["synthetic-value"]).exception(RuntimeError("token=synthetic-value"))
    assert rendered == f"RuntimeError: token={REDACTED}"
