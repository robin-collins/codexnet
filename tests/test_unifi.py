"""Offline UniFi detection, authentication, TLS, pagination, and safety tests."""

from __future__ import annotations

import asyncio
import functools
import json
import ssl
import subprocess
from collections.abc import Callable, Mapping
from email.message import Message
from pathlib import Path
from typing import ClassVar
from urllib.error import HTTPError, URLError

import pytest

from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CredentialReference,
    RetryableCollectorError,
)
from field_discovery.unifi import (
    HttpResponse,
    StdlibHttpTransport,
    UniFiClient,
    UniFiCollector,
    UniFiCredentials,
    UniFiEndpoint,
    UniFiError,
    UniFiUnsupportedAuthentication,
    discover_candidates,
    endpoint_from_config,
    resolve_credentials,
)


def async_test(function: object) -> object:
    """Run one async test without adding a runtime pytest plugin dependency."""
    async_function = function

    @functools.wraps(async_function)  # type: ignore[arg-type]
    def wrapper(*args: object, **kwargs: object) -> object:
        return asyncio.run(async_function(*args, **kwargs))  # type: ignore[operator]

    return wrapper


class ScriptedTransport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, str, Mapping[str, str], bytes | None, bool, float]] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        verify_tls: bool,
        timeout: float,
    ) -> HttpResponse:
        self.requests.append((method, url, headers, body, verify_tls, timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, HttpResponse)
        return response


def response(status: int = 200, value: object = None, **headers: str) -> HttpResponse:
    body = b"" if value is None else json.dumps(value).encode()
    return HttpResponse(status, headers, body)


def client(
    responses: list[object], *, api_type: str = "modern", verify_tls: bool = True, **bounds: int
) -> tuple[UniFiClient, ScriptedTransport]:
    transport = ScriptedTransport(responses)
    result = UniFiClient(
        UniFiEndpoint(
            "https://controller.example.invalid:8443", api_type, verify_tls, not verify_tls, 7
        ),
        transport,
        **bounds,
    )
    return result, transport


def test_candidate_detection_is_evidence_only_conservative_and_deterministic() -> None:
    candidates = discover_candidates(
        [
            {"host": "192.0.2.4", "port": 8443, "service": "https", "hostname": "switch"},
            {
                "host": "192.0.2.2",
                "port": 8443,
                "service": "UniFi Controller",
                "source": "nmap",
            },
            {
                "host": "192.0.2.2",
                "port": 8443,
                "mdns_type": "_unifi._tcp.local.",
                "source": "mdns",
            },
            {"host": "192.0.2.3", "port": 443, "hostname": "cloudkey-site", "source": "dns"},
            {"host": "", "port": 443, "service": "unifi"},
            {"host": "192.0.2.9", "port": True, "service": "unifi"},
            {"host": "192.0.2.9", "port": 70000, "service": "unifi"},
        ]
    )
    assert len(candidates) == 2
    assert (candidates[0].host, candidates[0].port, candidates[0].sources) == (
        "192.0.2.2",
        8443,
        ("mdns", "nmap"),
    )
    assert candidates[1].host == "192.0.2.3"


@async_test
async def test_modern_login_cookie_csrf_and_bounded_pagination_are_read_only() -> None:
    api, transport = client(
        [
            response(
                200,
                {},
                **{"Set-Cookie": "TOKEN=secret-cookie; Path=/", "X-CSRF-Token": "csrf"},
            ),
            response(200, {"data": [{"_id": "1"}, {"_id": "2"}]}),
            response(200, {"data": [{"_id": "3"}]}),
        ],
        page_size=2,
        max_pages=3,
        max_items=10,
    )
    await api.login(UniFiCredentials("fixture", "synthetic-password"))
    assert len(await api.get_pages("sites")) == 3
    assert transport.requests[0][0:2] == (
        "POST",
        "https://controller.example.invalid:8443/api/auth/login",
    )
    assert json.loads(transport.requests[0][3] or b"{}") == {
        "username": "fixture",
        "password": "synthetic-password",
        "rememberMe": False,
    }
    assert transport.requests[1][0] == transport.requests[2][0] == "GET"
    assert "/proxy/network/api/self/sites?_start=0&_limit=2" in transport.requests[1][1]
    assert transport.requests[1][2]["Cookie"] == "TOKEN=secret-cookie"
    assert transport.requests[1][2]["X-CSRF-Token"] == "csrf"


@async_test
async def test_legacy_login_and_item_ceiling() -> None:
    api, transport = client(
        [response(200, {"meta": {"rc": "ok"}}), response(200, {"data": [1, 2, 3]})],
        api_type="legacy",
        page_size=3,
        max_items=2,
    )
    await api.login(UniFiCredentials("fixture", "synthetic-password"))
    assert await api.get_pages("sites") == (1, 2)
    assert transport.requests[0][1].endswith("/api/login")
    assert "rememberMe" not in json.loads(transport.requests[0][3] or b"{}")
    assert "/api/self/sites" in transport.requests[1][1]


@pytest.mark.parametrize(
    ("reply", "error"),
    [
        (response(401, {"message": "no"}), CollectorAuthenticationError),
        (response(412, {}), UniFiUnsupportedAuthentication),
        (response(200, {"code": "MFA_REQUIRED"}), UniFiUnsupportedAuthentication),
        (response(500, {}), UniFiError),
        (response(200, {"meta": {"rc": "error"}}), UniFiError),
        (HttpResponse(200, {}, b"{"), UniFiError),
    ],
)
@async_test
async def test_login_failures_are_classified_without_response_secrets(
    reply: HttpResponse, error: type[Exception]
) -> None:
    api, _ = client([reply], api_type="legacy" if b"meta" in reply.body else "modern")
    with pytest.raises(error) as caught:
        await api.login(UniFiCredentials("fixture", "synthetic-password"))
    assert "synthetic-password" not in str(caught.value)


@async_test
async def test_read_authorization_timeout_malformed_and_allowlist_failures() -> None:
    api, _ = client([response(403, {})])
    with pytest.raises(CollectorAuthenticationError, match="denied"):
        await api.get_pages("sites")
    api, _ = client([response(500, {})])
    with pytest.raises(UniFiError, match="status 500"):
        await api.get_pages("sites")
    api, _ = client([response(200, {"data": {}})])
    with pytest.raises(UniFiError, match="data list"):
        await api.get_pages("sites")
    api, _ = client([RetryableCollectorError("transport failed")])
    with pytest.raises(RetryableCollectorError):
        await api.get_pages("sites")
    with pytest.raises(UniFiError, match="allowlist"):
        await api.get_pages("admins")
    with pytest.raises(UniFiError, match="non-read-only"):
        await api._request("DELETE", "/api/site/default/device")


@pytest.mark.parametrize(
    ("api_type", "method", "path", "payload"),
    [
        ("modern", "POST", "/api/login", {"username": "fixture"}),
        ("legacy", "POST", "/api/auth/login", {"username": "fixture"}),
        ("modern", "POST", "/api/auth/login/write", {}),
        ("modern", "POST", "/api/s/default/rest/networkconf/login/write", {}),
        ("modern", "POST", "/api/auth/../auth/login", {}),
        ("modern", "POST", "/api/%61uth/login", {}),
        ("modern", "POST", "/API/AUTH/LOGIN", {}),
        ("modern", "POST", "/api/auth/login?next=write", {}),
        ("modern", "POST", "/api/auth/login#fragment", {}),
        ("modern", "POST", "api/auth/login", {}),
        ("modern", "POST", "/api/auth/login/", {}),
        ("modern", "PUT", "/api/auth/login", {}),
        ("modern", "PATCH", "/api/auth/login", {}),
        ("modern", "DELETE", "/api/auth/login", {}),
        ("modern", "post", "/api/auth/login", {}),
        ("modern", "GET", "/api/self/sites", {}),
        ("modern", "GET", "//other.invalid/api/self/sites", None),
        ("modern", "GET", "https://other.invalid/api/self/sites", None),
    ],
)
@async_test
async def test_request_guard_denies_login_near_misses_and_write_methods_before_transport(
    api_type: str, method: str, path: str, payload: Mapping[str, object] | None
) -> None:
    api, transport = client([], api_type=api_type)
    with pytest.raises(UniFiError, match="non-read-only"):
        await api._request(method, path, payload=payload)
    assert transport.requests == []


def test_endpoint_requires_scoped_tls_opt_in_and_known_api() -> None:
    assert endpoint_from_config({"url": "https://controller.invalid"}).verify_tls
    assert (
        endpoint_from_config(
            {
                "url": "https://controller.invalid",
                "api_type": "legacy",
                "verify_tls": False,
                "allow_self_signed": True,
            }
        ).api_type
        == "legacy"
    )
    cases: tuple[tuple[Callable[[], UniFiEndpoint], str], ...] = (
        (lambda: UniFiEndpoint("http://controller.invalid"), "HTTPS"),
        (lambda: UniFiEndpoint("https://user:pass@controller.invalid"), "HTTPS"),
        (lambda: UniFiEndpoint("https://controller.invalid", "future"), "API type"),
        (lambda: UniFiEndpoint("https://controller.invalid", verify_tls=False), "self-signed"),
        (lambda: UniFiEndpoint("https://controller.invalid", timeout_seconds=0), "timeout"),
    )
    for factory, message in cases:
        with pytest.raises(UniFiError, match=message):
            factory()
    with pytest.raises(UniFiError, match="pagination"):
        UniFiClient(UniFiEndpoint("https://controller.invalid"), page_size=0)


@async_test
async def test_tls_policy_is_passed_per_request_and_invalid_cert_is_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secure, secure_transport = client([response(200, {})])
    await secure.login(UniFiCredentials("fixture", "synthetic-password"))
    assert secure_transport.requests[0][4] is True
    exception, exception_transport = client([response(200, {})], verify_tls=False)
    await exception.login(UniFiCredentials("fixture", "synthetic-password"))
    assert exception_transport.requests[0][4] is False

    class InvalidCertificate:
        def open(self, *_args: object, **_kwargs: object) -> object:
            raise ssl.SSLCertVerificationError("certificate verify failed: synthetic-token")

    import field_discovery.unifi as unifi

    monkeypatch.setattr(unifi, "build_opener", lambda *_args: InvalidCertificate())
    with pytest.raises(UniFiError) as caught:
        await StdlibHttpTransport().request(
            "GET",
            "https://controller.invalid",
            headers={},
            body=None,
            verify_tls=True,
            timeout=1,
        )
    assert "synthetic-token" not in str(caught.value)


def test_credentials_are_strictly_structured_and_resolved_from_safe_file(tmp_path: Path) -> None:
    value = json.dumps({"username": "fixture", "password": "synthetic-password"})
    assert UniFiCredentials.from_secret(value).username == "fixture"
    for bad in ("no", "[]", '{"username":"x"}', '{"username":"","password":"abcd"}'):
        with pytest.raises(UniFiError):
            UniFiCredentials.from_secret(bad)
    secret_file = tmp_path / "secrets.env"
    secret_file.write_text(f"OTHER=x\nUNIFI_PROFILE={value}\n")
    secret_file.chmod(0o600)
    reference = CredentialReference("fixture", "UNIFI_PROFILE")
    providers = {"fixture": {"type": "env_file", "path": str(secret_file)}}
    assert resolve_credentials(reference, providers).password == "synthetic-password"
    secret_file.chmod(0o644)
    with pytest.raises(UniFiError, match="mode"):
        resolve_credentials(reference, providers)
    with pytest.raises(UniFiError, match="unavailable"):
        resolve_credentials(reference, {"fixture": {"type": "env_file", "path": "/missing"}})
    with pytest.raises(UniFiError, match="provider"):
        resolve_credentials(reference, {})
    secret_file.chmod(0o600)
    secret_file.write_bytes(b"x" * 20_000)
    with pytest.raises(UniFiError, match="size"):
        resolve_credentials(reference, providers)
    secret_file.write_text("OTHER=value\n")
    with pytest.raises(UniFiError, match="unavailable"):
        resolve_credentials(reference, providers)
    linked = tmp_path / "linked.env"
    linked.symlink_to(secret_file)
    with pytest.raises(UniFiError, match="regular"):
        resolve_credentials(reference, {"fixture": {"type": "env_file", "path": str(linked)}})


def test_command_credential_provider_is_bounded_and_has_no_argv_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = CredentialReference("helper", "UNIFI_PROFILE")
    provider = {
        "helper": {"type": "command", "executable": "/fixture/helper", "timeout_seconds": 2}
    }
    value = json.dumps({"username": "fixture", "password": "synthetic-password"})
    seen: dict[str, object] = {}

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.update({"argv": argv, **kwargs})
        return subprocess.CompletedProcess(argv, 0, value + "\n", "")

    monkeypatch.setattr(subprocess, "run", run)
    assert resolve_credentials(reference, provider).username == "fixture"
    assert seen["argv"] == ["/fixture/helper"]
    assert seen["input"] == "UNIFI_PROFILE\n"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "secret", "secret"),
    )
    with pytest.raises(UniFiError, match="command failed"):
        resolve_credentials(reference, provider)
    monkeypatch.setattr(
        subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )
    with pytest.raises(UniFiError, match="command failed"):
        resolve_credentials(reference, provider)
    with pytest.raises(UniFiError, match="unsupported"):
        resolve_credentials(reference, {"helper": {"type": "future"}})
    with pytest.raises(UniFiError, match="timeout"):
        resolve_credentials(
            reference,
            {"helper": {"type": "command", "executable": "/helper", "timeout_seconds": True}},
        )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "x" * 20_000, ""),
    )
    with pytest.raises(UniFiError, match="command failed"):
        resolve_credentials(reference, provider)


@async_test
async def test_stdlib_transport_bounds_http_errors_and_transport_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FixtureResponse:
        status = 200
        headers: ClassVar[dict[str, str]] = {"Content-Type": "application/json"}

        def __init__(self, body: bytes) -> None:
            self.body = body

        def __enter__(self) -> FixtureResponse:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _size: int = -1, /) -> bytes:
            return self.body

    class Opener:
        def __init__(self, action: object) -> None:
            self.action = action

        def open(self, *_args: object, **_kwargs: object) -> FixtureResponse:
            if isinstance(self.action, BaseException):
                raise self.action
            assert isinstance(self.action, FixtureResponse)
            return self.action

    class FixtureHttpError(HTTPError):
        def __init__(self, status: int, body: bytes) -> None:
            super().__init__("https://controller.invalid", status, "fixture", Message(), None)
            self.body = body

        def read(self, _size: int = -1, /) -> bytes:
            return self.body

    import field_discovery.unifi as unifi

    transport = StdlibHttpTransport(max_response_bytes=2)
    monkeypatch.setattr(unifi, "build_opener", lambda *_args: Opener(FixtureResponse(b"{}")))
    result = await transport.request(
        "GET", "https://controller.invalid", headers={}, body=None, verify_tls=False, timeout=1
    )
    assert result.status == 200
    monkeypatch.setattr(unifi, "build_opener", lambda *_args: Opener(FixtureResponse(b"xxx")))
    with pytest.raises(UniFiError, match="size"):
        await transport.request(
            "GET", "https://controller.invalid", headers={}, body=None, verify_tls=True, timeout=1
        )
    missing = FixtureHttpError(404, b"{}")
    monkeypatch.setattr(unifi, "build_opener", lambda *_args: Opener(missing))
    assert (
        await transport.request(
            "GET", "https://controller.invalid", headers={}, body=None, verify_tls=True, timeout=1
        )
    ).status == 404
    oversized = FixtureHttpError(500, b"xxx")
    monkeypatch.setattr(unifi, "build_opener", lambda *_args: Opener(oversized))
    with pytest.raises(UniFiError, match="size"):
        await transport.request(
            "GET", "https://controller.invalid", headers={}, body=None, verify_tls=True, timeout=1
        )
    monkeypatch.setattr(unifi, "build_opener", lambda *_args: Opener(URLError("down")))
    with pytest.raises(RetryableCollectorError, match="transport"):
        await transport.request(
            "GET", "https://controller.invalid", headers={}, body=None, verify_tls=True, timeout=1
        )


@async_test
async def test_page_limit_empty_documents_and_non_mapping_mfa_branch() -> None:
    api, transport = client(
        [response(200, {"data": [1]}), response(200, {"data": [2]})],
        page_size=1,
        max_pages=2,
        max_items=10,
    )
    assert await api.get_pages("sites", site="fixture") == (1, 2)
    assert len(transport.requests) == 2
    assert UniFiClient._document(HttpResponse(200, {}, b"")) == {}
    assert UniFiClient._requires_mfa([]) is False
    from field_discovery.unifi import _NoRedirect

    _NoRedirect().redirect_request()


@async_test
async def test_collector_adapter_requires_reference_and_reports_site_count() -> None:
    scripted, _ = client([response(200, {}), response(200, {"data": [{}, {}]})])
    collector = UniFiCollector(
        UniFiEndpoint("https://controller.invalid"),
        lambda _reference: UniFiCredentials("fixture", "synthetic-password"),
        lambda _endpoint: scripted,
    )
    context = CollectorContext(
        "192.0.2.2", CredentialReference("fixture", "UNIFI_PROFILE"), asyncio.Event()
    )
    assert (await collector.collect(context)).item_count == 2
    with pytest.raises(UniFiError, match="credential reference"):
        await collector.collect(CollectorContext("192.0.2.2", None, asyncio.Event()))
