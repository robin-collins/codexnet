"""Conservative UniFi candidate detection and read-only controller API client."""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CollectorError,
    CollectorIssue,
    CollectorResult,
    CredentialReference,
    RetryableCollectorError,
)

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_SECRET_BYTES = 16 * 1024
DEFAULT_PAGE_SIZE = 200
DEFAULT_MAX_PAGES = 25
DEFAULT_MAX_ITEMS = 5_000
_KNOWN_PORTS = {443, 8443}
_KNOWN_MDNS_TYPES = {"_unifi._tcp", "_unifi._tcp.local"}
_LOGIN_PATHS = {"modern": "/api/auth/login", "legacy": "/api/login"}
_READ_ONLY_RESOURCES = {
    "sites",
    "devices",
    "clients",
    "networks",
    "wlans",
    "profiles",
    "alarms",
    "events",
}
_RESOURCE_PATHS = {
    "devices": "stat/device",
    "clients": "stat/sta",
    "networks": "rest/networkconf",
    "wlans": "rest/wlanconf",
    "profiles": "rest/portconf",
    "alarms": "stat/alarm",
    "events": "stat/event",
}


class UniFiError(CollectorError):
    """A safe UniFi configuration, protocol, or response failure."""


class UniFiUnsupportedAuthentication(UniFiError):
    """The controller requires MFA or another unsupported login flow."""


@dataclass(frozen=True)
class UniFiCandidate:
    """A controller candidate derived only from already-collected evidence."""

    host: str
    port: int
    sources: tuple[str, ...]


def discover_candidates(observations: Sequence[Mapping[str, object]]) -> tuple[UniFiCandidate, ...]:
    """Derive candidates from nmap/DNS/mDNS evidence without network probing."""
    found: dict[tuple[str, int], set[str]] = {}
    for observation in observations:
        host = observation.get("host")
        port = observation.get("port")
        if (
            not isinstance(host, str)
            or not host
            or isinstance(port, bool)
            or not isinstance(port, int)
        ):
            continue
        service = str(observation.get("service", "")).casefold()
        hostname = str(observation.get("hostname", "")).casefold()
        mdns_type = str(observation.get("mdns_type", "")).casefold().rstrip(".")
        source = str(observation.get("source", "evidence"))
        explicit_unifi = "unifi" in service or mdns_type in _KNOWN_MDNS_TYPES
        controller_name = any(word in hostname for word in ("unifi", "controller", "cloudkey"))
        if not explicit_unifi and not (port in _KNOWN_PORTS and controller_name):
            continue
        if port not in range(1, 65536):
            continue
        found.setdefault((host, port), set()).add(source)
    return tuple(
        UniFiCandidate(host, port, tuple(sorted(sources)))
        for (host, port), sources in sorted(found.items())
    )


@dataclass(frozen=True)
class UniFiCredentials:
    username: str
    password: str

    @classmethod
    def from_secret(cls, value: str) -> UniFiCredentials:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise UniFiError("referenced UniFi credential has an invalid format") from exc
        if not isinstance(parsed, dict) or set(parsed) != {"username", "password"}:
            raise UniFiError("referenced UniFi credential must contain username and password")
        username, password = parsed["username"], parsed["password"]
        if (
            not isinstance(username, str)
            or not username
            or not isinstance(password, str)
            or len(password) < 4
        ):
            raise UniFiError("referenced UniFi credential fields are invalid")
        return cls(username, password)


def resolve_credentials(
    reference: CredentialReference, providers: Mapping[str, Mapping[str, object]]
) -> UniFiCredentials:
    """Resolve one bounded secret without argv/environment exposure or persistence."""
    provider = providers.get(reference.provider)
    if provider is None:
        raise UniFiError("UniFi credential provider is unavailable")
    provider_type = provider.get("type")
    if provider_type == "env_file":
        path = Path(str(provider.get("path", "")))
        try:
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise UniFiError("UniFi credential file must be a regular file")
            if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid not in {0, os.geteuid()}:
                raise UniFiError("UniFi credential file ownership or mode is unsafe")
            raw = path.read_bytes()
        except OSError as exc:
            raise UniFiError("UniFi credential file is unavailable") from exc
        if len(raw) > MAX_SECRET_BYTES:
            raise UniFiError("UniFi credential file exceeds the size limit")
        secret: str | None = None
        for line in raw.decode("utf-8", errors="strict").splitlines():
            key, separator, value = line.partition("=")
            if separator and key == reference.key:
                secret = value
                break
    elif provider_type == "command":
        executable = str(provider.get("executable", ""))
        configured_timeout = provider.get("timeout_seconds", 5)
        if isinstance(configured_timeout, bool) or not isinstance(configured_timeout, int):
            raise UniFiError("UniFi credential command timeout is invalid")
        timeout = configured_timeout
        try:
            completed = subprocess.run(
                [executable],
                input=f"{reference.key}\n",
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={"PATH": "/usr/bin:/bin"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise UniFiError("UniFi credential command failed") from exc
        if completed.returncode != 0 or len(completed.stdout.encode()) > MAX_SECRET_BYTES:
            raise UniFiError("UniFi credential command failed")
        secret = completed.stdout.rstrip("\r\n")
    else:
        raise UniFiError("UniFi credential provider type is unsupported")
    if not secret:
        raise UniFiError("referenced UniFi credential is unavailable")
    return UniFiCredentials.from_secret(secret)


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpTransport(Protocol):
    async def request(  # pragma: no cover - structural typing declaration
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        verify_tls: bool,
        timeout: float,
    ) -> HttpResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


@dataclass(frozen=True)
class StdlibHttpTransport:
    """Bounded HTTPS transport with a request-scoped TLS policy and no redirects."""

    max_response_bytes: int = MAX_RESPONSE_BYTES

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
        return await asyncio.to_thread(
            self._request, method, url, headers, body, verify_tls, timeout
        )

    def _request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        verify_tls: bool,
        timeout: float,
    ) -> HttpResponse:
        context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
        opener = build_opener(_NoRedirect, HTTPSHandler(context=context))
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            with opener.open(request, timeout=timeout) as response:
                payload = response.read(self.max_response_bytes + 1)
                if len(payload) > self.max_response_bytes:
                    raise UniFiError("UniFi response exceeds the size limit")
                return HttpResponse(response.status, dict(response.headers.items()), payload)
        except HTTPError as exc:
            payload = exc.read(self.max_response_bytes + 1)
            if len(payload) > self.max_response_bytes:
                raise UniFiError("UniFi response exceeds the size limit") from exc
            return HttpResponse(exc.code, dict(exc.headers.items()), payload)
        except ssl.SSLCertVerificationError as exc:
            raise UniFiError("UniFi controller certificate verification failed") from exc
        except (TimeoutError, URLError, OSError) as exc:
            raise RetryableCollectorError("UniFi controller transport failed") from exc


@dataclass(frozen=True)
class UniFiEndpoint:
    url: str
    api_type: str = "modern"
    verify_tls: bool = True
    allow_self_signed: bool = False
    timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise UniFiError("UniFi endpoint must be an HTTPS URL without credentials")
        if self.api_type not in {"modern", "legacy"}:
            raise UniFiError("UniFi endpoint API type must be modern or legacy")
        if not self.verify_tls and not self.allow_self_signed:
            raise UniFiError("disabled UniFi TLS verification requires explicit self-signed opt-in")
        if self.timeout_seconds <= 0:
            raise UniFiError("UniFi endpoint timeout must be positive")


@dataclass
class UniFiClient:
    endpoint: UniFiEndpoint
    transport: HttpTransport = field(default_factory=StdlibHttpTransport)
    page_size: int = DEFAULT_PAGE_SIZE
    max_pages: int = DEFAULT_MAX_PAGES
    max_items: int = DEFAULT_MAX_ITEMS
    _headers: dict[str, str] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        if self.page_size < 1 or self.max_pages < 1 or self.max_items < 1:
            raise UniFiError("UniFi pagination bounds must be positive")

    async def login(self, credentials: UniFiCredentials) -> None:
        path = "/api/auth/login" if self.endpoint.api_type == "modern" else "/api/login"
        payload: dict[str, object] = {
            "username": credentials.username,
            "password": credentials.password,
        }
        if self.endpoint.api_type == "modern":
            payload["rememberMe"] = False
        response = await self._request("POST", path, payload=payload)
        document = self._document(response)
        if response.status in {401, 403}:
            raise CollectorAuthenticationError("referenced UniFi credential was rejected")
        if response.status in {409, 412} or self._requires_mfa(document):
            raise UniFiUnsupportedAuthentication("UniFi controller requires unsupported MFA")
        if response.status < 200 or response.status >= 300 or self._legacy_error(document):
            raise UniFiError(f"UniFi login failed with HTTP status {response.status}")
        cookie = self._cookie_header(response.headers)
        if cookie:
            self._headers["Cookie"] = cookie
        csrf = self._header(response.headers, "x-csrf-token")
        if csrf:
            self._headers["X-CSRF-Token"] = csrf

    async def get_pages(self, resource: str, *, site: str = "default") -> tuple[object, ...]:
        """GET an allowlisted resource with hard page and item ceilings."""
        if resource not in _READ_ONLY_RESOURCES:
            raise UniFiError("UniFi resource is not on the read-only allowlist")
        prefix = "/proxy/network" if self.endpoint.api_type == "modern" else ""
        base = (
            f"{prefix}/api/self/sites"
            if resource == "sites"
            else f"{prefix}/api/s/{site}/{_RESOURCE_PATHS[resource]}"
        )
        items: list[object] = []
        for page in range(self.max_pages):
            query = urlencode({"_start": page * self.page_size, "_limit": self.page_size})
            response = await self._request("GET", f"{base}?{query}")
            if response.status in {401, 403}:
                raise CollectorAuthenticationError("UniFi controller denied read access")
            if response.status < 200 or response.status >= 300:
                raise UniFiError(f"UniFi read failed with HTTP status {response.status}")
            document = self._document(response)
            page_items = document.get("data") if isinstance(document, dict) else None
            if not isinstance(page_items, list):
                raise UniFiError("UniFi response does not contain a data list")
            remaining = self.max_items - len(items)
            items.extend(page_items[:remaining])
            if len(items) >= self.max_items or len(page_items) < self.page_size:
                break
        return tuple(items)

    async def _request(
        self, method: str, path: str, *, payload: Mapping[str, object] | None = None
    ) -> HttpResponse:
        parsed_path = urlsplit(path)
        origin_relative = (
            path.startswith("/")
            and not path.startswith("//")
            and not parsed_path.scheme
            and not parsed_path.netloc
            and not parsed_path.fragment
        )
        read_request = method == "GET" and payload is None
        login_request = method == "POST" and path == _LOGIN_PATHS[self.endpoint.api_type]
        if not origin_relative or not (read_request or login_request):
            raise UniFiError("UniFi client refused a non-read-only operation")
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Accept": "application/json", **self._headers}
        if body is not None:
            headers["Content-Type"] = "application/json"
        return await self.transport.request(
            method,
            urljoin(self.endpoint.url.rstrip("/") + "/", path.lstrip("/")),
            headers=headers,
            body=body,
            verify_tls=self.endpoint.verify_tls,
            timeout=self.endpoint.timeout_seconds,
        )

    @staticmethod
    def _document(response: HttpResponse) -> object:
        if not response.body:
            return {}
        try:
            return json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise UniFiError("UniFi controller returned invalid JSON") from exc

    @staticmethod
    def _requires_mfa(document: object) -> bool:
        if not isinstance(document, dict):
            return False
        values = {str(document.get(key, "")).casefold() for key in ("error", "message", "code")}
        return any("mfa" in value or "2fa" in value for value in values)

    @staticmethod
    def _legacy_error(document: object) -> bool:
        return bool(
            isinstance(document, dict)
            and isinstance(document.get("meta"), dict)
            and document["meta"].get("rc") == "error"
        )

    @staticmethod
    def _header(headers: Mapping[str, str], name: str) -> str | None:
        return next(
            (value for key, value in headers.items() if key.casefold() == name.casefold()), None
        )

    @classmethod
    def _cookie_header(cls, headers: Mapping[str, str]) -> str | None:
        value = cls._header(headers, "set-cookie")
        if not value:
            return None
        cookie = SimpleCookie()
        cookie.load(value)
        return "; ".join(f"{key}={morsel.value}" for key, morsel in sorted(cookie.items())) or None


class ControllerClient(Protocol):
    async def login(  # pragma: no cover - structural typing declaration
        self, credentials: UniFiCredentials
    ) -> None: ...

    async def get_pages(  # pragma: no cover - structural typing declaration
        self, resource: str, *, site: str = "default"
    ) -> tuple[object, ...]: ...


CredentialLoader = Callable[[CredentialReference], UniFiCredentials]
ClientFactory = Callable[[UniFiEndpoint], ControllerClient]


@dataclass
class UniFiCollector:
    """Collector-framework adapter that authenticates and reads controller sites."""

    endpoint: UniFiEndpoint
    credential_loader: CredentialLoader
    client_factory: ClientFactory = UniFiClient
    name: str = "unifi"

    async def collect(self, context: CollectorContext) -> CollectorResult:
        if context.credential_ref is None:
            raise UniFiError("UniFi collection requires a credential reference")
        credentials = self.credential_loader(context.credential_ref)
        client = self.client_factory(self.endpoint)
        try:
            await client.login(credentials)
            sites = await client.get_pages("sites")
        finally:
            # Do not retain secrets longer than this invocation.
            credentials = UniFiCredentials("", "")
        issues: tuple[CollectorIssue, ...] = ()
        return CollectorResult(item_count=len(sites), issues=issues)


def endpoint_from_config(value: Mapping[str, object]) -> UniFiEndpoint:
    return UniFiEndpoint(
        url=str(value["url"]),
        api_type=str(value.get("api_type", "modern")),
        verify_tls=bool(value.get("verify_tls", True)),
        allow_self_signed=bool(value.get("allow_self_signed", False)),
    )
