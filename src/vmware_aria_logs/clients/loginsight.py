"""Log Insight API v2 client — read-only operations."""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


class LogInsightError(RuntimeError):
    """Raised when a Log Insight API call fails."""


# HTTP statuses that indicate the session token is expired/invalid and a
# single re-login + retry is warranted. vLI returns 440 "Login Timeout"
# for an expired session id; 401 covers a rejected/blank token.
_AUTH_EXPIRED_STATUSES = frozenset({401, 440})


VALID_OPERATORS = frozenset(
    {
        "CONTAINS",
        "NOT_CONTAINS",
        "HAS",
        "NOT_HAS",
        "EQ",
        "NE",
        "GT",
        "GE",
        "LT",
        "LE",
        "MATCHES_REGEX",
        "NOT_MATCHES_REGEX",
        "EXISTS",
    }
)


@dataclass(frozen=True)
class EventConstraint:
    """A single field constraint for event queries."""

    field_name: str
    operator: str  # CONTAINS, NOT_CONTAINS, HAS, etc.
    value: str

    def __post_init__(self) -> None:
        if self.operator not in VALID_OPERATORS:
            raise ValueError(
                f"Unknown operator: {self.operator!r}. Valid: {sorted(VALID_OPERATORS)}"
            )


@dataclass
class LogInsightClient:
    """Small client for the Log Insight API v2 read path.

    Supports session-based Bearer token auth and event querying with
    arbitrary field constraints.
    """

    base_url: str
    username: str
    password: str = field(default="", repr=False)
    provider: str = "Local"
    verify_tls: bool = False
    timeout_sec: int = 30
    token: str = field(default="", repr=False)
    # Proactive token lifecycle: refresh before the vLI session TTL expires.
    _token_expiry: float = field(default=0.0, repr=False)
    # Safety margin (seconds) subtracted from the TTL so we refresh early.
    token_refresh_buffer_sec: int = 60

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in ("https", "http"):
            raise LogInsightError(
                f"base_url must use http(s) scheme, got: {parsed.scheme!r}"
            )
        if not parsed.netloc:
            raise LogInsightError("base_url must include a hostname")
        if self.verify_tls:
            self._ssl_ctx = ssl.create_default_context()
        else:
            self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request_raw(
        self,
        *,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[int, str]:
        url = f"{self.base_url}{path}"
        data = None
        headers: dict[str, str] = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(
                request, context=self._ssl_ctx, timeout=self.timeout_sec
            ) as resp:
                body = resp.read().decode("utf-8")
                return int(getattr(resp, "status", resp.getcode())), body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return int(exc.code), body
        except urllib.error.URLError as exc:
            raise LogInsightError(f"request failed {method} {path}: {exc}") from exc

    def _request_json(
        self,
        *,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        _retried: bool = False,
    ) -> Any:
        status, body = self._request_raw(method=method, path=path, payload=payload)
        if (
            status in _AUTH_EXPIRED_STATUSES
            and not _retried
            and path != "/api/v2/sessions"
            and self.username
        ):
            # Session token expired/invalid (401 Unauthorized or
            # 440 Login Timeout) -- invalidate, re-login once, and retry.
            self._invalidate_token()
            self.authenticate()
            return self._request_json(
                method=method, path=path, payload=payload, _retried=True
            )
        if status >= 400:
            raise LogInsightError(f"HTTP {status} for {method} {path}: {body[:400]}")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise LogInsightError(
                f"non-JSON response for {path}: {body[:400]}"
            ) from exc

    def authenticate(self) -> str:
        """Obtain a session token. Returns the token string."""
        response = self._request_json(
            method="POST",
            path="/api/v2/sessions",
            payload={
                "username": self.username,
                "password": self.password,
                "provider": self.provider,
            },
        )
        token = str(
            response.get("sessionId")
            or response.get("session_id")
            or response.get("id")
            or ""
        ).strip()
        if not token:
            raise LogInsightError("auth succeeded but no session id returned")
        self.token = token
        # Record when this session token should be proactively refreshed.
        ttl_raw = response.get("ttl")
        try:
            ttl = float(ttl_raw) if ttl_raw is not None else 1800.0
        except (TypeError, ValueError):
            ttl = 1800.0
        # Never let the effective lifetime collapse to <= 0 from the buffer.
        effective = max(ttl - self.token_refresh_buffer_sec, ttl * 0.5, 1.0)
        self._token_expiry = time.monotonic() + effective
        return token

    def _invalidate_token(self) -> None:
        """Drop the cached session token, forcing a fresh login next time."""
        self.token = ""
        self._token_expiry = 0.0

    def _ensure_token(self) -> None:
        """Proactively (re)authenticate before the session TTL expires.

        Logs in when there is no token, or when the cached token is at/past
        its refresh deadline. This is the primary auth mechanism; the
        401/440 retry in ``_request_json`` is only a safety net.
        """
        if not self.token or time.monotonic() >= self._token_expiry:
            self._invalidate_token()
            self.authenticate()

    def _build_events_path(
        self,
        *,
        lookback_minutes: int,
        term: str = "",
        constraints: list[EventConstraint] | None = None,
        limit: int = 100,
    ) -> str:
        parts = [
            urllib.parse.quote("timestamp", safe=""),
            urllib.parse.quote(f"LAST {max(lookback_minutes, 1) * 60_000}", safe=""),
        ]
        if term:
            parts.extend(
                [
                    urllib.parse.quote("text", safe=""),
                    urllib.parse.quote("CONTAINS", safe="")
                    + "%20"
                    + urllib.parse.quote(term.strip(), safe=""),
                ]
            )
        for c in constraints or []:
            parts.extend(
                [
                    urllib.parse.quote(c.field_name, safe=""),
                    urllib.parse.quote(c.operator, safe="")
                    + "%20"
                    + urllib.parse.quote(c.value, safe=""),
                ]
            )
        return f"/api/v2/events/{'/'.join(parts)}?limit={int(limit)}"

    def query_events(
        self,
        *,
        lookback_minutes: int = 60,
        term: str = "",
        constraints: list[EventConstraint] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query events from Log Insight. Returns list of event dicts."""
        self._ensure_token()
        path = self._build_events_path(
            lookback_minutes=lookback_minutes,
            term=term,
            constraints=constraints,
            limit=limit,
        )
        payload = self._request_json(method="GET", path=path)
        return _extract_events(payload)

    def get_version(self) -> dict[str, Any]:
        """Get appliance version info."""
        self._ensure_token()
        return self._request_json(method="GET", path="/api/v2/version")

    def probe_endpoint(self, *, method: str, path: str) -> dict[str, Any]:
        """Probe an API endpoint and return availability info."""
        self._ensure_token()
        status, body = self._request_raw(method=method, path=path)
        if (
            status in _AUTH_EXPIRED_STATUSES
            and path != "/api/v2/sessions"
            and self.username
        ):
            # Probe bypasses _request_json's retry, so handle an expired/invalid
            # session here too: invalidate, re-login once, and probe again.
            self._invalidate_token()
            self.authenticate()
            status, body = self._request_raw(method=method, path=path)
        parsed: Any = None
        if body.strip():
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = None
        if status == 404:
            verdict = "unavailable"
        elif status >= 400:
            verdict = "auth_or_transport_error"
        else:
            verdict = "available"
        return {
            "method": method,
            "path": path,
            "http_status": status,
            "verdict": verdict,
            "body_excerpt": body[:500] if verdict != "available" else "",
            "parsed": parsed if isinstance(parsed, (dict, list)) else None,
        }

    def list_dashboards(self) -> list[dict[str, Any]]:
        """List saved dashboards via the legacy vRLIC API.

        Note: The ``/vrlic/api/v1/content/dashboards`` endpoint was deprecated
        starting in Aria Operations for Logs 8.18.  On 8.18+ appliances this
        method will return an empty list (probe verdict "unavailable").
        """
        self._ensure_token()
        result = self.probe_endpoint(
            method="GET", path="/vrlic/api/v1/content/dashboards"
        )
        if result["verdict"] == "available" and isinstance(result["parsed"], list):
            return result["parsed"]
        if isinstance(result["parsed"], dict):
            items = (
                result["parsed"].get("dashboards")
                or result["parsed"].get("content")
                or []
            )
            if isinstance(items, list):
                return items
        return []

    def query_aggregated(
        self,
        *,
        lookback_minutes: int = 60,
        group_by_field: str = "",
        term: str = "",
        constraints: list[EventConstraint] | None = None,
        aggregation_function: str = "COUNT",
    ) -> dict[str, Any]:
        """Run a server-side aggregation (COUNT/UCOUNT) over events.

        Returns the raw aggregation payload with ``bins``. When
        ``group_by_field`` is set, each bin includes a ``keys`` list
        identifying the group it counts.
        """
        if not self.token:
            self.authenticate()
        parts = [
            urllib.parse.quote("timestamp", safe=""),
            urllib.parse.quote(f"LAST {max(lookback_minutes, 1) * 60_000}", safe=""),
        ]
        if term:
            parts.extend(
                [
                    urllib.parse.quote("text", safe=""),
                    urllib.parse.quote("CONTAINS", safe="")
                    + "%20"
                    + urllib.parse.quote(term.strip(), safe=""),
                ]
            )
        for c in constraints or []:
            parts.extend(
                [
                    urllib.parse.quote(c.field_name, safe=""),
                    urllib.parse.quote(c.operator, safe="")
                    + "%20"
                    + urllib.parse.quote(c.value, safe=""),
                ]
            )
        query: dict[str, str] = {"aggregation-function": aggregation_function}
        if group_by_field:
            query["group-by-field"] = group_by_field
        path = (
            f"/api/v2/aggregated-events/{'/'.join(parts)}?"
            + urllib.parse.urlencode(query)
        )
        payload = self._request_json(method="GET", path=path)
        return payload if isinstance(payload, dict) else {"bins": []}

    def count_events(
        self,
        *,
        lookback_minutes: int = 60,
        term: str = "",
        constraints: list[EventConstraint] | None = None,
    ) -> int:
        """Exact total event count over a window (sum of aggregation bins).

        Unlike a grouped aggregation, a single-group COUNT fits within the
        appliance's ~100-bin response, so the summed total is exact and
        stable across calls. Use with a field constraint (e.g. source EQ x)
        for reliable per-entity counts.
        """
        payload = self.query_aggregated(
            lookback_minutes=lookback_minutes,
            term=term,
            constraints=constraints,
        )
        total = 0.0
        for b in payload.get("bins", []):
            if isinstance(b, dict):
                try:
                    total += float(b.get("value", 0) or 0)
                except (TypeError, ValueError):
                    continue
        return int(total)

    def list_alerts(self) -> list[dict[str, Any]]:
        """List configured alert definitions (on-prem ``/api/v2/alerts``)."""
        self._ensure_token()
        payload = self._request_json(method="GET", path="/api/v2/alerts")
        if isinstance(payload, list):
            return [a for a in payload if isinstance(a, dict)]
        if isinstance(payload, dict):
            for key in ("alerts", "alert", "items"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [a for a in value if isinstance(a, dict)]
        return []

    def list_fields(self) -> list[dict[str, Any]]:
        """List available log fields (on-prem ``/api/v2/fields``)."""
        self._ensure_token()
        payload = self._request_json(method="GET", path="/api/v2/fields")
        if isinstance(payload, list):
            return [f for f in payload if isinstance(f, dict)]
        if isinstance(payload, dict):
            for key in ("fields", "items"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [f for f in value if isinstance(f, dict)]
        return []


def _extract_events(payload: Any) -> list[dict[str, Any]]:
    """Extract event list from various API response shapes."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("events", "results", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []
