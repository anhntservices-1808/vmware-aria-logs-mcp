"""VMware Aria Operations for Logs — MCP Server.

Exposes Log Insight API v2 and optional vROps correlation as MCP tools.
"""

from __future__ import annotations

import json
import os
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .analysis.events import dedupe_events
from .analysis.incidents import detect_mass_incidents, incidents_to_dicts
from .clients.loginsight import EventConstraint, LogInsightClient, LogInsightError
from .clients.vrops import VropsClient


def _parse_int_env(name: str, default: int) -> int:
    """Parse an integer environment variable with a clear error on bad input."""
    raw = os.environ.get(name, str(default))
    try:
        return int(raw)
    except ValueError:
        raise LogInsightError(f"{name} must be an integer, got: {raw!r}") from None


def _build_transport_security() -> TransportSecuritySettings:
    """Build transport security settings for the streamable-HTTP transport.

    The MCP SDK enables DNS-rebinding protection by default, which rejects
    requests whose Host header is not in an allow-list (HTTP 421 when reached
    via an IP/hostname other than localhost). Behind Tailscale + a read-only
    container this adds little, so it is disabled by default and can be
    re-enabled via env:

      MCP_DNS_REBINDING_PROTECTION=true   -> enforce allow-lists
      MCP_ALLOWED_HOSTS=host1,host2        -> allowed Host headers (when enforced)
      MCP_ALLOWED_ORIGINS=origin1,origin2  -> allowed Origin headers (when enforced)
    """
    enabled = os.environ.get("MCP_DNS_REBINDING_PROTECTION", "false").lower() in (
        "true",
        "1",
        "yes",
    )
    hosts = [h.strip() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
    origins = [
        o.strip() for o in os.environ.get("MCP_ALLOWED_ORIGINS", "").split(",") if o.strip()
    ]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=enabled,
        allowed_hosts=hosts or ["*"],
        allowed_origins=origins or ["*"],
    )


mcp = FastMCP(
    "vmware-aria-logs",
    instructions="VMware Aria Operations for Logs (Log Insight) — log search, incident detection, vROps correlation",
    transport_security=_build_transport_security(),
)

# ---------------------------------------------------------------------------
# Lazy client singletons — created on first tool call
# ---------------------------------------------------------------------------

_li_client: LogInsightClient | None = None
_vrops_client: VropsClient | None = None


def _get_li_client() -> LogInsightClient:
    global _li_client
    if _li_client is None:
        base_url = (
            os.environ.get("LI_BASE_URL") or os.environ.get("LI_API_BASE_URL") or ""
        )
        if not base_url:
            raise LogInsightError("LI_BASE_URL environment variable is required")
        _li_client = LogInsightClient(
            base_url=base_url,
            username=os.environ.get("LI_USERNAME")
            or os.environ.get("LI_API_USER")
            or "admin",
            password=os.environ.get("LI_PASSWORD")
            or os.environ.get("LI_API_PASSWORD")
            or "",
            provider=os.environ.get("LI_PROVIDER")
            or os.environ.get("LI_API_PROVIDER")
            or "Local",
            verify_tls=os.environ.get("LI_VERIFY_TLS", "false").lower()
            in ("true", "1", "yes"),
            timeout_sec=_parse_int_env("LI_TIMEOUT_SEC", 30),
        )
    return _li_client


def _get_vrops_client() -> VropsClient | None:
    global _vrops_client
    if _vrops_client is None:
        base_url = os.environ.get("VROPS_BASE_URL") or ""
        if not base_url:
            return None
        _vrops_client = VropsClient(
            base_url=base_url,
            username=os.environ.get("VROPS_USERNAME")
            or os.environ.get("VROPS_USER")
            or "admin",
            password=os.environ.get("VROPS_PASSWORD") or "",
            auth_source=os.environ.get("VROPS_AUTH_SOURCE") or "local",
            verify_tls=os.environ.get("VROPS_VERIFY_TLS", "false").lower()
            in ("true", "1", "yes"),
            timeout_sec=_parse_int_env("VROPS_TIMEOUT_SEC", 30),
        )
    return _vrops_client


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def query_events(
    lookback_minutes: int = 60,
    search_term: str = "",
    limit: int = 100,
    field_name: str = "",
    field_operator: str = "CONTAINS",
    field_value: str = "",
) -> str:
    """Search log events in VMware Aria Operations for Logs.

    Args:
        lookback_minutes: How far back to search (default 60 minutes).
        search_term: Free-text search term (optional).
        limit: Maximum number of events to return (default 100, max 10000).
        field_name: Optional field constraint name (e.g. 'hostname', 'appname').
        field_operator: Constraint operator (CONTAINS, NOT_CONTAINS, HAS, etc.).
        field_value: Constraint value.

    Returns:
        JSON array of log events with text, source, timestamp, and fields.
    """
    client = _get_li_client()
    lookback_minutes = max(1, min(lookback_minutes, 10_080))  # cap at 1 week
    limit = max(1, min(limit, 10_000))
    constraints = None
    if field_name and field_value:
        if len(field_name) > 128:
            return json.dumps({"error": "field_name exceeds 128 characters"})
        try:
            constraints = [
                EventConstraint(
                    field_name=field_name, operator=field_operator, value=field_value
                )
            ]
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
    # Fetch extra to compensate for duplicates removed by dedup
    fetch_limit = min(limit * 2, 10_000)
    events = client.query_events(
        lookback_minutes=lookback_minutes,
        term=search_term,
        constraints=constraints,
        limit=fetch_limit,
    )
    events = dedupe_events(events)
    return json.dumps(events[:limit], ensure_ascii=False, indent=2)


@mcp.tool()
def get_version() -> str:
    """Get VMware Aria Operations for Logs appliance version and API surface.

    Returns version info and probes key API endpoints to determine
    which features are available on this deployment.
    """
    client = _get_li_client()
    if not client.token:
        client.authenticate()

    version_info = client.probe_endpoint(method="GET", path="/api/v2/version")
    dashboards = client.probe_endpoint(
        method="GET", path="/vrlic/api/v1/content/dashboards"
    )
    queries = client.probe_endpoint(
        method="GET", path="/vrlic/api/v1/query-definitions"
    )

    result = {
        "base_url": client.base_url,
        "version": version_info.get("parsed", {}),
        "api_surface": {
            "v2_version": version_info["verdict"],
            "legacy_dashboards": dashboards["verdict"],
            "legacy_query_definitions": queries["verdict"],
        },
    }
    return json.dumps(result, ensure_ascii=False, indent=2)


@mcp.tool()
def list_dashboards() -> str:
    """List saved dashboards from Aria Operations for Logs.

    NOTE: On-premise Aria Operations for Logs (vRealize Log Insight) does not
    expose a REST endpoint to list dashboards. The ``/vrlic/...`` content API
    only exists on the vRLI *Cloud* service. On an on-prem appliance every
    dashboard path returns 404, so this tool reports that clearly instead of
    silently returning empty. Use ``list_alerts`` for configured alerting, or
    the appliance web UI to view dashboards.
    """
    client = _get_li_client()
    dashboards = client.list_dashboards()
    if dashboards:
        return json.dumps(dashboards[:50], ensure_ascii=False, indent=2)
    return json.dumps(
        {
            "message": "Dashboard listing is not available via REST on on-prem "
            "Aria Operations for Logs (Cloud-only /vrlic API). "
            "Use list_alerts or the web UI instead.",
            "supported": False,
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def detect_incidents(
    lookback_minutes: int = 60,
    search_term: str = "",
    event_limit: int = 5000,
    mass_threshold: int = 5,
    max_incidents: int = 20,
) -> str:
    """Detect mass log incidents using signature clustering (Stormbreaker engine).

    Queries events, groups them by normalized signature pattern, and returns
    clusters that exceed the mass threshold — ranked by event count.

    Args:
        lookback_minutes: How far back to search (default 60 minutes).
        search_term: Free-text search term (optional, empty = all events).
        event_limit: Max events to fetch for analysis (default 5000).
        mass_threshold: Min events per signature to qualify as incident (default 5).
        max_incidents: Max incidents to return (default 20).

    Returns:
        JSON with ranked incidents including signature, event count,
        blast radius (affected sources), and sample text.
    """
    client = _get_li_client()
    lookback_minutes = max(1, min(lookback_minutes, 10_080))
    mass_threshold = max(1, mass_threshold)
    max_incidents = max(1, min(max_incidents, 100))
    events = client.query_events(
        lookback_minutes=lookback_minutes,
        term=search_term,
        limit=min(event_limit, 10_000),
    )
    events = dedupe_events(events)
    incidents = detect_mass_incidents(
        events,
        mass_threshold=mass_threshold,
        max_incidents=max_incidents,
    )
    return json.dumps(
        {
            "total_events_analyzed": len(events),
            "incidents_found": len(incidents),
            "lookback_minutes": lookback_minutes,
            "incidents": incidents_to_dicts(incidents),
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def find_vrops_resources(name: str) -> str:
    """Find resources in VMware Aria Operations (vROps) by name.

    Useful for correlating Log Insight events with vROps monitored entities.
    Requires VROPS_BASE_URL to be configured.

    Args:
        name: Resource name to search for (VM name, host name, etc.).

    Returns:
        JSON array of matching vROps resources with IDs, names, and types.
    """
    client = _get_vrops_client()
    if client is None:
        return json.dumps({"error": "vROps not configured (VROPS_BASE_URL not set)"})
    resources = client.find_resources(name)
    compact = [
        {
            "identifier": r.get("identifier", ""),
            "name": (r.get("resourceKey") or {}).get("name", ""),
            "resourceKind": (r.get("resourceKey") or {}).get("resourceKindKey", ""),
            "adapterKind": (r.get("resourceKey") or {}).get("adapterKindKey", ""),
            "health": r.get("resourceHealth", ""),
        }
        for r in resources[:20]
    ]
    return json.dumps(compact, ensure_ascii=False, indent=2)


@mcp.tool()
def get_vrops_alerts(resource_ids: str) -> str:
    """Get alerts from VMware Aria Operations for specific resources.

    Args:
        resource_ids: Comma-separated vROps resource IDs.

    Returns:
        JSON array of alerts with severity, status, and descriptions.
    """
    client = _get_vrops_client()
    if client is None:
        return json.dumps({"error": "vROps not configured (VROPS_BASE_URL not set)"})
    ids = [rid.strip() for rid in resource_ids.split(",") if rid.strip()]
    if not ids:
        return json.dumps({"error": "No resource IDs provided"})
    if len(ids) > 100:
        return json.dumps({"error": "Too many resource IDs (max 100)"})
    alerts = client.get_alerts(ids)
    compact = [
        {
            "alertId": a.get("alertId", ""),
            "alertLevel": a.get("alertLevel", ""),
            "status": a.get("status", ""),
            "alertDefinitionName": (a.get("alertDefinitionName") or a.get("name", "")),
            "startTimeUTC": a.get("startTimeUTC", 0),
            "resourceId": a.get("resourceId", ""),
        }
        for a in alerts[:50]
    ]
    return json.dumps(compact, ensure_ascii=False, indent=2)


@mcp.tool()
def aggregate_events(
    lookback_minutes: int = 60,
    group_by_field: str = "source",
    search_term: str = "",
    top_n: int = 10,
) -> str:
    """Server-side aggregation: count events grouped by a field (top talkers).

    Far more accurate than client-side counting for "top N hosts/sources"
    questions, because the appliance aggregates across ALL events (no 10k
    fetch cap).

    Args:
        lookback_minutes: How far back to aggregate (default 60).
        group_by_field: Field to group by (e.g. 'source', 'hostname',
            'appname', 'vmw_host'). Use list_fields to discover names.
        search_term: Optional free-text filter before aggregation.
        top_n: Number of top groups to return (default 10, max 100).

    Returns:
        JSON with ranked groups [{key, count}] sorted by count desc.
    """
    client = _get_li_client()
    lookback_minutes = max(1, min(lookback_minutes, 10_080))
    top_n = max(1, min(top_n, 100))
    if len(group_by_field) > 128:
        return json.dumps({"error": "group_by_field exceeds 128 characters"})
    payload = client.query_aggregated(
        lookback_minutes=lookback_minutes,
        group_by_field=group_by_field,
        term=search_term,
    )
    totals: dict[str, float] = {}
    for b in payload.get("bins", []):
        if not isinstance(b, dict):
            continue
        keys = b.get("keys") or []
        key = keys[0] if isinstance(keys, list) and keys else "(all)"
        try:
            totals[key] = totals.get(key, 0) + float(b.get("value", 0) or 0)
        except (TypeError, ValueError):
            continue
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
    return json.dumps(
        {
            "group_by_field": group_by_field,
            "lookback_minutes": lookback_minutes,
            "distinct_groups": len(totals),
            "top": [{"key": k, "count": int(v)} for k, v in ranked],
        },
        ensure_ascii=False,
        indent=2,
    )


@mcp.tool()
def list_alerts(only_enabled: bool = False, limit: int = 100) -> str:
    """List configured alert definitions in Aria Operations for Logs.

    Shows what the appliance is actively watching for (thresholds, hit
    counts, recipients) — far more useful on-prem than dashboards.

    Args:
        only_enabled: If True, return only enabled alerts.
        limit: Max alerts to return (default 100, max 500).

    Returns:
        JSON array of alert definitions (compacted).
    """
    client = _get_li_client()
    limit = max(1, min(limit, 500))
    alerts = client.list_alerts()
    if only_enabled:
        alerts = [a for a in alerts if a.get("enabled")]
    compact = [
        {
            "name": a.get("name", ""),
            "enabled": a.get("enabled"),
            "type": a.get("type", ""),
            "hitCount": a.get("hitCount", 0),
            "hitOperator": a.get("hitOperator", ""),
            "info": (a.get("info") or "")[:200],
            "recipients": a.get("recipients", ""),
        }
        for a in alerts[:limit]
    ]
    return json.dumps(
        {"total": len(alerts), "alerts": compact}, ensure_ascii=False, indent=2
    )


@mcp.tool()
def list_fields(name_filter: str = "", limit: int = 100) -> str:
    """List log fields available for querying/aggregation.

    Use this to discover valid field names (incl. custom CF_* fields) before
    using field constraints in query_events or aggregate_events.

    Args:
        name_filter: Optional case-insensitive substring filter on field name.
        limit: Max fields to return (default 100, max 1000).

    Returns:
        JSON array of fields with internalName, displayName, fieldType.
    """
    client = _get_li_client()
    limit = max(1, min(limit, 1000))
    fields = client.list_fields()
    nf = name_filter.strip().lower()
    if nf:
        fields = [
            f
            for f in fields
            if nf in str(f.get("internalName", "")).lower()
            or nf in str(f.get("displayName", "")).lower()
        ]
    compact = [
        {
            "internalName": f.get("internalName", ""),
            "displayName": f.get("displayName", ""),
            "fieldType": f.get("fieldType", ""),
            "static": f.get("isStatic", False),
        }
        for f in fields[:limit]
    ]
    return json.dumps(
        {"total": len(fields), "fields": compact}, ensure_ascii=False, indent=2
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _build_http_app():
    """Build the Starlette ASGI app for streamable-HTTP transport.

    Wraps the MCP streamable-HTTP app under ``/`` and adds a lightweight
    ``/health`` route for container/nginx health checks. Routes are declared
    upfront (rather than mutating an existing router) so this stays robust if
    the MCP SDK ever returns a compiled/wrapped ASGI app.
    """
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route

    mcp_app = mcp.streamable_http_app()

    async def _health(_request) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "vmware-aria-logs-mcp"})

    return Starlette(
        routes=[
            Route("/health", _health, methods=["GET"]),
            Mount("/", app=mcp_app),
        ],
        lifespan=lambda app: mcp_app.router.lifespan_context(mcp_app),
    )


def main() -> None:
    """Run the MCP server.

    Transport is selected via the ``MCP_TRANSPORT`` env var:
      - ``stdio`` (default): classic stdio transport, spawn-per-call.
      - ``http`` / ``streamable-http``: long-running streamable-HTTP server
        bound to ``MCP_HOST``:``MCP_PORT`` (default 0.0.0.0:8770), MCP at /mcp.
    """
    transport = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
    if transport in ("http", "streamable-http", "streamable_http"):
        import uvicorn

        host = os.environ.get("MCP_HOST", "0.0.0.0")
        port = _parse_int_env("MCP_PORT", 8770)
        uvicorn.run(_build_http_app(), host=host, port=port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
