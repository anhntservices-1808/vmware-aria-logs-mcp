# Changelog

## 0.1.1 (2026-06-17)

- fix(auth): auto re-login on HTTP 401 in LogInsightClient._request_json.
  Long-lived HTTP-server process previously held a stale vLI session token
  until manual container restart. Now a single re-auth + retry happens on 401
  (excludes /api/v2/sessions, capped at one retry to avoid lockout loops).

## 0.1.0 (2026-04-06)

- Initial release
- 6 MCP tools: query_events, detect_incidents, get_version, list_dashboards, find_vrops_resources, get_vrops_alerts
- Stormbreaker signature clustering engine for mass incident detection
- Optional VMware Aria Operations (vROps) cross-correlation
- Zero external HTTP dependencies (stdlib urllib only)
- 98% test coverage (86 tests)
