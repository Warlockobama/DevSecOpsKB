---
aliases:
  - "STS documentwrite-c453"
confidence: "High"
definitionId: "def-10035"
domain: "public-firing-range.appspot.com"
findingId: "fin-33679564f2106b38"
generatedAt: "2025-09-21T20:00:10Z"
host: "public-firing-range.appspot.com"
id: "occ-7c89bcc52db6c453"
issueId: "fin-33679564f2106b38"
kind: "observation"
method: "GET"
observationId: "occ-7c89bcc52db6c453"
observedAt: "2025-09-21T20:00:10Z"
path: "/address/baseURI/documentwrite"
risk: "Low"
riskId: "1"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceId: "3"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/address/baseURI/documentwrite"
---

# Observation occ-7c89bcc52db6c453 — STS documentwrite-c453

> [!Note]
> Risk: Low () — Confidence: High

- Definition: [[definitions/10035-strict-transport-security-header-not-set.md|def-10035]]
- Issue: [[findings/fin-33679564f2106b38.md|fin-33679564f2106b38]]

**Endpoint:** GET https://public-firing-range.appspot.com/address/baseURI/documentwrite

## Rule summary

- Title: Strict-Transport-Security Header Not Set (Plugin 10035)
- WASC: 15
- CWE: 319
- CWE URI: https://cwe.mitre.org/data/definitions/319.html
- Remediation: Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security.
  - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
  - https://owasp.org/www-community/Security_Headers

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /address/baseURI/documentwrite

## Repro (curl)

```bash
curl -H _line: GET https://www.google.com/search?client=firefox-b-d&q=google+firing+range&sei=j_jJaNXSKOmMwbkP-Je1uAY HTTP/1.1 -H User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0 -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.5 -H Connection: keep-alive "https://public-firing-range.appspot.com/address/baseURI/documentwrite"
```

## Traffic

### Request

GET https://public-firing-range.appspot.com/address/baseURI/documentwrite

_Headers: 13_

Headers:
- _line: GET https://www.google.com/search?client=firefox-b-d&q=google+firing+range&sei=j_jJaNXSKOmMwbkP-Je1uAY HTTP/1.1
- host: www.google.com
- User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0
- Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
- Accept-Language: en-US,en;q=0.5
- Connection: keep-alive
- Referer: https://www.google.com/search?client=firefox-b-d&q=google+firing+range
- Cookie: AEC=AVh_V2itGPFDy5NUTrzLCDO3sa8KowSPzR6cXXkBS1p36ngCcV5V1EHlCQ; NID=525=OkkS3xU62zImhRB86gbEo-uP8Lk1Xk2VCXW0o3qI5oRhTHGcov8z9UDM2BQuJEHBKaZzyJYexOXSqvCVOX8TYEJgRtWQoTAGbx2U8h39A-L6zAufpA84ULfhOcpcI_N6jlMMnFgDyeD1HZDOIAjkT5zC_QC-BXce8YoQr7PdivVpfmL9GegnQ-zl76ci2baXJ3IENnT0KkLmHiRvMN0QBhsO; SG_SS=*U2-abzfyAAZbjm8ie4595FfvUN4BTp8EADQBEArZ1IOkeoirLVMc47Q1dpKfWE68LqdQQbkqHG0kpX1GY6PBJXtMYWmsaTv_Ts60_LCpPQAAABttAAAABVcBB0EANWNC5Lu5dBWD7y-CEzDi_tZajAkA3YbN-WhTQRvHEMv3EOSii1UUCgR5IPROGA11KIH5Nn0qpgIzRdbsHHiiU87BZ6S4RgNthH3Hpd2TX8q0PMwd1JNv8fWaXd7VCjCvank9Z79GANj3NmzaApi1rfELEzPLlsHuqVfdAbvM5mIk6QqHBQYWqAc1YZcHNwemsUnFaNEQqYCVFTZpCBusdHEy5VEjD7BIoeA5jiKwMF_PyAtB28QoMTOT73ei4jdSX3UA3-oD79dViQT3O28HAbomsUa0g-L1VXEmL4TwZmyRMma2iilQcRWwnunRK9k9pBFHIEG95GTTGcYCcG1Xblb8g11vTU-lj4NHomW-r08gjWoLRJ-nEvaj4Ea5aGwLTAAcfJx6pfcdScSwVvqIcjo4mmUkf3_Y69RelOZbVo7PVQ3XgR1HlK8OhQTJNKVqS0eCQLbhJ07yHDhdmZxnssaAqsFeu4Qif8EBg1_kQqdWAcvatcRsJRjFZT3TTdMCSZOUYCYBBDCEIvCXlB1yYfDaUHDE2-Q0RSa_mDhbvMj14h4x1tJJ2sYTeGgEv5xwsslV-ky5BCXUBg4cuMCIbDYO3bP422Ylj8urE7sqDlp8fWmB_6_Pfh4AmRQf3JAmXjwlmHjNfike3Oa6hVrR-gtU77L69Dsa3sEIxBndOhoD1n5eOJfpp2ZuS3nFTtNvshvmEYcgb7ix5kraiMgTDsgDL1Rr54fzo045P0NNypdFv4TaEAwYlTtGp8tH_cHKlzsc7lOCrwBBe5fvMBqq-5CjmOiZrErYwoNa7z9IJsWRv7subBSwAC8gGig
- Upgrade-Insecure-Requests: 1
- Sec-Fetch-Dest: document
- Sec-Fetch-Mode: navigate
- Sec-Fetch-Site: same-origin
- Priority: u=0, i

### Response

Status: 302

_Content-Type: text/html; charset=UTF-8_

_Content-Length: 453_

_Headers: 17_

Headers:
- _line: HTTP/1.1 302 Found
- Location: https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dgoogle%2Bfiring%2Brange%26sei%3Dj_jJaNXSKOmMwbkP-Je1uAY&q=EgSB3qOYGJDxp8YGIjDveYUWABxXj37Uckg8e5nyxzUCm3Hoex3ej7Ur3nbuOglgQJYhcGkp8XUuNILWJFQyAVJaAUM
- x-hallmonitor-challenge: CgsIkPGnxgYQxab6XhIEgd6jmA
- Content-Type: text/html; charset=UTF-8
- Strict-Transport-Security: max-age=31536000
- Content-Security-Policy: object-src 'none';base-uri 'self';script-src 'nonce-ywte5NpqQJJqpHOu_nH5kw' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/fff
- Cross-Origin-Opener-Policy: same-origin-allow-popups; report-to="gws"
- Report-To: {"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/fff"}]}
- P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
- Date: Tue, 16 Sep 2025 23:53:52 GMT
- Server: gws
- Content-Length: 453
- X-XSS-Protection: 0
- X-Frame-Options: SAMEORIGIN
- Set-Cookie: SG_SS=0;Expires=Mon, 01-Jan-1990 00:00:00 GMT
- Set-Cookie: NID=525=baAJ1j2d332_8mvxKTNiaMuty7-V-NCpCx3LVhAWOWGxeCqItbmsW6vpmJ9XlJl2ZKBsBpr6K25XWn3GlYeVpncmZahs4tGofSmIyyJ9AqazIOpg7zLB-WaxPnOxcDbMUcu8HEFRyZlAP8mgZn6M9U3stX3zPVUGnqHOGzRk9MXllNbq9rrBeUa576cCJkqi7iDfszgIafGEgtn5LydNVqYWE8z_u-GVULtg5Fv1zuDuQM6qJD-v; expires=Wed, 18-Mar-2026 23:53:51 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=none
- Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000

```http
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>302 Moved</TITLE></HEAD><BODY>
<H1>302 Moved</H1>
The document has moved
<A HREF="https://www.google.com/sorry/index?continue=https://www.google.com/search%3Fclient%3Dfirefox-b-d%26q%3Dgoogle%2Bfiring%2Brange%26sei%3Dj_jJaNXSKOmMwbkP-Je1uAY&amp;q=EgSB3qOYGJDxp8YGIjDveYUWABxXj37Uckg8e5nyxzUCm3Hoex3ej7Ur3nbuOglgQJYhcGkp8XUuNILWJFQyAVJaAUM">here</A>.
</BODY></HTML>

```

## Triage guidance

- Validate the finding manually and confirm exploitability in this context.
- Document false-positive conditions and add ignores where appropriate.

## Workflow

- Status: open

### Checklist

- [ ] Triage
- [ ] Validate
- [ ] File ticket
- [ ] Fix verified
- [ ] Close

### Governance

- False positive reason: 
- Acceptance justification: 
- Acceptance expires at (UTC): 
- Due at (UTC): 
