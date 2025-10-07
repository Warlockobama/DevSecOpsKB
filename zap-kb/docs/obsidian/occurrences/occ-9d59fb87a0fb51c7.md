---
aliases:
  - "HCAVH index.html-51c7"
confidence: "Medium"
definitionId: "def-10047"
domain: "public-firing-range.appspot.com"
evidence: "http://public-firing-range.appspot.com/badscriptimport/index.html"
findingId: "fin-8f05b055439ca9c1"
generatedAt: "2025-09-21T20:00:10Z"
host: "public-firing-range.appspot.com"
id: "occ-9d59fb87a0fb51c7"
issueId: "fin-8f05b055439ca9c1"
kind: "observation"
method: "GET"
observationId: "occ-9d59fb87a0fb51c7"
observedAt: "2025-09-21T20:00:10Z"
path: "/badscriptimport/index.html"
risk: "Low"
riskId: "1"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceId: "1"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/badscriptimport/index.html"
---

# Observation occ-9d59fb87a0fb51c7 — HCAVH index.html-51c7

> [!Note]
> Risk: Low () — Confidence: Medium

- Definition: [[definitions/10047-https-content-available-via-http.md|def-10047]]
- Issue: [[findings/fin-8f05b055439ca9c1.md|fin-8f05b055439ca9c1]]

**Endpoint:** GET https://public-firing-range.appspot.com/badscriptimport/index.html

## Rule summary

- Title: HTTPS Content Available via HTTP (Plugin 10047)
- WASC: 4
- CWE: 311
- CWE URI: https://cwe.mitre.org/data/definitions/311.html
- Remediation: Ensure that your web server, application server, load balancer, etc. is configured to only serve such content via HTTPS. Consider implementing HTTP Strict Transport Security.
  - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
  - https://owasp.org/www-community/Security_Headers

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /badscriptimport/index.html

## Evidence

```
http://public-firing-range.appspot.com/badscriptimport/index.html
```

## Repro (curl)

```bash
curl -H _line: GET https://www.google.com/search?client=firefox-b-d&q=google+firing+range HTTP/1.1 -H User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0 -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.5 -H Connection: keep-alive "https://public-firing-range.appspot.com/badscriptimport/index.html"
```

## Traffic

### Request

GET https://public-firing-range.appspot.com/badscriptimport/index.html

_Headers: 12_

Headers:
- _line: GET https://www.google.com/search?client=firefox-b-d&q=google+firing+range HTTP/1.1
- host: www.google.com
- User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0
- Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
- Accept-Language: en-US,en;q=0.5
- Connection: keep-alive
- Upgrade-Insecure-Requests: 1
- Sec-Fetch-Dest: document
- Sec-Fetch-Mode: navigate
- Sec-Fetch-Site: none
- Sec-Fetch-User: ?1
- Priority: u=0, i

### Response

Status: 200

_Content-Type: text/html; charset=UTF-8_

_Content-Length: 84242_

_Headers: 20_

Headers:
- _line: HTTP/1.1 200 OK
- Content-Type: text/html; charset=UTF-8
- Strict-Transport-Security: max-age=31536000
- Content-Security-Policy: object-src 'none';base-uri 'self';script-src 'nonce-YGSL19v0akIoYNqdeqrBzw' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/fff
- Cross-Origin-Opener-Policy: same-origin-allow-popups; report-to="gws"
- Report-To: {"group":"gws","max_age":2592000,"endpoints":[{"url":"https://csp.withgoogle.com/csp/report-to/gws/fff"}]}
- Accept-CH: Sec-CH-Prefers-Color-Scheme
- P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
- Date: Tue, 16 Sep 2025 23:53:51 GMT
- Server: gws
- X-XSS-Protection: 0
- X-Frame-Options: SAMEORIGIN
- Expires: Tue, 16 Sep 2025 23:53:51 GMT
- Cache-Control: private
- Set-Cookie: AEC=AVh_V2itGPFDy5NUTrzLCDO3sa8KowSPzR6cXXkBS1p36ngCcV5V1EHlCQ; expires=Sun, 15-Mar-2026 23:53:51 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
- Set-Cookie: NID=525=OkkS3xU62zImhRB86gbEo-uP8Lk1Xk2VCXW0o3qI5oRhTHGcov8z9UDM2BQuJEHBKaZzyJYexOXSqvCVOX8TYEJgRtWQoTAGbx2U8h39A-L6zAufpA84ULfhOcpcI_N6jlMMnFgDyeD1HZDOIAjkT5zC_QC-BXce8YoQr7PdivVpfmL9GegnQ-zl76ci2baXJ3IENnT0KkLmHiRvMN0QBhsO; expires=Wed, 18-Mar-2026 23:53:51 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=none
- Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
- Accept-Ranges: none
- Vary: Accept-Encoding
- content-length: 84242

```http
<!DOCTYPE html><html lang="en"><head><title>Google Search</title><style>body{background-color:var(--xhUGwc)}</style><script nonce="YGSL19v0akIoYNqdeqrBzw">window.google = window.google || {};window.google.c = window.google.c || {ezx:false,cap:0};</script></head><body><noscript><style>table,div,span,p{display:none}</style><meta content="0;url=/httpservice/retry/enablejs?sei=j_jJaNXSKOmMwbkP-Je1uAY" http-equiv="refresh"><div style="display:block">Please click <a href="/httpservice/retry/enablejs?sei=j_jJaNXSKOmMwbkP-Je1uAY">here</a> if you are not redirected within a few seconds.</div></noscript><script nonce="YGSL19v0akIoYNqdeqrBzw">(function(){var sctm=false;(function(){sctm&&google.tick("load","pbsst");}).call(this);})();</script><script nonce="YGSL19v0akIoYNqdeqrBzw">//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjogMywic291cmNlcyI6WyIiXSwic291cmNlc0NvbnRlbnQiOlsiICJdLCJuYW1lcyI6WyJjbG9zdXJlRHluYW1pY0J1dHRvbiJdLCJtYXBwaW5ncyI6IkFBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEifQ==
(function(){var M=function(V,t,p,z,U,I,S,n,x,C){for(x=t;x!=86;)if(x==35){if((S=(n=z,B.trustedTypes))&&S.createPolicy){try{n=S.createPolicy(U,{createHTML:F,createScript:F,createScriptURL:F})}catch(e){if(B.console)B.console[I](e.message)}C=n}else C=n;x=66}else if(x==V)x=(p>>2&7)>=4&&p-3>>4<4?5:25;else if(x==5)C=z,x=25;else if(x==t)x=V;else{if(x==66)return C;x==25&&(x=(p^22)>=11&&p-V>>5<1?35:66)}},F=function(V){return M.call(this,8,62,16,V)},B=this||self;(0,eval)(function(V,t){return(t=M(8,62,3,null,"ks","error"))&&V.eval(t.createScript("1"))===1?function(p){return t.createScript(p)}:function(p){return""+p}}(B)(Array(Math.random()*7824|0).join("\n")+['//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjogMywic291cmNlcyI6WyIiXSwic291cmNlc0NvbnRlbnQiOlsiICJdLCJuYW1lcyI6WyJjbG9zdXJlRHluYW1pY0J1dHRvbiJdLCJtYXBwaW5ncyI6IkFBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUEifQ==',
'(function(){/*',
'',
' Copyright Google LLC',
' SPDX-License-Identifier: Apache-2.0',
'*/',
'var v7=function(p,V,x,t,n
```

_Response body truncated to 2048 bytes (of 84242)_

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
