---
aliases:
  - "CSSR script_src-bf0b"
attack: "javascript:alert(1);"
confidence: "Medium"
definitionId: "def-40012"
domain: "public-firing-range.appspot.com"
evidence: "javascript:alert(1);"
findingId: "fin-a977b39f9fe28700"
generatedAt: "2025-09-21T20:00:10Z"
host: "public-firing-range.appspot.com"
id: "occ-6dc39e1091febf0b"
issueId: "fin-a977b39f9fe28700"
kind: "observation"
method: "GET"
observationId: "occ-6dc39e1091febf0b"
observedAt: "2025-09-21T20:00:10Z"
param: "q"
path: "/reflected/url/script_src"
queryKeys: "q"
risk: "High"
riskId: "3"
scan.label: "Google Firing Range run 2"
schemaVersion: "v1"
sourceId: "1"
sourceTool: "zap"
url: "https://public-firing-range.appspot.com/reflected/url/script_src?q=javascript%3Aalert%281%29%3B"
---

# Observation occ-6dc39e1091febf0b — CSSR script_src-bf0b

> [!Warning]
> Risk: High () — Confidence: Medium

- Definition: [[definitions/40012-cross-site-scripting-reflected.md|def-40012]]
- Issue: [[findings/fin-a977b39f9fe28700.md|fin-a977b39f9fe28700]]

**Endpoint:** GET https://public-firing-range.appspot.com/reflected/url/script_src?q=javascript%3Aalert%281%29%3B

## Rule summary

- Title: Cross Site Scripting (Reflected) (Plugin 40012)
- WASC: 8
- CWE: 79
- CWE URI: https://cwe.mitre.org/data/definitions/79.html
- Remediation: Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
  - https://owasp.org/www-community/attacks/xss/
  - https://cwe.mitre.org/data/definitions/79.html

## Endpoint details

- Scheme: https
- Host: public-firing-range.appspot.com
- Path: /reflected/url/script_src
- Query keys: q

**Param:** q

**Attack:** `javascript:alert(1);`

## Evidence

```
javascript:alert(1);
```

## Repro (curl)

```bash
curl -H _line: GET https://www.google.com/search?client=firefox-b-d&q=google+firing+range HTTP/1.1 -H User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0 -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.5 -H Connection: keep-alive "https://public-firing-range.appspot.com/reflected/url/script_src?q=javascript%3Aalert%281%29%3B"
```

## Traffic

### Request

GET https://public-firing-range.appspot.com/reflected/url/script_src?q=javascript%3Aalert%281%29%3B

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
