#!/usr/bin/env python3
"""Generate a DevSecOps KB run artifact directly from OWASP ZAP outputs.

This script is a standalone Python implementation so it can be used on CI/CD
images that lack the Go toolchain. It can read alerts from a JSON file or fetch
live data from the ZAP API, normalize them into the KB entities model, and write
an import-ready run artifact (optionally zipped). Traffic capture is
configurable to balance evidence retention with artifact size.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

_AUTOMATION_SUCCESS_STATES = {"FINISHED", "COMPLETED", "DONE", "SUCCESS", "SUCCEEDED"}
_AUTOMATION_FAILURE_STATES = {"FAILED", "ABORTED", "ERRORED", "ERROR", "STOPPED", "HALTED"}


@dataclass
class AutomationStatus:
    status: str
    progress: float
    message: str
    raw: Dict[str, Any]

    def is_success(self) -> bool:
        return self.status.upper() in _AUTOMATION_SUCCESS_STATES

    def is_failure(self) -> bool:
        return self.status.upper() in _AUTOMATION_FAILURE_STATES

    def is_terminal(self) -> bool:
        return self.is_success() or self.is_failure()


def _compute_deadline(timeout_seconds: int) -> Optional[float]:
    if timeout_seconds and timeout_seconds > 0:
        return time.monotonic() + timeout_seconds
    return None


def _remaining_time(deadline: Optional[float]) -> Optional[float]:
    if deadline is None:
        return None
    return deadline - time.monotonic()


def _sleep_interval(poll_seconds: float, deadline: Optional[float]) -> float:
    poll = max(0.5, poll_seconds)
    if deadline is None:
        return poll
    remaining = _remaining_time(deadline)
    if remaining is None:
        return poll
    if remaining <= 0:
        return 0.0
    return max(0.1, min(poll, remaining))


def _parse_progress_value(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if text.endswith("%"):
        text = text[:-1]
    try:
        return float(text)
    except ValueError:
        return 0.0


def _extract_automation_payload(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict):
        current: Any = data
    else:
        return {}
    visited: set[int] = set()
    while isinstance(current, dict) and id(current) not in visited:
        visited.add(id(current))
        if any(
            key in current
            for key in (
                "planStatus",
                "status",
                "state",
                "planProgress",
                "progress",
                "completion",
            )
        ):
            return current
        next_dict: Optional[Dict[str, Any]] = None
        for key in (
            "automation",
            "autoRunDetails",
            "details",
            "run",
            "plan",
            "message",
            "status",
            "result",
        ):
            candidate = current.get(key)
            if isinstance(candidate, dict):
                next_dict = candidate
                break
        if next_dict is None:
            break
        current = next_dict
    return current if isinstance(current, dict) else {}

# ----------------------------- Helpers -------------------------------------


def _now_rfc3339() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _intish(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
    except Exception:
        return 0
    if not text:
        return 0
    try:
        return int(text)
    except ValueError:
        return 0


def _short_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]


def _split_refs(text: str) -> List[str]:
    lines = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            lines.append(line)
    return lines


def _ellipsis_middle(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    keep = limit - 1
    head = keep // 2
    tail = keep - head
    return f"{text[:head]}.{text[-tail:]}"


def _param_acronym(text: str) -> str:
    out: List[str] = []
    for chunk in filter(None, [c.strip() for c in text.split(" ")]):
        for token in chunk.replace("_", " ").replace("-", " ").split():
            token = token.strip()
            if not token:
                continue
            out.append(token[0].lower())
            if len(out) >= 8:
                break
        if len(out) >= 8:
            break
    return "".join(out)


def _rule_acronym(text: str) -> str:
    text = text.strip()
    if not text:
        return "ALRT"
    tokens = []
    word = ""
    for ch in text:
        if ch.isalnum():
            word += ch
        else:
            if word:
                tokens.append(word)
            word = ""
    if word:
        tokens.append(word)
    stop = {"header", "missing", "not", "set", "detected", "found", "the", "and", "of", "to", "in", "for", "a", "an"}
    out: List[str] = []
    for token in tokens:
        if token.lower() in stop:
            continue
        out.append(token[0].upper())
        if len(out) >= 5:
            break
    return "".join(out) or "ALRT"


def _url_base_or_parent(raw: str) -> Tuple[str, str]:
    raw = (raw or "").strip()
    if not raw:
        return "", ""
    parsed = urllib.parse.urlparse(raw)
    if not parsed.scheme and not parsed.netloc:
        segments = [segment for segment in raw.strip("/").split("/") if segment]
        if not segments:
            return "root", ""
        return segments[-1], ""
    path = parsed.path or "/"
    if path in {"", "/"}:
        return "", f"{parsed.netloc}/" if parsed.netloc else ""
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return "root", ""
    base = segments[-1]
    generic = {"index.html", "index.htm", "default.aspx", "home"}
    if base.lower() in generic and len(segments) >= 2:
        return f"{segments[-2]}/{base}", ""
    return base, ""


def _ensure_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _path_matches(base_path: str, candidate_path: str) -> bool:
    base_path = base_path or "/"
    candidate_path = candidate_path or "/"
    if not base_path.endswith("/"):
        trimmed = base_path.rstrip("/")
        if candidate_path == trimmed:
            return True
        return candidate_path.startswith(f"{trimmed}/")
    return candidate_path.startswith(base_path)


def _url_in_scope(url: str, scope: str) -> bool:
    if not scope:
        return True
    try:
        target = urllib.parse.urlparse(url)
    except Exception:
        return False
    try:
        base = urllib.parse.urlparse(scope)
    except Exception:
        return False

    if base.scheme and (target.scheme or "").lower() != base.scheme.lower():
        return False

    if base.netloc:
        if (target.netloc or "").lower() != base.netloc.lower():
            return False
    elif base.scheme:
        pass
    else:
        return _path_matches(base.path, target.path)

    return _path_matches(base.path or "/", target.path or "/")


def _make_finding_name(alert: Dict[str, Any]) -> str:
    rule = _first_non_empty(alert.get("alert"), alert.get("name"), alert.get("pluginId"))
    acronym = _rule_acronym(rule)
    base, host_root = _url_base_or_parent(str(alert.get("url", "")))
    name = f"{acronym}: "
    if base:
        name += base
    elif host_root:
        name += host_root
    param = str(alert.get("param", "")).strip()
    if param:
        name += f"[{_param_acronym(param)}]"
    return _ellipsis_middle(name, 40)


def _make_occurrence_name(alert: Dict[str, Any]) -> str:
    base, host_root = _url_base_or_parent(str(alert.get("url", "")))
    name = base or host_root
    param = str(alert.get("param", "")).strip()
    if param:
        name += f"[{_param_acronym(param)}]"
    return _ellipsis_middle(name, 40)


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _alert_source_ids(alert: Dict[str, Any]) -> List[str]:
    candidates: List[str] = []
    for key in ("messageId", "sourceMessageId", "sourceid", "sourceId"):
        value = alert.get(key)
        text = str(value or "").strip()
        if not text:
            continue
        if text not in candidates:
            candidates.append(text)
    return candidates


def _alert_key(alert: Dict[str, Any]) -> str:
    parts = [
        f"p:{str(alert.get('pluginId', '')).strip()}",
        f"u:{str(alert.get('url', '')).strip()}",
        f"m:{str(alert.get('method', '')).strip()}",
        f"pa:{str(alert.get('param', '')).strip()}",
        f"rk:{str(alert.get('riskcode', '')).strip()}",
        f"cf:{str(alert.get('confidence', '')).strip()}",
        f"ak:{str(alert.get('attack', '')).strip()}",
        f"ev:{str(alert.get('evidence', '')).strip()}",
    ]
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _finding_key(alert: Dict[str, Any]) -> str:
    return "|".join(
        [
            str(alert.get("pluginId", "")).strip(),
            str(alert.get("url", "")).strip(),
            str(alert.get("method", "")).strip(),
        ]
    )


def _truncate_utf8(text: str, limit: int) -> str:
    if limit <= 0:
        return text
    data = text.encode("utf-8")
    if len(data) <= limit:
        return text
    clipped = data[:limit]
    while clipped:
        try:
            return clipped.decode("utf-8")
        except UnicodeDecodeError as exc:
            clipped = clipped[:exc.start]
    return ""


def _parse_raw_headers(raw: str) -> List[Dict[str, str]]:
    if not raw:
        return []
    raw = raw.replace("\r\n", "\n")
    headers: List[Dict[str, str]] = []
    for index, line in enumerate(raw.split("\n")):
        line = line.rstrip("\r\n")
        if not line.strip():
            break
        if index == 0:
            headers.append({"name": "_line", "value": line})
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append({"name": name.strip(), "value": value.strip()})
        else:
            headers.append({"name": "_raw", "value": line})
    return headers


def _parse_response_headers(raw: str) -> Tuple[List[Dict[str, str]], int]:
    headers = _parse_raw_headers(raw)
    status = 0
    if headers:
        parts = headers[0]["value"].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    return headers, status


def _severity_code(value: str) -> int:
    mapping = {"high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0, "information": 0}
    return mapping.get(str(value or "").strip().lower(), 0)


# ----------------------------- ZAP client ----------------------------------


@dataclass
class ZapClient:
    base_url: str
    api_key: str | None = None
    timeout: int = 60

    def _build_url(self, path: str, params: Optional[Dict[str, str]] = None) -> str:
        params = dict(params or {})
        if self.api_key:
            params.setdefault("apikey", self.api_key)
        query = urllib.parse.urlencode(params, doseq=True)
        url = urllib.parse.urljoin(self.base_url.rstrip("/"), path)
        return f"{url}?{query}" if query else url

    def _request(self, path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        url = self._build_url(path, params)
        req = urllib.request.Request(url)
        if self.api_key:
            req.add_header("X-ZAP-API-Key", self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read()
                status = getattr(resp, "status", 200)
        except urllib.error.HTTPError as exc:
            snippet = exc.read() if hasattr(exc, "read") else b""
            detail = snippet.decode("utf-8", "ignore")
            raise RuntimeError(f"ZAP API {exc.code}: {detail}".strip()) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"ZAP API request failed: {exc.reason}") from exc
        if status >= 300:
            preview = payload[:512].decode("utf-8", "ignore")
            raise RuntimeError(f"ZAP API {status}: {preview}")
        try:
            return json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            preview = payload[:512].decode("utf-8", "ignore")
            raise RuntimeError(f"ZAP API returned invalid JSON: {preview}") from exc

    def get_alerts(self, *, base_url: Optional[str], count: Optional[int], page_size: int = 500) -> List[Dict[str, Any]]:
        collected: List[Dict[str, Any]] = []
        start = 0
        remaining = count if count and count > 0 else None
        while True:
            params = {"start": str(start), "count": str(page_size)}
            if base_url:
                params["baseurl"] = base_url
            data = self._request("/JSON/core/view/alerts", params)
            alerts = data.get("alerts", [])
            if not alerts:
                break
            collected.extend(alerts)
            fetched = len(alerts)
            start += fetched
            if remaining is not None:
                remaining -= fetched
                if remaining <= 0:
                    collected = collected[:count]
                    break
        return collected

    def get_message(self, history_id: str) -> Dict[str, Any]:
        data = self._request("/JSON/core/view/message", {"id": history_id})
        return data.get("message", {})

    def get_automation_status(self, plan_id: Optional[str] = None) -> AutomationStatus:
        params: Dict[str, str] = {}
        if plan_id:
            params["planId"] = plan_id
        try:
            payload = self._request("/JSON/automation/view/status", params)
        except RuntimeError as exc:
            raise RuntimeError(f"ZAP automation status request failed: {exc}") from exc
        details = _extract_automation_payload(payload)
        status = str(
            details.get("planStatus")
            or details.get("status")
            or details.get("state")
            or ""
        ).strip().upper()
        message = str(
            details.get("runMessage")
            or details.get("message")
            or details.get("planMessage")
            or ""
        ).strip()
        progress = _parse_progress_value(details.get("planProgress") or details.get("progress") or details.get("completion"))
        return AutomationStatus(status=status, progress=progress, message=message, raw=dict(details) if isinstance(details, dict) else {})

    def wait_for_automation(
        self,
        *,
        plan_id: Optional[str],
        poll_seconds: float = 5.0,
        deadline: Optional[float] = None,
        verbose: bool = False,
    ) -> AutomationStatus:
        poll = max(0.5, poll_seconds)
        last_status = ""
        last_progress = None
        last_message = ""
        while True:
            remaining = _remaining_time(deadline)
            if remaining is not None and remaining <= 0:
                raise TimeoutError("Timed out waiting for ZAP automation to finish")
            try:
                status = self.get_automation_status(plan_id=plan_id)
            except RuntimeError as exc:
                if verbose:
                    print(f"[zap-kb] automation status unavailable ({exc}); retrying in {poll:.1f}s", file=sys.stderr)
                sleep_for = _sleep_interval(poll, deadline)
                if sleep_for <= 0:
                    raise TimeoutError("Timed out waiting for ZAP automation to finish")
                time.sleep(sleep_for)
                continue

            display_status = status.status or "UNKNOWN"
            progress_changed = last_progress is None or abs(status.progress - (last_progress or 0.0)) >= 1.0
            message_changed = bool(status.message) and status.message != last_message
            if verbose and (
                status.status != last_status or (status.status == "RUNNING" and progress_changed) or message_changed
            ):
                progress_text = f"{status.progress:.1f}%" if status.progress else "0.0%"
                print(f"[zap-kb] automation status: {display_status} (progress {progress_text})", file=sys.stderr)
                if status.message:
                    print(f"[zap-kb] automation message: {status.message}", file=sys.stderr)

            if status.is_failure():
                raise RuntimeError(
                    f"ZAP automation finished with status {display_status}: {status.message or 'no details'}"
                )
            if status.is_success():
                return status

            last_status = status.status
            last_progress = status.progress
            last_message = status.message

            sleep_for = _sleep_interval(poll, deadline)
            if sleep_for <= 0:
                raise TimeoutError("Timed out waiting for ZAP automation to finish")
            time.sleep(sleep_for)

    def end_wait_job(
        self,
        *,
        plan_id: Optional[str],
        job_id: str,
        message: Optional[str] = None,
    ) -> None:
        if not job_id:
            raise ValueError("job_id is required to end a wait job")
        params: Dict[str, str] = {"jobId": job_id}
        if plan_id:
            params["planId"] = plan_id
        if message:
            params["message"] = message
        try:
            payload = self._request("/JSON/automation/action/endWaitJob", params)
        except RuntimeError as exc:
            raise RuntimeError(f"ZAP end wait job request failed: {exc}") from exc
        result = str(payload.get("Result") or payload.get("result") or payload.get("status") or "").strip()
        if result and result.upper() not in (_AUTOMATION_SUCCESS_STATES | {"OK"}):
            raise RuntimeError(f"ZAP end wait job returned unexpected response: {payload}")


# ----------------------------- Core logic ----------------------------------


def _deduplicate_alerts(alerts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    result: List[Dict[str, Any]] = []
    for alert in alerts:
        plugin = str(alert.get("pluginId", "")).strip()
        if not plugin:
            continue
        if not any(str(alert.get(field, "")).strip() for field in ("url", "param", "evidence")):
            continue
        key = _alert_key(alert)
        if key in seen:
            continue
        seen.add(key)
        result.append(alert)
    result.sort(key=lambda a: (
        str(a.get("pluginId", "")),
        str(a.get("url", "")),
        str(a.get("param", "")),
        str(a.get("evidence", "")),
    ))
    return result


def _normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key, value in alert.items():
        if isinstance(value, (dict, list)):
            normalized[key] = value
            continue
        if value is None:
            normalized[key] = ""
            continue
        normalized[key] = str(value)
    # Ensure required keys exist
    for field in ("pluginId", "alert", "name", "risk", "riskcode", "confidence", "url", "method", "param", "attack", "evidence", "other", "solution", "reference", "sourceid"):
        normalized.setdefault(field, "")
    normalized.setdefault("cweid", alert.get("cweid"))
    normalized.setdefault("wascid", alert.get("wascid"))
    return normalized


def build_entities(alerts: Sequence[Dict[str, Any]], source_tool: str, generated_at: str) -> Dict[str, Any]:
    definitions: Dict[str, Dict[str, Any]] = {}
    findings: Dict[str, Dict[str, Any]] = {}
    occurrences: List[Dict[str, Any]] = []

    for raw_alert in alerts:
        alert = _normalize_alert(raw_alert)
        plugin_id = alert.get("pluginId", "").strip()
        if not plugin_id:
            continue
        definition_id = f"def-{plugin_id}"
        if definition_id not in definitions:
            cwe = _intish(alert.get("cweid"))
            taxonomy = None
            if cwe > 0:
                taxonomy = {
                    "cweid": cwe,
                    "cweUri": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
                }
            remediation_summary = alert.get("solution", "").strip()
            remediation_refs = _split_refs(alert.get("reference", ""))
            remediation = {}
            if remediation_summary:
                remediation["summary"] = remediation_summary
            if remediation_refs:
                remediation["references"] = remediation_refs
            if not remediation:
                remediation = None
            definition = {
                "definitionId": definition_id,
                "pluginId": plugin_id,
                "alert": alert.get("alert", ""),
                "name": alert.get("name", ""),
                "wascid": _intish(alert.get("wascid")),
            }
            if taxonomy:
                definition["taxonomy"] = taxonomy
            if remediation:
                definition["remediation"] = remediation
            definitions[definition_id] = definition

        finding_key = _finding_key(alert)
        finding_id = f"fin-{_short_hash(finding_key)}"
        finding = findings.get(finding_id)
        if not finding:
            finding = {
                "findingId": finding_id,
                "definitionId": definition_id,
                "pluginId": plugin_id,
                "url": alert.get("url", ""),
                "method": alert.get("method", ""),
                "name": _make_finding_name(alert),
                "risk": alert.get("risk", ""),
                "riskcode": alert.get("riskcode", ""),
                "confidence": alert.get("confidence", ""),
                "occurrenceCount": 0,
            }
        finding["occurrenceCount"] = finding.get("occurrenceCount", 0) + 1
        findings[finding_id] = finding

        source_ids = _alert_source_ids(alert)
        primary_source_id = source_ids[0] if source_ids else ""

        occurrence = {
            "occurrenceId": f"occ-{_short_hash(_alert_key(alert))}",
            "definitionId": definition_id,
            "findingId": finding_id,
            "name": _make_occurrence_name(alert),
            "url": alert.get("url", ""),
            "method": alert.get("method", ""),
            "param": alert.get("param", ""),
            "attack": alert.get("attack", ""),
            "evidence": alert.get("evidence", ""),
            "risk": alert.get("risk", ""),
            "riskcode": alert.get("riskcode", ""),
            "confidence": alert.get("confidence", ""),
            "sourceId": primary_source_id,
        }

        if len(source_ids) > 1:
            occurrence["sourceIds"] = source_ids

        extra_ids = {"messageId": alert.get("messageId"), "sourceMessageId": alert.get("sourceMessageId")}
        for key, value in extra_ids.items():
            text_value = str(value or "").strip()
            if text_value:
                occurrence[key] = text_value

        occurrences.append(occurrence)

    definition_list = sorted(definitions.values(), key=lambda d: d["pluginId"])
    finding_list = sorted(
        findings.values(),
        key=lambda f: (f["pluginId"], f["url"], f["method"]),
    )
    occurrence_list = sorted(
        occurrences,
        key=lambda o: (o["findingId"], o["url"], o.get("param", ""), o.get("evidence", "")),
    )

    return {
        "schemaVersion": "v1",
        "generatedAt": generated_at,
        "sourceTool": source_tool,
        "definitions": definition_list,
        "findings": finding_list,
        "occurrences": occurrence_list,
    }


def enrich_traffic(
    entities: Dict[str, Any],
    client: ZapClient,
    scope: str,
    max_bytes: int,
    max_per_issue: int,
    total_max: int,
    min_risk: str,
) -> None:
    if not entities or not entities.get("occurrences"):
        return
    if scope not in {"first", "all"}:
        scope = "first"

    if scope == "all":
        indices = range(len(entities["occurrences"]))
    else:
        # Prioritise higher-risk findings when enforcing enrichment limits.
        indices = sorted(range(len(entities["occurrences"])), key=lambda i: -_severity_code(entities["occurrences"][i].get("risk", "")))

    per_issue: Dict[str, int] = {}
    enriched = 0
    floor = _severity_code(min_risk)

    for idx in indices:
        occ = entities["occurrences"][idx]
        if scope != "all":
            if total_max > 0 and enriched >= total_max:
                break
            if _severity_code(occ.get("risk", "")) < floor:
                continue
            if per_issue.get(occ["findingId"], 0) >= max(1, max_per_issue):
                continue
        candidate_ids: List[str] = []
        for key in ("sourceId", "messageId", "sourceMessageId"):
            value = occ.get(key)
            text_value = str(value or "").strip()
            if text_value and text_value not in candidate_ids:
                candidate_ids.append(text_value)
        for alt_id in occ.get("sourceIds", []) or []:
            text_value = str(alt_id or "").strip()
            if text_value and text_value not in candidate_ids:
                candidate_ids.append(text_value)
        if not candidate_ids:
            continue

        message = None
        for source_id in candidate_ids:
            try:
                message = client.get_message(source_id)
            except Exception:
                continue
            if message:
                break
        if not message:
            continue
        request_header = _ensure_text(message.get("requestHeader"))
        request_body = _ensure_text(message.get("requestBody"))
        response_header = _ensure_text(message.get("responseHeader"))
        response_body = _ensure_text(message.get("responseBody"))

        req_headers = _parse_raw_headers(request_header)
        resp_headers, status = _parse_response_headers(response_header)

        entities["occurrences"][idx]["request"] = {
            "headers": req_headers,
            "bodyBytes": len(request_body.encode("utf-8")),
            "bodySnippet": _truncate_utf8(request_body, max_bytes),
            "rawHeader": request_header,
            "rawHeaderBytes": len(request_header.encode("utf-8")),
        }
        entities["occurrences"][idx]["response"] = {
            "statusCode": status,
            "headers": resp_headers,
            "bodyBytes": len(response_body.encode("utf-8")),
            "bodySnippet": _truncate_utf8(response_body, max_bytes),
            "rawHeader": response_header,
            "rawHeaderBytes": len(response_header.encode("utf-8")),
        }

        if scope != "all":
            per_issue[occ["findingId"]] = per_issue.get(occ["findingId"], 0) + 1
            enriched += 1


# ----------------------------- I/O helpers ----------------------------------


def load_alerts_from_file(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "alerts" in data:
        alerts = data["alerts"]
    elif isinstance(data, list):
        alerts = data
    else:
        raise ValueError("Alerts JSON must be a list or contain an 'alerts' array")
    return [dict(alert) for alert in alerts]


def wait_for_alerts_file(
    path: Path,
    *,
    deadline: Optional[float],
    poll_seconds: float,
    verbose: bool,
) -> List[Dict[str, Any]]:
    poll = max(0.5, poll_seconds)
    last_error = ""
    announced_missing = False
    while True:
        remaining = _remaining_time(deadline)
        if remaining is not None and remaining <= 0:
            raise TimeoutError(f"Timed out waiting for alerts JSON at {path}")

        if not path.exists():
            if verbose and not announced_missing:
                print(f"[zap-kb] waiting for alerts file at {path}", file=sys.stderr)
            announced_missing = True
            sleep_for = _sleep_interval(poll, deadline)
            if sleep_for <= 0:
                raise TimeoutError(f"Timed out waiting for alerts JSON at {path}")
            time.sleep(sleep_for)
            continue

        announced_missing = False

        try:
            return load_alerts_from_file(path)
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            message = str(exc)
            if verbose and message != last_error:
                print(f"[zap-kb] alerts file not ready ({message}); retrying", file=sys.stderr)
            last_error = message

        sleep_for = _sleep_interval(poll, deadline)
        if sleep_for <= 0:
            raise TimeoutError(f"Timed out waiting for alerts JSON at {path}")
        time.sleep(sleep_for)


def filter_alerts(alerts: Iterable[Dict[str, Any]], base_url: Optional[str]) -> List[Dict[str, Any]]:
    if not base_url:
        return list(alerts)
    base_url = base_url.strip()
    return [alert for alert in alerts if _url_in_scope(str(alert.get("url", "")), base_url)]


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_zip(zip_path: Path, files: Dict[str, Path]) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for arcname, actual in files.items():
            if actual.exists():
                archive.write(actual, arcname)


# ----------------------------- CLI parsing ----------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a DevSecOps KB run artifact without the Go CLI.")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--alerts-json", help="Path to a ZAP alerts JSON export (array or {\"alerts\":[]} wrapper).")
    input_group.add_argument("--zap-url", help="ZAP API base URL, e.g. http://127.0.0.1:8090")

    parser.add_argument("-o", "--artifact", required=True, help="Path for the KB run artifact JSON (e.g. out/run.json).")
    parser.add_argument("--api-key", help="ZAP API key when using --zap-url.")
    parser.add_argument("--base-url", help="Filter alerts to a specific target base URL.")
    parser.add_argument("--count", type=int, help="Limit number of alerts fetched (API mode) or kept (file mode).")
    parser.add_argument("--source-tool", default="zap", help="Source tool recorded in the entities file (default: zap).")
    parser.add_argument("--generated-at", help="Override generatedAt timestamp (RFC3339).")
    parser.add_argument("--scan-label", help="Label for this scan run (meta.scanLabel).")
    parser.add_argument("--site-label", help="Override site/domain label for Obsidian import.")
    parser.add_argument("--zap-base-url", help="Public ZAP base URL used when rendering observation links.")
    parser.add_argument("--meta-commit", help="Populate meta.commit with a revision identifier.")
    parser.add_argument("--meta-branch", help="Populate meta.branch with a branch/ref name.")
    parser.add_argument("--meta-pipeline-run", help="Populate meta.pipelineRun with a CI run identifier.")
    parser.add_argument("--keep-alerts", action="store_true", help="Embed raw alerts in the artifact (default: drop them).")
    parser.add_argument("--zip-archive", help="Optional zip archive to package the artifact (and entities JSON).")
    parser.add_argument("--entities-json", help="Optional path to save the intermediate entities JSON alongside the artifact.")

    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Start in daemon mode: wait for ZAP automation (API mode) or the alerts JSON (file mode) before processing.",
    )
    parser.add_argument(
        "--daemon-timeout",
        type=int,
        default=0,
        help="Maximum seconds to wait in daemon mode before aborting (0 = no timeout).",
    )
    parser.add_argument(
        "--daemon-poll-interval",
        type=float,
        default=5.0,
        help="Seconds between readiness checks in daemon mode (default: 5).",
    )
    parser.add_argument(
        "--automation-plan-id",
        help="Optional ZAP automation plan identifier to monitor when --daemon is used with --zap-url.",
    )
    parser.add_argument(
        "--automation-wait-job-id",
        help="Optional ZAP automation wait job identifier to end after artifact generation.",
    )
    parser.add_argument(
        "--automation-wait-job-message",
        help="Optional message to include when ending the ZAP automation wait job.",
    )

    # Traffic capture tuning
    parser.add_argument("--include-traffic", action="store_true", help="Fetch HTTP request/response snippets from ZAP.")
    parser.add_argument("--traffic-scope", choices=["first", "all"], default="first", help="Capture only selected occurrences per finding (first) or every occurrence (all).")
    parser.add_argument("--traffic-max-bytes", type=int, default=2048, help="Truncate request/response bodies to this many bytes (default: 2048).")
    parser.add_argument("--traffic-max-per-issue", type=int, default=1, help="When scope=first, capture up to this many occurrences per finding (default: 1).")
    parser.add_argument("--traffic-total-max", type=int, default=0, help="Global cap on enriched occurrences (0 = unlimited).")
    parser.add_argument("--traffic-min-risk", choices=["info", "low", "medium", "high"], default="info", help="Only capture traffic for occurrences at or above this risk level.")

    parser.add_argument("--timeout", type=int, default=60, help="HTTP timeout for ZAP API requests (seconds).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print progress messages to stderr.")
    return parser


# ----------------------------- Main flow ------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    artifact_path = Path(args.artifact).expanduser().resolve()
    entities_path = Path(args.entities_json).expanduser().resolve() if args.entities_json else None
    zip_path = Path(args.zip_archive).expanduser().resolve() if args.zip_archive else None

    alerts: Optional[List[Dict[str, Any]]] = None
    zap_client: Optional[ZapClient] = None
    alert_file = Path(args.alerts_json).expanduser().resolve() if args.alerts_json else None
    daemon_deadline = _compute_deadline(args.daemon_timeout) if args.daemon else None
    poll_interval = args.daemon_poll_interval if args.daemon else 5.0
    if args.daemon and poll_interval <= 0:
        poll_interval = 5.0
    if args.daemon and args.verbose:
        timeout_text = f"{args.daemon_timeout}s" if args.daemon_timeout and args.daemon_timeout > 0 else "no timeout"
        print(
            f"[zap-kb] daemon mode enabled (poll {poll_interval:.1f}s, timeout {timeout_text})",
            file=sys.stderr,
        )

    if alert_file:
        if args.daemon:
            if args.verbose:
                print(f"[zap-kb] waiting for alerts file at {alert_file}", file=sys.stderr)
            try:
                alerts = wait_for_alerts_file(
                    alert_file,
                    deadline=daemon_deadline,
                    poll_seconds=poll_interval,
                    verbose=args.verbose,
                )
            except TimeoutError as exc:
                parser.error(str(exc))
        else:
            if not alert_file.exists():
                parser.error(f"alerts JSON not found: {alert_file}")
            alerts = load_alerts_from_file(alert_file)
        if args.verbose:
            print(f"[zap-kb] loaded alerts from {alert_file}", file=sys.stderr)
        alerts = filter_alerts(alerts, args.base_url)
        if args.count and args.count > 0:
            alerts = alerts[: args.count]
    else:
        zap_client = ZapClient(base_url=args.zap_url, api_key=args.api_key, timeout=args.timeout)
        if args.daemon:
            if args.verbose:
                plan_label = args.automation_plan_id or "<default>"
                print(f"[zap-kb] waiting for ZAP automation plan {plan_label}", file=sys.stderr)
            try:
                zap_client.wait_for_automation(
                    plan_id=args.automation_plan_id,
                    poll_seconds=poll_interval,
                    deadline=daemon_deadline,
                    verbose=args.verbose,
                )
            except (RuntimeError, TimeoutError) as exc:
                parser.error(str(exc))
        if args.verbose:
            print("[zap-kb] fetching alerts from ZAP API", file=sys.stderr)
        alerts = zap_client.get_alerts(base_url=args.base_url, count=args.count)

    if alerts is None:
        parser.error("No alerts available; daemon mode may have timed out before data was ready.")

    if args.verbose:
        print(f"[zap-kb] loaded {len(alerts)} alerts before de-duplication", file=sys.stderr)

    alerts = _deduplicate_alerts(alerts)

    if args.verbose:
        print(f"[zap-kb] retained {len(alerts)} unique alerts", file=sys.stderr)

    generated_at = args.generated_at or _now_rfc3339()
    entities = build_entities(alerts, args.source_tool, generated_at)

    if args.include_traffic:
        if not zap_client and args.zap_url:
            zap_client = ZapClient(base_url=args.zap_url, api_key=args.api_key, timeout=args.timeout)
        if not zap_client:
            parser.error("--include-traffic requires --zap-url so HTTP messages can be retrieved")
        if args.verbose:
            print("[zap-kb] enriching occurrences with traffic", file=sys.stderr)
        enrich_traffic(
            entities,
            zap_client,
            scope=args.traffic_scope,
            max_bytes=max(args.traffic_max_bytes, 0),
            max_per_issue=args.traffic_max_per_issue,
            total_max=args.traffic_total_max,
            min_risk=args.traffic_min_risk,
        )

    if entities_path:
        if args.verbose:
            print(f"[zap-kb] writing entities JSON to {entities_path}", file=sys.stderr)
        write_json(entities_path, entities)

    meta = {
        "sourceTool": entities.get("sourceTool"),
        "generatedAt": entities.get("generatedAt"),
        "scanLabel": args.scan_label or "",
        "siteLabel": args.site_label or "",
        "zapBaseUrl": args.zap_base_url or "",
        "baseUrl": args.base_url or "",
        "includeTraffic": bool(args.include_traffic),
    }
    if args.meta_commit:
        meta["commit"] = args.meta_commit
    if args.meta_branch:
        meta["branch"] = args.meta_branch
    if args.meta_pipeline_run:
        meta["pipelineRun"] = args.meta_pipeline_run

    artifact = {
        "schema": "zap-kb/run/v1",
        "meta": meta,
        "entities": entities,
    }
    if args.keep_alerts:
        artifact["alerts"] = alerts

    if args.verbose:
        print(f"[zap-kb] writing run artifact to {artifact_path}", file=sys.stderr)
    write_json(artifact_path, artifact)

    cleanup_files: List[Path] = []
    if zip_path:
        files = {artifact_path.name: artifact_path}
        if entities_path:
            files.setdefault(entities_path.name, entities_path)
        elif not args.entities_json:
            temp_entities_path = artifact_path.with_suffix(".entities.json")
            write_json(temp_entities_path, entities)
            files[temp_entities_path.name] = temp_entities_path
            cleanup_files.append(temp_entities_path)
        if args.verbose:
            print(f"[zap-kb] packaging artifact zip at {zip_path}", file=sys.stderr)
        write_zip(zip_path, files)
        for temp_file in cleanup_files:
            try:
                temp_file.unlink()
            except FileNotFoundError:
                pass

    if args.automation_wait_job_id:
        if not zap_client and args.zap_url:
            zap_client = ZapClient(base_url=args.zap_url, api_key=args.api_key, timeout=args.timeout)
        if not zap_client:
            parser.error("--automation-wait-job-id requires --zap-url so the wait job can be ended via the ZAP API.")
        try:
            zap_client.end_wait_job(
                plan_id=args.automation_plan_id,
                job_id=args.automation_wait_job_id,
                message=args.automation_wait_job_message,
            )
        except RuntimeError as exc:
            parser.error(str(exc))
        if args.verbose:
            print(
                f"[zap-kb] ended automation wait job {args.automation_wait_job_id}",
                file=sys.stderr,
            )

    if args.verbose:
        print("[zap-kb] done", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
