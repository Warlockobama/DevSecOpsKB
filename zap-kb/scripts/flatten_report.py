#!/usr/bin/env python3
"""Flatten a ZAP JSON-plus report (site->alerts->instances) into zap-kb friendly alerts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse


RISK_BY_CODE = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
}

CONFIDENCE_BY_CODE = {
    "0": "False Positive",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Confirmed",
}

RISK_ALIASES = {
    "informational": "informational",
    "info": "informational",
    "information": "informational",
    "low": "low",
    "medium": "medium",
    "med": "medium",
    "high": "high",
}


@dataclass(frozen=True)
class Filters:
    risks: Optional[Set[str]]
    plugin_ids: Optional[Set[str]]
    hosts: Optional[Set[str]]
    url_prefixes: Optional[List[str]]
    limit: Optional[int]


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert the JSON-plus report (site->alerts->instances) into the flat alert "
            "array accepted by zap-kb's -in flag."
        )
    )
    parser.add_argument("--report", required=True, help="Path to the JSON-plus report.")
    parser.add_argument("--out", required=True, help="Destination path for flattened alerts JSON.")
    parser.add_argument(
        "--risk",
        action="append",
        help="Comma/list of risk levels to keep (info, low, medium, high). Default: keep all.",
    )
    parser.add_argument(
        "--plugin",
        action="append",
        help="Comma/list of plugin IDs to include. Default: include every plugin.",
    )
    parser.add_argument(
        "--host",
        action="append",
        help="Comma/list of site hosts to include (matches @host or URL netloc).",
    )
    parser.add_argument(
        "--url-prefix",
        action="append",
        help="Comma/list of URL prefixes to include. All prefixes optional; any match passes the filter.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Optional cap on the number of flattened alerts emitted (after filtering).",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=None,
        help="Pretty-print JSON with the provided indent. Default: compact output.",
    )
    parser.add_argument(
        "--delete-report",
        action="store_true",
        help="Delete the source report after successful conversion.",
    )
    return parser.parse_args(argv)


def normalize_list(values: Optional[Iterable[str]]) -> List[str]:
    items: List[str] = []
    if not values:
        return items
    for raw in values:
        if raw is None:
            continue
        for piece in raw.split(","):
            piece = piece.strip()
            if piece:
                items.append(piece)
    return items


def normalize_risk_filters(raw: Optional[Iterable[str]]) -> Optional[Set[str]]:
    names = normalize_list(raw)
    if not names:
        return None
    normalized = set()
    for name in names:
        key = name.lower()
        if key not in RISK_ALIASES:
            raise SystemExit(f"Unknown risk level '{name}'. Expected one of: {', '.join(sorted(RISK_ALIASES))}.")
        normalized.add(RISK_ALIASES[key])
    return normalized


def normalize_string_set(values: Optional[Iterable[str]]) -> Optional[Set[str]]:
    items = normalize_list(values)
    if not items:
        return None
    return {item.lower() for item in items}


def normalize_plugin_set(values: Optional[Iterable[str]]) -> Optional[Set[str]]:
    items = normalize_list(values)
    if not items:
        return None
    return {item.strip() for item in items}


def decode_risk_name(alert: Dict[str, Any]) -> str:
    code = str(alert.get("riskcode", "")).strip()
    if code in RISK_BY_CODE:
        return RISK_BY_CODE[code]
    desc = alert.get("riskdesc") or ""
    if desc:
        head = desc.split("(", 1)[0].strip()
        if head:
            return head
    return ""


def decode_confidence(alert: Dict[str, Any]) -> str:
    code = str(alert.get("confidence", "")).strip()
    if code in CONFIDENCE_BY_CODE:
        return CONFIDENCE_BY_CODE[code]
    desc = alert.get("riskdesc") or ""
    if "(" in desc and desc.endswith(")"):
        inner = desc.split("(", 1)[1].rstrip(")")
        inner = inner.strip()
        if inner:
            return inner
    return ""


def coerce_int(value: Any) -> int:
    if value in (None, "", "-", "null"):
        return 0
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return 0


def extract_host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:  # pragma: no cover - defensive
        return ""


def matches_filters(
    record: Dict[str, Any],
    site_meta: Dict[str, Any],
    filters: Filters,
) -> bool:
    if filters.risks:
        if record["risk"].lower() not in filters.risks:
            return False
    if filters.plugin_ids:
        if record["pluginId"] not in filters.plugin_ids:
            return False
    if filters.hosts:
        site_host = (site_meta.get("@host") or "").lower()
        url_host = extract_host(record.get("url", ""))
        if site_host not in filters.hosts and url_host not in filters.hosts:
            return False
    if filters.url_prefixes:
        url_value = record.get("url") or ""
        if not any(url_value.startswith(prefix) for prefix in filters.url_prefixes):
            return False
    return True


def flatten_report(data: Dict[str, Any], filters: Filters) -> List[Dict[str, Any]]:
    flattened: List[Dict[str, Any]] = []
    sites = data.get("site") or []
    for site in sites:
        alerts = site.get("alerts") or []
        for alert in alerts:
            plugin_id = str(alert.get("pluginid", "")).strip()
            risk_code = str(alert.get("riskcode", "")).strip()
            confidence_code = str(alert.get("confidence", "")).strip()
            base = {
                "pluginId": plugin_id,
                "alert": alert.get("alert", ""),
                "name": alert.get("name", ""),
                "riskcode": risk_code,
                "confidence": decode_confidence(alert),
                "risk": decode_risk_name(alert),
                "solution": strip_html(alert.get("solution", "")),
                "reference": strip_html(alert.get("reference", "")),
                "cweid": coerce_int(alert.get("cweid")),
                "wascid": coerce_int(alert.get("wascid")),
                "sourceid": str(alert.get("sourceid", "")).strip(),
                "tags": [t.get("tag") for t in alert.get("tags", []) if isinstance(t, dict) and t.get("tag")],
            }
            instances = alert.get("instances") or [{}]
            for inst in instances:
                record = dict(base)
                record.update(
                    {
                        "url": inst.get("uri") or alert.get("uri") or site.get("@name") or "",
                        "method": inst.get("method") or "",
                        "param": inst.get("param") or "",
                        "attack": inst.get("attack") or "",
                        "evidence": inst.get("evidence") or "",
                        "other": inst.get("otherinfo") or alert.get("otherinfo") or "",
                        "requestHeader": inst.get("request-header") or "",
                        "requestBody": inst.get("request-body") or "",
                        "responseHeader": inst.get("response-header") or "",
                        "responseBody": inst.get("response-body") or "",
                    }
                )
                if not record["risk"]:
                    record["risk"] = decode_risk_name(alert)
                if not record["confidence"]:
                    record["confidence"] = decode_confidence(alert)

                record["risk"] = record["risk"] or RISK_BY_CODE.get(risk_code, "")
                record["confidence"] = record["confidence"] or CONFIDENCE_BY_CODE.get(confidence_code, "")

                if matches_filters(record, site, filters):
                    flattened.append(record)
                    if filters.limit and len(flattened) >= filters.limit:
                        return flattened
    return flattened


def strip_html(value: str) -> str:
    if not isinstance(value, str):
        return ""
    if "<" not in value:
        return value.strip()
    normalized = (
        value.replace("</p>", "\n")
        .replace("<p>", "\n")
        .replace("<br/>", "\n")
        .replace("<br />", "\n")
        .replace("<br>", "\n")
        .replace("</li>", "\n")
        .replace("</div>", "\n")
    )
    cleaned = re.sub(r"<[^>]+>", "", normalized)
    lines = [line.strip() for line in cleaned.splitlines()]
    return "\n".join(line for line in lines if line)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    report_path = Path(args.report)
    out_path = Path(args.out)

    if not report_path.exists():
        print(f"[!] Report not found: {report_path}", file=sys.stderr)
        return 2

    risk_filters = normalize_risk_filters(args.risk)
    plugin_filters = normalize_plugin_set(args.plugin)
    host_filters = normalize_string_set(args.host)
    prefixes = normalize_list(args.url_prefix)

    filters = Filters(
        risks=risk_filters,
        plugin_ids=plugin_filters,
        hosts=host_filters,
        url_prefixes=prefixes if prefixes else None,
        limit=args.limit if args.limit and args.limit > 0 else None,
    )

    with report_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    flattened = flatten_report(data, filters)
    if not flattened:
        print("[!] No alerts matched the provided filters.", file=sys.stderr)
    else:
        print(f"[+] Flattened {len(flattened)} alert instances.")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        json.dump(flattened, handle, indent=args.indent)

    if args.delete_report:
        report_path.unlink(missing_ok=True)
        print(f"[+] Deleted source report: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
