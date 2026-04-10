#!/usr/bin/env python3
"""Delete all issues in the KAN Jira project.

Usage:
    set JIRA_USER=you@example.com
    set JIRA_API_TOKEN=yourtoken
    python scripts/delete_kan_issues.py
"""
import os
import sys
import base64
import json
import http.client
import urllib.parse
import time

JIRA_BASE = "jameslerud.atlassian.net"
PROJECT   = "KAN"

user  = os.environ.get("JIRA_USER", "")
token = os.environ.get("JIRA_API_TOKEN", "")
if not user or not token:
    print("ERROR: Set JIRA_USER and JIRA_API_TOKEN env vars")
    sys.exit(1)

auth = base64.b64encode(f"{user}:{token}".encode()).decode()
headers = {
    "Authorization": f"Basic {auth}",
    "Content-Type":  "application/json",
    "Accept":        "application/json",
}

def request(method, path, body=None):
    conn = http.client.HTTPSConnection(JIRA_BASE)
    data = json.dumps(body).encode() if body else None
    conn.request(method, path, data, headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(raw)
    except Exception:
        return resp.status, raw.decode(errors="replace")

# Collect all issue IDs via cursor-paginated POST /rest/api/3/search/jql
all_issues = []
page_size = 100
next_token = None
while True:
    body = {"jql": f"project = {PROJECT}", "maxResults": page_size, "fields": ["id", "key", "summary"]}
    if next_token:
        body["nextPageToken"] = next_token
    status, data = request("POST", "/rest/api/3/search/jql", body)
    if status != 200:
        print(f"Search failed (HTTP {status}): {data}")
        sys.exit(1)

    issues = data.get("issues", [])
    all_issues.extend(issues)
    print(f"  fetched {len(all_issues)} issues so far")

    next_token = data.get("nextPageToken")
    if not next_token or len(issues) < page_size:
        break

print(f"\nFound {len(all_issues)} issues to delete")
if not all_issues:
    print("Nothing to delete.")
    sys.exit(0)

# Show a sample
for iss in all_issues[:5]:
    print(f"  {iss['key']}: {iss['fields'].get('summary','')[:80]}")
if len(all_issues) > 5:
    print(f"  ... and {len(all_issues) - 5} more")

confirm = input("\nDelete ALL of these? (yes/no): ").strip().lower()
if confirm != "yes":
    print("Aborted.")
    sys.exit(0)

deleted = 0
failed  = 0
for iss in all_issues:
    key = iss["key"]
    status, _ = request("DELETE", f"/rest/api/2/issue/{key}")
    if status == 204:
        deleted += 1
        if deleted % 10 == 0:
            print(f"  deleted {deleted}/{len(all_issues)}")
    else:
        print(f"  FAILED to delete {key}: HTTP {status}")
        failed += 1
    time.sleep(0.25)  # rate limit courtesy

print(f"\nDone: deleted={deleted} failed={failed}")
