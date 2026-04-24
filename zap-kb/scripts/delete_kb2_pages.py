#!/usr/bin/env python3
"""Delete pages in a Confluence space (one-off cleanup before fresh export).

This is a DESTRUCTIVE operation. It requires --force to actually delete and
accepts the Confluence base URL + comma-separated page IDs on the CLI so the
script is not coupled to one hard-coded site/space.

Usage:
    CONFLUENCE_USER=you@example.com CONFLUENCE_TOKEN=xxx \\
        python3 delete_kb2_pages.py \\
            --base https://your-site.atlassian.net/wiki \\
            --ids-file pageids.txt \\
            [--skip 3735717,3735730] \\
            [--force]

Without --force the script performs a dry-run listing what would be deleted.
"""
import argparse
import os
import sys
import time

import requests
from requests.auth import HTTPBasicAuth


def parse_ids(raw: str):
    return [p for p in raw.replace(",", " ").split() if p.strip()]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", required=True, help="Confluence base URL, e.g. https://your-site.atlassian.net/wiki")
    p.add_argument("--ids-file", help="File containing whitespace-separated page IDs to delete")
    p.add_argument("--ids", help="Comma- or space-separated page IDs to delete (alternative to --ids-file)")
    p.add_argument("--skip", default="", help="Comma-separated page IDs to skip (e.g. space root, homepage)")
    p.add_argument("--force", action="store_true", help="Actually delete. Without this flag the script is a dry-run.")
    args = p.parse_args()

    user = os.environ.get("CONFLUENCE_USER")
    token = os.environ.get("CONFLUENCE_TOKEN")
    if not user or not token:
        sys.exit("CONFLUENCE_USER and CONFLUENCE_TOKEN must be set in the environment")

    ids_raw = ""
    if args.ids_file:
        with open(args.ids_file) as f:
            ids_raw = f.read()
    elif args.ids:
        ids_raw = args.ids
    else:
        sys.exit("Provide --ids-file or --ids")

    all_ids = parse_ids(ids_raw)
    skip = set(parse_ids(args.skip))
    ids_to_delete = [i for i in all_ids if i not in skip]

    mode = "DELETING" if args.force else "DRY-RUN"
    print(f"[{mode}] {len(ids_to_delete)} pages on {args.base} (skipping {len(skip)})")

    if not args.force:
        for pid in ids_to_delete:
            print(f"  would delete: {pid}")
        print("\nRe-run with --force to actually delete.")
        return

    auth = HTTPBasicAuth(user, token)
    deleted = skipped = errors = 0
    for pid in ids_to_delete:
        url = f"{args.base}/rest/api/content/{pid}?status=current"
        r = requests.delete(url, auth=auth)
        if r.status_code == 204:
            deleted += 1
            if deleted % 20 == 0:
                print(f"  deleted {deleted}/{len(ids_to_delete)}...")
        elif r.status_code == 404:
            skipped += 1  # already gone
        elif r.status_code == 429:
            print("  rate limited, sleeping 5s...")
            time.sleep(5)
            r2 = requests.delete(url, auth=auth)
            if r2.status_code == 204:
                deleted += 1
            else:
                print(f"  ERROR {pid}: {r2.status_code}")
                errors += 1
        else:
            print(f"  ERROR {pid}: {r.status_code} {r.text[:80]}")
            errors += 1
        time.sleep(0.1)

    print(f"\nDone: deleted={deleted} already_gone={skipped} errors={errors}")


if __name__ == "__main__":
    main()
