#!/usr/bin/env python3
"""
Small helper for the Infomaniak Newsletter API (stdlib only).

Used to prepare what the sign-up Worker expects:
  * the numeric domain id            ->  wrangler.toml IK_DOMAIN_ID
  * the subscriber fields            ->  firstname, lastname, affiliation,
                                         country, consent_at, consent_source
  * the groups                       ->  Community, WG1..WG3, Open Exchange Platform

Auth: export IK_TOKEN with a token that has the newsletter scope
(Infomaniak Manager -> profile -> API tokens, or the "API key" entry in the
Newsletter panel).

Examples
--------
    export IK_TOKEN=...                 # PowerShell:  $env:IK_TOKEN="..."
    python ik_newsletter.py domains
    python ik_newsletter.py fields 64876
    python ik_newsletter.py groups 64876
    python ik_newsletter.py ensure-groups 64876
    python ik_newsletter.py subscribers 64876 --limit 20
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.infomaniak.com"

WANTED_GROUPS = [
    "sig-wus community",
    "WG1 Standards & Regulatory Affairs",
    "WG2 Events & Education",
    "WG3 Industry & Clinical Translation",
    "Open Exchange Platform",
]

WANTED_FIELDS = ["firstname", "lastname", "affiliation", "country",
                 "consent_at", "consent_source"]


# --------------------------------------------------------------------- http --

def call(method: str, path: str, payload: dict | None = None) -> dict:
    token = os.environ.get("IK_TOKEN")
    if not token:
        sys.exit("IK_TOKEN is not set.")

    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        API + path,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read().decode())
    except urllib.error.HTTPError as err:
        detail = err.read().decode(errors="replace")
        sys.exit(f"HTTP {err.code} on {method} {path}\n{detail}")


def rows(result: dict) -> list:
    data = result.get("data", [])
    return data if isinstance(data, list) else [data]


# ------------------------------------------------------------------ commands --

def cmd_domains(_args) -> None:
    for d in rows(call("GET", "/1/newsletters")):
        print(f'{d.get("id"):>8}  {d.get("name") or d.get("domain") or ""}')


def cmd_fields(args) -> None:
    for f in rows(call("GET", f"/1/newsletters/{args.domain}/fields?per_page=200")):
        print(f'{f.get("id"):>8}  key={f.get("key"):<16} name={f.get("name")}')
    print("\nWorker sends:", ", ".join(WANTED_FIELDS))
    print("Any key listed above that does not match is simply ignored by the API,")
    print("so create the missing ones in Subscribers -> fields, or adapt the Worker.")


def cmd_groups(args) -> None:
    for g in rows(call("GET", f"/1/newsletters/{args.domain}/groups?per_page=200")):
        print(f'{g.get("id"):>8}  {g.get("name")}')


def cmd_ensure_groups(args) -> None:
    existing = {g.get("name") for g in rows(call("GET", f"/1/newsletters/{args.domain}/groups?per_page=200"))}
    for name in WANTED_GROUPS:
        if name in existing:
            print(f"ok      {name}")
            continue
        call("POST", f"/1/newsletters/{args.domain}/groups", {"name": name})
        print(f"created {name}")


def cmd_subscribers(args) -> None:
    query = urllib.parse.urlencode({"per_page": args.limit, "page": 1})
    for s in rows(call("GET", f"/1/newsletters/{args.domain}/subscribers?{query}")):
        print(f'{s.get("id"):>8}  {s.get("status"):<12} {s.get("email")}')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("domains", help="list newsletter domains and their ids").set_defaults(fn=cmd_domains)

    p = sub.add_parser("fields", help="list subscriber fields")
    p.add_argument("domain", type=int)
    p.set_defaults(fn=cmd_fields)

    p = sub.add_parser("groups", help="list groups")
    p.add_argument("domain", type=int)
    p.set_defaults(fn=cmd_groups)

    p = sub.add_parser("ensure-groups", help="create the SIG-WUS groups if missing")
    p.add_argument("domain", type=int)
    p.set_defaults(fn=cmd_ensure_groups)

    p = sub.add_parser("subscribers", help="list subscribers")
    p.add_argument("domain", type=int)
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(fn=cmd_subscribers)

    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
