#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""The fixture's API client, relayed by test_skills_relay.sh: its token comes
from the relay's environment, a file from its home; "the API" is a public
bearer-token echo (API_URL: a stand-in behind `corporate` with CORPORATE=1). It
prints hashes of what it got, never the token."""
import argparse
import hashlib
import json
import os
import sys
import urllib.request

URL = os.environ.get("API_URL") or "https://httpbin.org/bearer"


def tag(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("whoami", "other", "home", "save"):
        sub.add_parser(name)
    sub.add_parser("fetch").add_argument("-o", required=True)
    args = ap.parse_args()
    token = os.environ.get("API_TOKEN", "")
    if args.cmd == "whoami":
        if token.startswith("expired"):
            print("401 invalid_auth: the token has expired", file=sys.stderr)
            return 1
        req = urllib.request.Request(URL, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.load(r)
        print(f"WHOAMI authenticated={body.get('authenticated')} token={tag(body.get('token', ''))} "
              f"mode={os.environ.get('API_MODE')}")
    elif args.cmd == "other":  # a host the relay does not name
        try:
            urllib.request.urlopen("https://example.com/", timeout=20)
            print("OTHER reached")
        except OSError as e:
            print(f"OTHER blocked ({e})")
    elif args.cmd == "home":
        path = os.path.expanduser("~/.config/demo/ws.json")
        with open(path) as f:
            ws = json.load(f)
        print(f"HOME ws={tag(ws['token'])} mode={oct(os.stat(path).st_mode & 0o777)}")
    elif args.cmd == "fetch":
        with open(args.o, "w") as f:
            f.write(f"FETCHED {tag(token)}\n")
        print(f"FETCH wrote {args.o}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
