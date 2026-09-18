from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from typing import Any


LAUNCHPAD_API = "https://api.launchpad.net/devel"
ARCHIVE = f"{LAUNCHPAD_API}/ubuntu/+archive/primary"


def publication_preference(item: dict[str, Any]) -> tuple[int, int, str]:
    pocket_rank = {"Release": 0, "Security": 1, "Updates": 2, "Proposed": 3, "Backports": 4}
    status_rank = {"Published": 0, "Superseded": 1, "Deleted": 2}
    return (pocket_rank.get(item.get("pocket", ""), 9), status_rank.get(item.get("status", ""), 9), item.get("date_published") or item.get("date_created") or "")


def launchpad_get(url: str, params: dict[str, str]) -> Any:
    full_url = url + "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(full_url, headers={"User-Agent": "agentic-dataset-deployed-builder/1.0"})
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            last_exc = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"Launchpad GET failed: {full_url}: {last_exc}")
