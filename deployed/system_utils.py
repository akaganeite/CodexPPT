"""Small filesystem, process, and download helpers shared by deployed stages."""

from __future__ import annotations

import hashlib
import http.client
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable


DownloadValidator = Callable[[Path], tuple[bool, str]]


class DownloadIntegrityError(Exception):
    """The server returned a file that failed deterministic integrity checks."""


def safe_token(value: str, default: str = "item") -> str:
    token = re.sub(r"[^A-Za-z0-9.+_-]+", "_", str(value)).strip("_")
    return token[:160] or default


def run_command(
    argv: list[str],
    *,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout,
        env=env,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_file(
    url: str,
    dest: Path,
    *,
    sha256: str = "",
    verify_sha256: bool = True,
    timeout: int = 300,
    attempts: int = 3,
    validator: DownloadValidator | None = None,
    bypass_proxy: bool = False,
) -> tuple[bool, str]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        valid = True
        if verify_sha256 and sha256:
            actual = sha256_file(dest)
            if actual.lower() != sha256.lower():
                valid = False
        if valid and validator:
            try:
                valid, _ = validator(dest)
            except Exception:
                valid = False
        if valid:
            message = "reused existing verified download" if verify_sha256 and sha256 else "reused existing download"
            return True, message
        dest.unlink(missing_ok=True)

    request = urllib.request.Request(url, headers={"User-Agent": "agentic-dataset-deployed-builder/1.0"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({})) if bypass_proxy else None
    temporary_path = dest.with_suffix(dest.suffix + ".tmp")
    deadline = time.monotonic() + max(1, timeout)
    last_error = "download failed"
    for attempt in range(1, max(1, attempts) + 1):
        temporary_path.unlink(missing_ok=True)
        remaining = max(1, int(deadline - time.monotonic()))
        try:
            response_context = opener.open(request, timeout=remaining) if opener else urllib.request.urlopen(
                request,
                timeout=remaining,
            )
            with response_context as response, temporary_path.open("wb") as file_handle:
                shutil.copyfileobj(response, file_handle)
                expected_length = response.headers.get("Content-Length") if hasattr(response, "headers") else None
            actual_size = temporary_path.stat().st_size
            if expected_length:
                try:
                    expected_size = int(expected_length)
                except (TypeError, ValueError):
                    expected_size = 0
                if expected_size > 0 and actual_size != expected_size:
                    raise DownloadIntegrityError(
                        f"content-length mismatch expected={expected_size} actual={actual_size}"
                    )
            if validator:
                valid, validation_message = validator(temporary_path)
                if not valid:
                    raise DownloadIntegrityError(validation_message or "download validation failed")
            if verify_sha256 and sha256:
                actual = sha256_file(temporary_path)
                if actual.lower() != sha256.lower():
                    last_error = f"sha256 mismatch expected={sha256} actual={actual}"
                    temporary_path.unlink(missing_ok=True)
                else:
                    os.replace(temporary_path, dest)
                    suffix = f" after {attempt} attempts" if attempt > 1 else ""
                    return True, f"downloaded{suffix}"
            else:
                os.replace(temporary_path, dest)
                suffix = f" after {attempt} attempts" if attempt > 1 else ""
                return True, f"downloaded{suffix}"
        except Exception as exc:
            temporary_path.unlink(missing_ok=True)
            last_error = str(exc)
            if not retryable_download_error(exc):
                return False, last_error
        if attempt >= max(1, attempts):
            break
        remaining_delay = deadline - time.monotonic()
        if remaining_delay <= 0:
            break
        time.sleep(min(1.5 * attempt, remaining_delay))
    return False, last_error


def retryable_download_error(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in {408, 425, 429, 500, 502, 503, 504}
    return isinstance(
        exc,
        (urllib.error.URLError, TimeoutError, ConnectionError, http.client.IncompleteRead, DownloadIntegrityError),
    )


def canonical_download_direct(url: str) -> bool:
    configured = os.environ.get("DEPLOYED_CANONICAL_DIRECT", "1").strip().lower()
    if configured in {"0", "false", "no", "off"}:
        return False
    hostname = (urllib.parse.urlsplit(url).hostname or "").lower()
    return hostname in {"ubuntu.com", "launchpad.net", "launchpadlibrarian.net"} or hostname.endswith(
        (".ubuntu.com", ".launchpad.net", ".launchpadlibrarian.net")
    )
