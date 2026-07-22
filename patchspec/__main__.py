"""Command-line entry point for standalone PatchSpec generation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from claudeagent.host import import_env_from_interactive_shell, load_env_files
from claudeagent.model_config import (
    apply_profile_to_args,
    interactive_env_keys,
    resolve_api_key,
    resolve_profile,
)

from .core import PatchSpecError, prepare_metadata
from .generator import PatchSpecModelConfig
from .storage import ensure_patch_spec


def _load_metadata(path: str, cve_id: str) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchSpecError(f"cannot load metadata JSON: {exc}") from exc
    if isinstance(raw, dict) and cve_id in raw and isinstance(raw[cve_id], dict):
        value = raw[cve_id]
    elif isinstance(raw, list):
        matches = [
            item for item in raw
            if isinstance(item, dict) and item.get("cve_id") == cve_id
        ]
        if len(matches) != 1:
            raise PatchSpecError(f"expected one metadata entry for {cve_id}, found {len(matches)}")
        value = matches[0]
    elif isinstance(raw, dict) and raw.get("cve_id") in {None, cve_id}:
        value = raw
    else:
        raise PatchSpecError(f"CVE not found in metadata JSON: {cve_id}")
    value = dict(value)
    # This repository's supported dataset is curl; match agent_loop/batch
    # normalization so a standalone artifact remains loadable by either path.
    value.setdefault("project", "curl")
    return prepare_metadata(value, cve_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compile CVE metadata into PatchSpec v1")
    parser.add_argument("--metadata-json", required=True)
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cache-dir", default="")
    parser.add_argument("--model-profile", default="")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="")
    parser.add_argument("--reasoning-effort", default="")
    parser.add_argument("--api-timeout", type=int, default=240)
    parser.add_argument("--api-max-retries", type=int, default=3)
    parser.add_argument("--api-turn-retries", type=int, default=1)
    parser.add_argument("--env-file", default="")
    parser.add_argument("--import-interactive-env", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        metadata = _load_metadata(args.metadata_json, args.cve_id)
        load_env_files(args.env_file)
        profile = resolve_profile(args)
        apply_profile_to_args(args, profile)
        if args.import_interactive_env and not args.dry_run:
            import_env_from_interactive_shell(interactive_env_keys(profile))
        api_key = "" if args.dry_run else resolve_api_key(profile)
        config = PatchSpecModelConfig.from_profile(
            profile,
            api_key=api_key,
            base_url=args.base_url,
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            timeout=args.api_timeout,
            max_retries=args.api_max_retries,
        )
        result = ensure_patch_spec(
            metadata,
            cve_id=args.cve_id,
            config=config,
            cache_dir=args.cache_dir or None,
            output_path=args.output,
            dry_run=args.dry_run,
        )
        print(json.dumps(result.as_dict(include_spec=args.dry_run), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (PatchSpecError, ValueError) as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, indent=2, sort_keys=True),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
