from __future__ import annotations

import argparse
from pathlib import Path


def parse_args(script_dir: Path) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one codex exec per CVE and merge patch-presence JSON results."
    )
    parser.add_argument(
        "--project",
        help="Project name under --base-dir. Example: --project binutils uses binutils.json and binutils/.",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=script_dir,
        help="Directory containing <project>.json, testset.json, and <project>/.",
    )
    parser.add_argument(
        "--binaries-root",
        type=Path,
        default=Path.home() / "ClawSpace" / "binaries",
        help=(
            "Root for external binary collections. With --project binutils, "
            "the first default target-dir candidate is <root>/binutils_gcc."
        ),
    )
    parser.add_argument(
        "--opt",
        default="O0",
        help=(
            "Optimization suffix used in target filenames. Dataset testsets use "
            "canonical names without this suffix; target files are resolved as "
            "<binary>-<compiler>-<opt> when the canonical name is not present."
        ),
    )
    parser.add_argument(
        "--compiler",
        default="gcc",
        help=(
            "Compiler suffix used in target filenames. Dataset testsets use "
            "canonical names without this suffix; target files are resolved as "
            "<binary>-<compiler>-<opt> when the canonical name is not present."
        ),
    )
    parser.add_argument("--project-json", type=Path)
    parser.add_argument("--testset-json", type=Path)
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--groundtruth-json",
        type=Path,
        help="Groundtruth JSON used only by this wrapper after all codex exec runs finish. Never passed to codex.",
    )
    parser.add_argument(
        "--metrics-output",
        type=Path,
        help="Optional path for evaluation metrics JSON. Defaults to <output>.metrics.json.",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=None,
        help="Directory for prompts, stdout/stderr, and per-CVE outputs.",
    )
    parser.add_argument(
        "--prompt-template",
        type=Path,
        default=script_dir / "prompts" / "patch_presence.md",
        help="Prompt template file loaded for every CVE.",
    )
    parser.add_argument("--cve", action="append", help="Only run this CVE; repeatable.")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--binarywise",
        action="store_true",
        help="Run one codex exec per CVE/binary pair instead of one exec per CVE.",
    )
    parser.add_argument("--resume", action="store_true", help="Skip CVEs already in --output.")
    parser.add_argument(
        "--retry-errors",
        action="store_true",
        help="With --resume, rerun CVEs whose existing output contains at least one status=error.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Write prompts but do not call codex.")
    parser.add_argument("--codex-bin", default="codex")
    profile_group = parser.add_mutually_exclusive_group()
    profile_group.add_argument(
        "--model-profile",
        default=None,
        help=(
            "Profile name in straight_detect/model_config.json. Defaults to its "
            "active_profile; the config path is fixed and cannot be overridden."
        ),
    )
    profile_group.add_argument(
        "--provider",
        default=None,
        help=(
            "Deprecated profile alias loaded from model_config.json. "
            "Use --model-profile instead."
        ),
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default=None,
        help="Override Codex model reasoning effort for each codex exec run.",
    )
    parser.add_argument("--profile", default=None)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument(
        "--sandbox",
        default="workspace-write",
        choices=["read-only", "workspace-write", "danger-full-access"],
    )
    parser.add_argument(
        "--cd",
        type=Path,
        default=None,
        help="Working root passed to codex exec. With --project, defaults to the project directory; otherwise defaults to --target-dir.",
    )
    parser.add_argument(
        "--codex-json-events",
        action="store_true",
        help="Pass --json to codex exec. The final message is still read from --output-last-message.",
    )
    parser.add_argument(
        "--no-anonymize-targets",
        action="store_true",
        help="Expose original target filenames to codex exec instead of per-CVE anonymous temp copies.",
    )
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=1,
        help=(
            "Number of codex exec tasks to run concurrently. Default 1 (serial). "
            "Higher is faster but raises 429 rate-limit risk; lowering --jobs is the throttle."
        ),
    )
    return parser.parse_args()
