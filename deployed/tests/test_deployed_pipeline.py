from __future__ import annotations

import argparse
import io
import json
import subprocess
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from deployed.cli import build_parser
from deployed.command_run import (
    handle_run,
    prepare_ubuntu_jsons,
    resolve_requested_cves,
    run_source_fallbacks,
)
from deployed.config import DebugRules, ElfRules, NameRules, ProjectConfig, load_config
from deployed.candidate_discovery.metadata import CveMetadata, load_metadata, resolve_metadata_path
from deployed.candidate_discovery.source_history import SourcePublication
from deployed.candidate_discovery.ubuntu_groundtruth import build_ubuntu_groundtruth, normalize_series_filter
from deployed.candidate_discovery.ubuntu_tracker_fallback import parse_tracker_cve
from deployed.candidate_discovery.ubuntu_source_groundtruth import (
    build_source_groundtruth_for_cve,
    select_vulnerable_source_publications,
)
from deployed.models import ArtifactResult, PackagePair
from deployed.dataset_export.exporter import (
    build_base_testset,
    build_groundtruth,
    build_testset,
    prune_unreferenced_binaries,
)
from deployed.dataset_export.finalize import cleanup_work_caches, finalize_run_output, rebase_finalized_output
from deployed.dataset_export.validator import validate_dataset
from deployed.incremental import completed_cves, merge_build_snapshot
from deployed.io_utils import write_json
from deployed.naming import deployed_export_name, deployed_target_binary_name
from deployed.package_acquisition.artifacts import (
    artifact_dir_name,
    copy_exported_elf,
    copy_exported_pair,
    download_package_file,
    package_download_urls,
    restore_candidate_exports,
    ubuntu_snapshot_id,
)
from deployed.package_acquisition.deepseek_client import load_llm_config
from deployed.package_acquisition.elf_utils import disassembler_for_elf, elf_matches_architecture
from deployed.package_acquisition.package_hints import package_matches_component, source_component_hints
from deployed.package_acquisition.package_ranker import candidate_families, rank_selected_packages
from deployed.package_acquisition.selected_build import (
    labels_from_selections,
    load_selection_results,
    materialize_one,
    materialize_ranked_selections,
    pairs_for_family,
    requested_function_universe,
    version_attempts,
)
from deployed.system_utils import download_file
from deployed.testset_selection.ubuntu_3v3 import (
    expand_selection_result,
    evaluate_series,
    extend_unique_balanced_pairs,
    initial_review_candidate_ids,
    primary_balanced_pairs,
    refresh_selection_result,
    review_attempt_sources,
    selection_from_pairs,
)
from deployed.testset_selection.codex_source_review import (
    candidate_task,
    load_cached_source_review,
    render_prompt,
    review_cache_paths,
)
from deployed.testset_selection.architecture_rebind import rebind_reviewed_selections
from deployed.testset_selection.ubuntu_publication_artifacts import (
    directory_supports_symlinks,
    materialize_source_publication,
    normalize_arch,
    pair_runtime_debug_files,
    parse_binary_file,
    reuse_cached_source_file,
    source_snapshot_id,
)
from deployed.versions import debian_compare, upstream_version


class VersionTests(unittest.TestCase):
    def test_debian_compare_handles_ubuntu_revisions(self) -> None:
        self.assertLess(debian_compare("7.81.0-1ubuntu1", "7.81.0-1ubuntu1.20"), 0)
        self.assertEqual(upstream_version("2:7.81.0-1ubuntu1.20"), "7.81.0")


class UbuntuGroundtruthTests(unittest.TestCase):
    def test_released_security_status_becomes_patch(self) -> None:
        result = build_ubuntu_groundtruth(
            {
                "id": "CVE-2024-0001",
                "packages": [
                    {
                        "name": "demo",
                        "statuses": [
                            {
                                "release_codename": "noble",
                                "status": "released",
                                "description": "1.2-3ubuntu1",
                                "pocket": "security",
                            }
                        ],
                    }
                ],
            }
        )
        row = result["security_patch_groundtruth"][0]
        self.assertEqual(row["ubuntu_release"], "24.04")
        self.assertEqual(row["fixed_source_version"], "1.2-3ubuntu1")

    def test_non_security_and_not_affected_are_not_patch(self) -> None:
        result = build_ubuntu_groundtruth(
            {
                "id": "CVE-2024-0002",
                "packages": [
                    {
                        "name": "demo",
                        "statuses": [
                            {"release_codename": "jammy", "status": "not-affected", "pocket": "security"},
                            {"release_codename": "noble", "status": "released", "description": "1.1", "pocket": "updates"},
                        ],
                    }
                ],
            }
        )
        self.assertEqual(result["security_patch_groundtruth"], [])

    def test_esm_is_opt_in_and_numeric_series_filter_maps(self) -> None:
        payload = {
            "id": "CVE-2024-0003",
            "packages": [
                {
                    "name": "demo",
                    "statuses": [
                        {"release_codename": "noble", "status": "released", "description": "1.0", "pocket": "security"},
                        {"release_codename": "focal", "status": "released", "description": "0.9", "pocket": "esm-apps"},
                    ],
                }
            ],
        }
        normal = build_ubuntu_groundtruth(payload, series_filter=["2404"])
        esm = build_ubuntu_groundtruth(payload, include_esm=True, series_filter=["focal"])
        self.assertEqual([row["ubuntu_series"] for row in normal["security_patch_groundtruth"]], ["noble"])
        self.assertEqual(esm["security_patch_groundtruth"][0]["pocket"], "esm-apps")
        self.assertEqual(normalize_series_filter(["2404", "noble"], {"noble": "24.04"}), {"noble"})

    def test_historical_release_catalog_contains_tested_series(self) -> None:
        result = build_ubuntu_groundtruth(
            {
                "id": "CVE-2024-0004",
                "packages": [
                    {
                        "name": "demo",
                        "statuses": [
                            {"release_codename": "trusty", "status": "released", "description": "1.0", "pocket": "security"},
                            {"release_codename": "resolute", "status": "released", "description": "2.0", "pocket": "security"},
                        ],
                    }
                ],
            }
        )
        releases = {row["ubuntu_series"]: row["ubuntu_release"] for row in result["security_patch_groundtruth"]}
        self.assertEqual(releases, {"trusty": "14.04", "resolute": "26.04"})

    def test_tracker_fallback_recreates_release_status_payload(self) -> None:
        payload = parse_tracker_cve(
            """Candidate: CVE-2024-0001
Description:
 demo vulnerability
Notes:
 analyst> reviewed
Patches_demo:
 upstream: https://example/fix
upstream_demo: released (2.0)
focal_demo: released (1.0-1ubuntu0.1)
esm-infra/bionic_demo: released (0.9-1ubuntu0.1+esm1)
jammy_demo: not-affected (code not present)
""",
            source_url="https://git.launchpad.test/CVE-2024-0001",
            bucket="retired",
        )
        result = build_ubuntu_groundtruth(payload)
        patch = result["security_patch_groundtruth"][0]
        self.assertEqual(payload["id"], "CVE-2024-0001")
        self.assertEqual(patch["ubuntu_series"], "focal")
        self.assertEqual(patch["fixed_source_version"], "1.0-1ubuntu0.1")
        bionic = next(
            row for row in result["release_status"] if row["ubuntu_series"] == "bionic"
        )
        self.assertEqual(bionic["pocket"], "esm-infra")


class SourceGroundtruthTests(unittest.TestCase):
    def test_nearest_versions_exclude_proposed(self) -> None:
        history = [
            SourcePublication("demo", "1.0-1", "focal", "Release", "main", "Published", "release", "", ""),
            SourcePublication("demo", "1.0-2", "focal", "Updates", "main", "Superseded", "updates", "", ""),
            SourcePublication("demo", "1.0-3", "focal", "Proposed", "main", "Published", "proposed", "", ""),
            SourcePublication("demo", "1.0-4", "focal", "Security", "main", "Superseded", "security", "", ""),
            SourcePublication("demo", "1.0-5", "focal", "Security", "main", "Published", "fixed", "", ""),
        ]
        selected = select_vulnerable_source_publications(history, "1.0-5", max_count=3)
        self.assertEqual([item.source_version for item in selected], ["1.0-4", "1.0-2", "1.0-1"])

    def test_source_groundtruth_attaches_exact_publication(self) -> None:
        def fake_loader(source_package, series, *, cache_path, refresh, log):
            return {
                "focal": [
                    SourcePublication(source_package, "1.0-1", "focal", "Updates", "main", "Superseded", "old", "", ""),
                    SourcePublication(source_package, "1.0-2", "focal", "Security", "main", "Published", "fixed", "", ""),
                ]
            }

        with tempfile.TemporaryDirectory() as directory:
            result = build_source_groundtruth_for_cve(
                {
                    "id": "CVE-2024-0005",
                    "packages": [
                        {
                            "name": "demo",
                            "statuses": [
                                {"release_codename": "focal", "status": "released", "description": "1.0-2", "pocket": "security"}
                            ],
                        }
                    ],
                },
                source_path=None,
                state_dir=Path(directory),
                source_history_loader=fake_loader,
            )
        self.assertEqual(result["rows"][0]["source_groundtruth_status"], "verified")


class SelectionTests(unittest.TestCase):
    def test_artifact_directory_is_architecture_isolated(self) -> None:
        common = {
            "cve_id": "CVE-2024-1000",
            "label": "vuln",
            "source_package": "demo",
            "source_version": "1.0",
            "series": "noble",
            "pocket": "Security",
            "component": "main",
            "runtime_package": "demo",
            "runtime_version": "1.0",
        }
        amd64 = PackagePair(**common, architecture="amd64")
        arm64 = PackagePair(**common, architecture="arm64")

        self.assertNotEqual(artifact_dir_name(amd64), artifact_dir_name(arm64))
        self.assertIn("amd64", artifact_dir_name(amd64))
        self.assertIn("arm64", artifact_dir_name(arm64))

    def test_architecture_rebind_reuses_source_labels_and_selects_one_pair(self) -> None:
        source = balanced_selection(2)
        source["package_ranking"] = {"arch": "amd64"}
        candidate_rows = []
        for pair in source["candidate_pool"]["pairs"]:
            for side, item in (("vuln", pair["vulnerable"]), ("patch", pair["patch"])):
                publication = source_publication(
                    item["source_version"],
                    "2024-01-01T00:00:00+00:00",
                ).to_json()
                publication["series"] = item["series"]
                publication["pocket"] = item["pocket"]
                item.update(
                    {
                        "candidate_id": f"{side}-{item['series']}-{item['source_version']}",
                        "side": side,
                        "source_publication": publication,
                    }
                )
                candidate_rows.append(item)
        source["series_attempts"] = [
            {
                "series": "focal",
                "ubuntu_release": "20.04",
                "fixed_source_version": "p1",
                "candidate_matrix": candidate_rows,
            }
        ]
        for attempt in source["series_attempts"]:
            for item in attempt["candidate_matrix"]:
                item["source_validation"] = {
                    "classified_label": item["side"],
                    "functions_available": True,
                    "function_mappings": [
                        {
                            "canonical_function": "decode_item",
                            "candidate_function": "decode_item",
                            "relationship": "exact",
                        }
                    ],
                }

        def availability(publication, *, arch, cache_dir, refresh):
            del cache_dir, refresh
            package = f"libdemo-{publication.source_version}"
            return {
                "ready": True,
                "arch": arch,
                "runtime_debug_pairs": [
                    {
                        "match": "exact_package_name",
                        "runtime": {
                            "package": package,
                            "version": publication.source_version,
                            "arch": arch,
                            "filename": f"{package}_{publication.source_version}_{arch}.deb",
                            "url": f"https://example.test/{package}_{arch}.deb",
                        },
                        "debug": {
                            "package": f"{package}-dbgsym",
                            "version": publication.source_version,
                            "arch": arch,
                            "filename": f"{package}-dbgsym_{publication.source_version}_{arch}.ddeb",
                            "url": f"https://example.test/{package}-dbgsym_{arch}.ddeb",
                        },
                    }
                ],
            }

        with tempfile.TemporaryDirectory() as directory, patch(
            "deployed.testset_selection.architecture_rebind.publication_binary_availability",
            side_effect=availability,
        ) as availability_call:
            selected, excluded = rebind_reviewed_selections(
                [source],
                arch="arm64",
                cache_dir=Path(directory),
                max_per_label=1,
            )
        self.assertFalse(excluded)
        self.assertEqual(availability_call.call_count, 2)
        result = selected[0]
        self.assertNotIn("package_ranking", result)
        self.assertEqual(result["arch"], "arm64")
        self.assertEqual(result["selected"]["count_per_label"], 1)
        rows = [*result["selected"]["vulnerable"], *result["selected"]["patch"]]
        self.assertTrue(all(row["binary_availability"]["arch"] == "arm64" for row in rows))
        self.assertTrue(
            all(
                pair["runtime"]["url"].endswith("_arm64.deb")
                for row in rows
                for pair in row["binary_availability"]["runtime_debug_pairs"]
            )
        )
        self.assertEqual(
            rows[0]["source_validation"]["function_mappings"][0]["relationship"],
            "exact",
        )

    def test_selected_candidate_exports_are_restored_after_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "extract" / "libssl.so.3"
            debug = root / "extract" / "libssl.so.3.debug"
            stripped = root / "target" / "libssl.so.3"
            exported_debug = root / "debug" / "libssl.so.3.debug"
            runtime.parent.mkdir(parents=True)
            runtime.write_bytes(b"runtime")
            debug.write_bytes(b"debug")
            restore_candidate_exports(
                {
                    "runtime_elf": str(runtime),
                    "debug_file": str(debug),
                    "stripped_path": str(stripped),
                    "exported_debug_path": str(exported_debug),
                }
            )
            self.assertEqual(stripped.read_bytes(), b"runtime")
            self.assertEqual(exported_debug.read_bytes(), b"debug")

    def test_export_name_collision_does_not_overwrite_existing_elf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "destination"
            source.write_bytes(b"new")
            destination.write_bytes(b"existing")
            with patch("deployed.package_acquisition.artifacts.read_build_id", return_value="other"):
                with self.assertRaisesRegex(ValueError, "name collision"):
                    copy_exported_elf(source, destination, "expected")
            self.assertEqual(destination.read_bytes(), b"existing")

    def test_export_pair_collision_rejects_candidate_without_partial_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime_source = root / "runtime.so"
            debug_source = root / "runtime.so.debug"
            runtime_destination = root / "target" / "runtime.so"
            debug_destination = root / "debug" / "runtime.so.debug"
            runtime_source.write_bytes(b"new runtime")
            debug_source.write_bytes(b"new debug")
            runtime_destination.parent.mkdir()
            runtime_destination.write_bytes(b"existing runtime")
            with patch("deployed.package_acquisition.artifacts.read_build_id", return_value="other"):
                ok, message = copy_exported_pair(
                    runtime_source,
                    runtime_destination,
                    debug_source,
                    debug_destination,
                    "expected",
                )
            self.assertFalse(ok)
            self.assertIn("name collision", message)
            self.assertEqual(runtime_destination.read_bytes(), b"existing runtime")
            self.assertFalse(debug_destination.exists())

    def test_download_retries_transient_launchpad_error(self) -> None:
        transient = urllib.error.HTTPError("https://launchpad.test/pkg.deb", 503, "unavailable", {}, None)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "pkg.deb"
            with (
                patch("deployed.system_utils.urllib.request.urlopen", side_effect=[transient, io.BytesIO(b"deb")]),
                patch("deployed.system_utils.time.sleep"),
            ):
                ok, message = download_file(
                    "https://launchpad.test/pkg.deb",
                    destination,
                    verify_sha256=False,
                    timeout=30,
                )
            self.assertTrue(ok)
            self.assertEqual(message, "downloaded after 2 attempts")
            self.assertEqual(destination.read_bytes(), b"deb")

    def test_download_retries_short_content_length_response(self) -> None:
        class Response(io.BytesIO):
            def __init__(self, content: bytes, expected_length: int):
                super().__init__(content)
                self.headers = {"Content-Length": str(expected_length)}

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "pkg.deb"
            with (
                patch(
                    "deployed.system_utils.urllib.request.urlopen",
                    side_effect=[Response(b"partial", 8), Response(b"complete", 8)],
                ),
                patch("deployed.system_utils.time.sleep"),
            ):
                ok, message = download_file(
                    "https://launchpad.test/pkg.deb",
                    destination,
                    verify_sha256=False,
                    timeout=30,
                )
            self.assertTrue(ok)
            self.assertEqual(message, "downloaded after 2 attempts")
            self.assertEqual(destination.read_bytes(), b"complete")

    def test_download_replaces_invalid_existing_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "pkg.deb"
            destination.write_bytes(b"partial")

            def validator(path: Path) -> tuple[bool, str]:
                return path.read_bytes() == b"complete", "truncated package"

            with patch("deployed.system_utils.urllib.request.urlopen", return_value=io.BytesIO(b"complete")):
                ok, message = download_file(
                    "https://launchpad.test/pkg.deb",
                    destination,
                    verify_sha256=False,
                    validator=validator,
                )
            self.assertTrue(ok)
            self.assertEqual(message, "downloaded")
            self.assertEqual(destination.read_bytes(), b"complete")

    def test_package_download_urls_prefer_ubuntu_pool_mirrors(self) -> None:
        pair = PackagePair(
            cve_id="CVE-2024-0001",
            label="patch",
            source_package="ffmpeg",
            source_version="7:4.2.7-0ubuntu0.1",
            series="focal",
            pocket="Security",
            component="universe",
            publication_date="2024-03-27T11:54:44+00:00",
            runtime_url="https://launchpad.test/libavcodec58.deb",
            runtime_filename="libavcodec58_4.2.7-0ubuntu0.1_amd64.deb",
            debug_url="https://launchpad.test/libavcodec58-dbgsym.ddeb",
            debug_filename="libavcodec58-dbgsym_4.2.7-0ubuntu0.1_amd64.ddeb",
        )
        self.assertEqual(
            package_download_urls(pair, debug=False)[0],
            "https://archive.ubuntu.com/ubuntu/pool/universe/f/ffmpeg/libavcodec58_4.2.7-0ubuntu0.1_amd64.deb",
        )
        self.assertEqual(
            package_download_urls(pair, debug=True)[0],
            "https://ddebs.ubuntu.com/pool/universe/f/ffmpeg/libavcodec58-dbgsym_4.2.7-0ubuntu0.1_amd64.ddeb",
        )
        self.assertIn(
            "https://snapshot.ubuntu.com/ubuntu/20240328T115444Z/"
            "pool/universe/f/ffmpeg/libavcodec58_4.2.7-0ubuntu0.1_amd64.deb",
            package_download_urls(pair, debug=False),
        )
        self.assertIn(
            "https://snapshot.ubuntu.com/ubuntu/20240328T115444Z/"
            "pool/universe/f/ffmpeg/libavcodec58-dbgsym_4.2.7-0ubuntu0.1_amd64.ddeb",
            package_download_urls(pair, debug=True),
        )

    def test_snapshot_id_uses_day_after_publication(self) -> None:
        self.assertEqual(ubuntu_snapshot_id("2024-03-27T23:30:00-05:00"), "20240329T043000Z")
        self.assertEqual(ubuntu_snapshot_id("not-a-date"), "")

    def test_elf_architecture_validation_rejects_wrong_machine(self) -> None:
        path = Path("/tmp/not-read-by-mock")
        with patch("deployed.package_acquisition.elf_utils.read_elf_machine", return_value="AArch64"):
            self.assertEqual(elf_matches_architecture(path, "arm64"), (True, "AArch64"))
            self.assertEqual(elf_matches_architecture(path, "amd64"), (False, "AArch64"))

    def test_aarch64_elf_uses_cross_disassembler(self) -> None:
        path = Path("/tmp/not-read-by-mock")
        with (
            patch("deployed.package_acquisition.elf_utils.read_elf_machine", return_value="AArch64"),
            patch("deployed.package_acquisition.elf_utils.shutil.which", return_value="/usr/bin/aarch64-linux-gnu-objdump"),
        ):
            self.assertEqual(disassembler_for_elf(path), "aarch64-linux-gnu-objdump")

    def test_cross_disassembly_fails_closed_when_tool_is_missing(self) -> None:
        path = Path("/tmp/not-read-by-mock")
        with (
            patch("deployed.package_acquisition.elf_utils.read_elf_machine", return_value="AArch64"),
            patch("deployed.package_acquisition.elf_utils.shutil.which", return_value=None),
        ):
            self.assertEqual(disassembler_for_elf(path), "")

    def test_package_mirror_probe_uses_short_timeout_before_original_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "pkg.deb"
            with patch(
                "deployed.package_acquisition.artifacts.download_file",
                side_effect=[(False, "mirror unavailable"), (True, "downloaded")],
            ) as download:
                ok, message = download_package_file(
                    ["https://mirror.test/pkg.deb", "https://launchpad.test/pkg.deb"],
                    destination,
                    sha256="",
                    verify_sha256=False,
                    timeout=300,
                )
        self.assertTrue(ok)
        self.assertEqual(message, "downloaded")
        self.assertEqual(download.call_args_list[0].kwargs["timeout"], 20)
        self.assertEqual(download.call_args_list[0].kwargs["attempts"], 1)
        self.assertEqual(download.call_args_list[1].kwargs["timeout"], 300)
        self.assertEqual(download.call_args_list[1].kwargs["attempts"], 2)

    def test_launchpad_package_download_bypasses_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "pkg.deb"
            with patch(
                "deployed.package_acquisition.artifacts.download_file",
                return_value=(True, "downloaded"),
            ) as download:
                ok, _ = download_package_file(
                    ["https://launchpad.net/ubuntu/+archive/primary/+files/pkg.deb"],
                    destination,
                    sha256="",
                    verify_sha256=False,
                    timeout=300,
                )
        self.assertTrue(ok)
        self.assertTrue(download.call_args.kwargs["bypass_proxy"])

    def test_x86_alias_and_runtime_debug_pairing(self) -> None:
        runtime = parse_binary_file("https://example/pkg_1.0_amd64.deb")
        debug = parse_binary_file("https://example/pkg-dbgsym_1.0_amd64.ddeb")
        self.assertEqual(normalize_arch("x86"), "amd64")
        self.assertEqual(pair_runtime_debug_files([runtime], [debug])[0]["runtime"]["package"], "pkg")

    def test_source_wide_debug_package_is_kept_as_fallback(self) -> None:
        runtime = parse_binary_file("https://example/libcodec1_1.0_amd64.deb")
        debug = parse_binary_file("https://example/demo-dbg_1.0_amd64.deb")
        pair = pair_runtime_debug_files([runtime], [debug])[0]
        self.assertEqual(pair["match"], "source_debug_fallback")

    def test_source_files_are_reused_across_ubuntu_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory)
            cached = cache_dir / "openssl" / "3.5.5-1ubuntu1" / "source-files" / "openssl_3.5.5.orig.tar.gz"
            cached.parent.mkdir(parents=True)
            cached.write_bytes(b"shared upstream source")
            destination = cache_dir / "openssl" / "3.5.5-1ubuntu3" / "source-files" / cached.name
            reused = reuse_cached_source_file(cache_dir, "openssl", cached.name, destination)
            self.assertEqual(reused, cached)
            self.assertEqual(destination.read_bytes(), b"shared upstream source")

    def test_corrupt_source_cache_is_redownloaded_after_extraction_failure(self) -> None:
        publication = SourcePublication(
            "openssl",
            "3.5.0-2ubuntu1",
            "questing",
            "Release",
            "main",
            "Superseded",
            "https://api.launchpad.test/source/1",
            "",
            "",
        )
        urls = [
            "https://launchpad.test/openssl_3.5.0-2ubuntu1.dsc",
            "https://launchpad.test/openssl_3.5.0.orig.tar.gz",
        ]
        with tempfile.TemporaryDirectory() as directory:
            cache_dir = Path(directory)
            source_files = cache_dir / "openssl" / "3.5.0-2ubuntu1" / "source-files"
            source_files.mkdir(parents=True)
            for url in urls:
                (source_files / Path(url).name).write_bytes(b"partial")
            extraction_calls = 0

            def fake_download(url, destination, **kwargs):
                existed = destination.exists()
                if not existed:
                    destination.write_bytes(b"complete")
                return True, "reused existing download" if existed else "downloaded"

            def fake_run(argv, *, timeout):
                nonlocal extraction_calls
                extraction_calls += 1
                if extraction_calls == 1:
                    return subprocess.CompletedProcess(argv, 2, "", "size mismatch")
                Path(argv[-1]).mkdir(parents=True)
                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                patch("deployed.testset_selection.ubuntu_publication_artifacts.launchpad_get", return_value=urls),
                patch("deployed.testset_selection.ubuntu_publication_artifacts.download_file", side_effect=fake_download),
                patch("deployed.testset_selection.ubuntu_publication_artifacts.run_command", side_effect=fake_run),
            ):
                report = materialize_source_publication(publication, cache_dir=cache_dir, refresh=False)

        self.assertEqual(report["status"], "ok")
        self.assertEqual(extraction_calls, 2)

    def test_source_materialization_uses_local_workspace_without_symlinks(self) -> None:
        publication = SourcePublication(
            "ffmpeg",
            "7:4.2.4-1ubuntu0.1",
            "focal",
            "Security",
            "universe",
            "Published",
            "https://launchpad.test/sourcepub/1",
            "2020-07-22T00:00:00+00:00",
            "2020-07-22T00:00:00+00:00",
        )
        urls = [
            "https://launchpad.test/ffmpeg_4.2.4-1ubuntu0.1.dsc",
            "https://launchpad.test/ffmpeg_4.2.4.orig.tar.xz",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache_dir = root / "external-cache"
            work_dir = root / "local-work"

            def fake_download(url, destination, **kwargs):
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"source")
                return True, "downloaded"

            def fake_run(argv, *, timeout):
                extracted = Path(argv[-1])
                self.assertTrue(extracted.is_relative_to(work_dir))
                extracted.mkdir(parents=True)
                return subprocess.CompletedProcess(argv, 0, "", "")

            with (
                patch.dict("os.environ", {"DEPLOYED_SOURCE_WORKDIR": str(work_dir)}),
                patch("deployed.testset_selection.ubuntu_publication_artifacts.launchpad_get", return_value=urls),
                patch("deployed.testset_selection.ubuntu_publication_artifacts.download_file", side_effect=fake_download),
                patch(
                    "deployed.testset_selection.ubuntu_publication_artifacts.directory_supports_symlinks",
                    return_value=False,
                ),
                patch("deployed.testset_selection.ubuntu_publication_artifacts.run_command", side_effect=fake_run),
            ):
                report = materialize_source_publication(publication, cache_dir=cache_dir, refresh=False)

        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["extraction_storage"], "local_symlink_workspace")

    def test_source_materialization_uses_snapshot_before_launchpad_fallback(self) -> None:
        publication = SourcePublication(
            "sqlite3",
            "3.8.2-1ubuntu2.1",
            "trusty",
            "Security",
            "main",
            "Superseded",
            "https://api.launchpad.test/sourcepub/1",
            "2015-07-30T16:43:41+00:00",
            "2015-07-30T16:39:06+00:00",
        )
        original_url = (
            "https://launchpad.test/sourcefiles/sqlite3/3.8.2-1ubuntu2.1/"
            "sqlite3_3.8.2-1ubuntu2.1.dsc"
        )
        calls = []

        def fake_download(url, destination, **kwargs):
            calls.append(url)
            if "snapshot.ubuntu.com" not in url:
                return False, "not found"
            destination.write_bytes(b"source descriptor")
            return True, "downloaded"

        def fake_run(argv, *, timeout):
            Path(argv[-1]).mkdir(parents=True)
            return subprocess.CompletedProcess(argv, 0, "", "")

        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "deployed.testset_selection.ubuntu_publication_artifacts.launchpad_get",
                return_value=[original_url],
            ),
            patch(
                "deployed.testset_selection.ubuntu_publication_artifacts.download_file",
                side_effect=fake_download,
            ),
            patch(
                "deployed.testset_selection.ubuntu_publication_artifacts.run_command",
                side_effect=fake_run,
            ),
        ):
            report = materialize_source_publication(
                publication,
                cache_dir=Path(directory),
                refresh=False,
            )

        self.assertEqual(report["status"], "ok")
        self.assertIn("snapshot.ubuntu.com/ubuntu/20150731T164341Z", calls[-1])
        self.assertNotIn(original_url, calls)
        self.assertIn("snapshot.ubuntu.com", report["downloaded"][0]["download_url"])

    def test_source_snapshot_id_uses_day_after_publication(self) -> None:
        self.assertEqual(source_snapshot_id("2015-07-30T16:43:41+00:00"), "20150731T164341Z")
        self.assertEqual(source_snapshot_id("not-a-date"), "")

    def test_directory_symlink_probe_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertTrue(directory_supports_symlinks(root))
            self.assertEqual(list(root.iterdir()), [])

    def test_cleanup_removes_entire_local_source_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            workspace_base = root / "source-work"
            workspace = workspace_base / "scope" / "demo" / "1.0"
            extracted = workspace / "extracted"
            extracted.mkdir(parents=True)
            (workspace / "demo.orig.tar.xz").write_bytes(b"archive")
            report = output / "deployed" / "selection" / "sources" / "demo" / "1.0" / "source_materialization.json"
            report.parent.mkdir(parents=True)
            report.write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "extraction_storage": "local_symlink_workspace",
                        "extracted_path": str(extracted),
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict("os.environ", {"DEPLOYED_SOURCE_WORKDIR": str(workspace_base)}):
                removed = cleanup_work_caches(output)

            self.assertFalse(workspace.exists())
            self.assertIn(str(workspace), removed)

    def test_balanced_selection_accepts_two_pairs(self) -> None:
        selected = selection_from_pairs(
            [balanced_pair("v1", "p1", "focal"), balanced_pair("v2", "p2", "focal")]
        )
        self.assertEqual(selected["count_per_label"], 2)
        self.assertEqual(len(selected["vulnerable"]), 2)
        self.assertEqual(len(selected["patch"]), 2)

    def test_missing_exact_fixed_publication_uses_notice_anchor(self) -> None:
        history = [
            source_publication("1.0", "2022-06-01T00:00:00+00:00"),
            source_publication("2.1", "2022-06-10T00:00:00+00:00"),
        ]
        payload = {
            "notices": [{"id": "USN-1", "published": "2022-06-08T12:00:00"}],
        }
        patch_row = {
            "ubuntu_series": "focal",
            "ubuntu_release": "20.04",
            "fixed_source_version": "2.0",
            "pocket": "security",
            "notice_ids": ["USN-1"],
        }
        with tempfile.TemporaryDirectory() as directory, patch(
            "deployed.testset_selection.ubuntu_3v3.publication_binary_availability",
            return_value={"ready": True, "runtime_debug_pairs": []},
        ):
            attempt = evaluate_series(
                patch_row,
                history,
                ranking_metadata(),
                payload=payload,
                output=Path(directory),
                arch="amd64",
                include_esm=False,
                max_candidates_per_side=8,
                deadline=0,
                source_download_timeout=90,
                refresh=False,
                log=None,
            )
        self.assertEqual(attempt["status"], "prechecked")
        self.assertIsNone(attempt["fixed_source_publication"])
        self.assertEqual(attempt["fixed_time_anchor"]["source"], "ubuntu_security_notice")
        self.assertEqual(attempt["review_pair_capacity_upper_bound"], 1)

    def test_cross_series_supplement_uses_distinct_versions(self) -> None:
        pairs = [balanced_pair("v1", "p1", "resolute")]
        attempt = {
            "series": "questing",
            "ubuntu_release": "25.10",
            "fixed_source_version": "p2",
            "eligible_vulnerable": [candidate("v1", -1), candidate("v2", -2), candidate("v3", -3)],
            "eligible_patch": [candidate("p2", 0), candidate("p3", 1)],
        }
        extend_unique_balanced_pairs(pairs, attempt, series_rank=1)
        selected = primary_balanced_pairs(pairs)
        vulnerable = [item["vulnerable"]["source_version"] for item in selected]
        patched = [item["patch"]["source_version"] for item in selected]
        self.assertEqual(vulnerable, ["v1", "v2"])
        self.assertEqual(patched, ["p1", "p2"])
        self.assertTrue(set(vulnerable).isdisjoint(patched))

    def test_primary_balanced_pairs_honors_one_per_label_limit(self) -> None:
        pairs = [
            balanced_pair("v1", "p1", "resolute"),
            balanced_pair("v2", "p2", "resolute"),
            balanced_pair("v3", "p3", "resolute"),
        ]
        selected = primary_balanced_pairs(pairs, max_per_label=1)
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["vulnerable"]["source_version"], "v1")
        self.assertEqual(selected[0]["patch"]["source_version"], "p1")

    def test_initial_review_spans_near_mid_and_far_versions(self) -> None:
        history = [
            source_publication(f"1.{index}", f"2022-01-{index + 4:02d}T00:00:00+00:00")
            for index in range(6)
        ] + [
            source_publication(f"2.{index}", f"2022-01-{index + 10:02d}T00:00:00+00:00")
            for index in range(6)
        ]
        patch_row = {
            "ubuntu_series": "focal",
            "ubuntu_release": "20.04",
            "fixed_source_version": "2.0",
            "pocket": "security",
            "notice_ids": [],
        }
        with tempfile.TemporaryDirectory() as directory, patch(
            "deployed.testset_selection.ubuntu_3v3.publication_binary_availability",
            return_value={"ready": True, "runtime_debug_pairs": []},
        ):
            attempt = evaluate_series(
                patch_row,
                history,
                ranking_metadata(),
                payload={},
                output=Path(directory),
                arch="amd64",
                include_esm=False,
                max_candidates_per_side=3,
                deadline=0,
                source_download_timeout=90,
                refresh=False,
                log=None,
            )
        selected_ids = initial_review_candidate_ids(attempt, 3)
        selected = [item for item in attempt["candidate_matrix"] if item["candidate_id"] in selected_ids]
        by_side = {
            side: {item["sampling_stratum"] for item in selected if item["side"] == side}
            for side in ("vuln", "patch")
        }
        self.assertEqual(by_side, {"vuln": {"near", "mid", "far"}, "patch": {"near", "mid", "far"}})

    def test_source_fallback_reviews_only_new_candidates_in_failed_stratum(self) -> None:
        initial = source_review_candidates((("vuln", "v-near"), ("patch", "p-near")))
        reserve = source_review_candidates(
            (("vuln", "v-mid"), ("patch", "p-mid"), ("vuln", "v-far"), ("patch", "p-far"))
        )
        for item in initial:
            item.update(
                {
                    "review_attempted": True,
                    "eligible": True,
                    "days_from_fix": -1 if item["side"] == "vuln" else 1,
                    "sampling_stratum": "near",
                    "sampling_position": 0.0,
                    "source_validation": {"classified_label": item["side"], "functions_available": True},
                }
            )
        for item in reserve:
            stratum = "mid" if "mid" in item["source_version"] else "far"
            item.update(
                {
                    "review_attempted": False,
                    "days_from_fix": -10 if item["side"] == "vuln" else 10,
                    "sampling_stratum": stratum,
                    "sampling_position": 0.5 if stratum == "mid" else 1.0,
                }
            )
        attempt = {
            "series": "focal",
            "ubuntu_release": "20.04",
            "fixed_source_version": "p-near",
            "status": "candidates_ready",
            "candidate_matrix": [*initial, *reserve],
            "eligible_vulnerable": [initial[0]],
            "eligible_patch": [initial[1]],
        }
        result = {"cve_id": "CVE-2024-1000", "series_attempts": [attempt], "candidate_pool": {}}
        refresh_selection_result(result)

        def review(metadata, candidates, **kwargs):
            del metadata, kwargs
            return source_review_result(candidates)

        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "deployed.testset_selection.ubuntu_3v3.materialize_source_publication",
                return_value={"status": "ok", "extracted_path": directory},
            ),
            patch("deployed.testset_selection.ubuntu_3v3.load_cached_source_review", return_value=None),
            patch("deployed.testset_selection.ubuntu_3v3.review_source_candidates", side_effect=review),
        ):
            expansion = expand_selection_result(
                result,
                ranking_metadata(),
                output=Path(directory),
                preferred_strata=["far"],
                max_selection_minutes=0,
            )
        self.assertEqual(set(expansion["reviewed_candidate_ids"]), {"vuln-v-far", "patch-p-far"})
        self.assertEqual(expansion["new_pair_count"], 1)
        self.assertEqual(result["candidate_pool"]["pair_count"], 2)
        self.assertFalse(any(item["review_attempted"] for item in reserve if "mid" in item["source_version"]))

    def test_codex_source_review_assigns_labels_independent_of_version_bucket(self) -> None:
        candidates = source_review_candidates(
            (("vuln", "1.0"), ("patch", "1.1")),
            pocket="Release",
        )
        attempt = {"series": "focal", "status": "prechecked", "candidate_matrix": candidates}
        review = source_review_result(candidates, swap_labels=True)
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "deployed.testset_selection.ubuntu_3v3.materialize_source_publication",
                return_value={"status": "ok", "extracted_path": directory},
            ),
            patch("deployed.testset_selection.ubuntu_3v3.review_source_candidates", return_value=review) as codex,
        ):
            review_attempt_sources(
                attempt,
                ranking_metadata(),
                candidate_ids={item["candidate_id"] for item in candidates},
                output=Path(directory),
                deadline=0,
                source_download_timeout=30,
                refresh=False,
                log=None,
            )
        self.assertEqual(codex.call_args.kwargs["timeout"], 300)
        self.assertEqual(len(attempt["eligible_vulnerable"]), 1)
        self.assertEqual(len(attempt["eligible_patch"]), 1)
        self.assertEqual(attempt["eligible_vulnerable"][0]["source_version"], "1.1")
        self.assertEqual(attempt["eligible_patch"][0]["source_version"], "1.0")
        self.assertEqual(attempt["candidate_matrix"][0]["temporal_side"], "vuln")
        self.assertEqual(attempt["candidate_matrix"][0]["source_validation"]["reviewer"], "codex_exec")

    def test_cached_codex_review_skips_source_materialization(self) -> None:
        candidates = source_review_candidates((("vuln", "1.0"), ("patch", "2.0")))
        review = source_review_result(candidates)
        attempt = {"series": "focal", "status": "prechecked", "candidate_matrix": candidates}
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "deployed.testset_selection.ubuntu_3v3.load_cached_source_review",
                return_value=review,
            ),
            patch(
                "deployed.testset_selection.ubuntu_3v3.materialize_source_publication"
            ) as materialize,
            patch("deployed.testset_selection.ubuntu_3v3.review_source_candidates") as codex,
        ):
            review_attempt_sources(
                attempt,
                ranking_metadata(),
                output=Path(directory),
                deadline=0,
                source_download_timeout=90,
                refresh=False,
                log=None,
            )
        materialize.assert_not_called()
        codex.assert_not_called()
        self.assertEqual(len(attempt["eligible_vulnerable"]), 1)
        self.assertEqual(len(attempt["eligible_patch"]), 1)
        self.assertTrue(all(item["eligible"] for item in candidates))
        self.assertTrue(
            all(item["source_materialization"]["status"] == "review_cache_reused" for item in candidates)
        )

    def test_cached_review_migrates_when_only_source_roots_changed(self) -> None:
        metadata = ranking_metadata()
        candidate = {
            "candidate_id": "vuln-1.0",
            "side": "vuln",
            "source_version": "1.0",
            "series": "focal",
            "pocket": "Updates",
            "source_materialization": {"extracted_path": "/current/source"},
        }
        legacy_candidate = {
            **candidate,
            "source_materialization": {"extracted_path": "/legacy/source"},
        }
        result = {
            "status": "ok",
            "items": [
                {
                    "candidate_id": "vuln-1.0",
                    "source_version": "1.0",
                    "classified_label": "vuln",
                    "functions_available": True,
                    "confidence": 1.0,
                    "reason": "cached",
                    "evidence": ["evidence"],
                }
            ],
            "notes": "",
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            legacy_tasks = [candidate_task(legacy_candidate)]
            _, legacy_prompt, legacy_result, _ = review_cache_paths(
                metadata,
                legacy_tasks,
                output=output,
                series="focal",
            )
            legacy_prompt.parent.mkdir(parents=True)
            legacy_prompt.write_text(render_prompt(metadata, legacy_tasks), encoding="utf-8")
            legacy_result.write_text(json.dumps(result), encoding="utf-8")
            cached = load_cached_source_review(
                metadata,
                [candidate],
                output=output,
                series="focal",
            )
            current_tasks = [candidate_task(candidate)]
            _, _, current_result, _ = review_cache_paths(
                metadata,
                current_tasks,
                output=output,
                series="focal",
            )
            self.assertTrue(current_result.is_file())
        self.assertEqual(cached["status"], "ok")
        self.assertEqual(cached["cache_migrated_from"], str(legacy_result))


class MetadataTests(unittest.TestCase):
    def test_metadata_adapter_resolves_project_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exports = root / "exports"
            diff_dir = root / "Diff" / "demo" / "diff_files"
            exports.mkdir()
            diff_dir.mkdir(parents=True)
            diff_path = diff_dir / "CVE-2024-0001.diff"
            diff_path.write_text("diff --git a/src/a.c b/src/a.c\n@@ -1 +1 @@\n-old();\n+new();\n", encoding="utf-8")
            (exports / "demo_metadata.json").write_text(
                json.dumps(
                    [
                        {
                            "CVE": "CVE-2024-0001",
                            "functions": ["parse_item"],
                            "function_code": {"by_function": {"parse_item": {}}},
                            "diff_related": [{"file": str(diff_path)}],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            path = resolve_metadata_path(root, "demo")
            rows = load_metadata(path, project="demo")
        self.assertEqual(rows[0].cve_id, "CVE-2024-0001")
        self.assertEqual(rows[0].raw["function_code"]["by_function"]["parse_item"]["file"], "src/a.c")


class PackageHintTests(unittest.TestCase):
    def test_component_matching_is_only_a_hint(self) -> None:
        self.assertEqual(source_component_hints(["libavcodec/decode.c", "lib/cookie.c"]), ["libavcodec"])
        self.assertTrue(package_matches_component("libavcodec58", "libavcodec"))
        self.assertFalse(package_matches_component("libcurl4", "lib"))


class PackageRankingTests(unittest.TestCase):
    def test_deepseek_result_is_closed_world(self) -> None:
        selection = selection_result()
        metadata = ranking_metadata()
        project = demo_project()

        def fake_transport(config, api_key, prompt):
            families = candidate_families(selection["selected"])
            return {
                "ranking": [
                    {"candidate_id": "invented", "confidence": "high", "reason": "invalid"},
                    {"candidate_id": families[1]["candidate_id"], "confidence": "medium", "reason": "valid"},
                ]
            }, {"model": "deepseek-v4-pro", "usage": {"total_tokens": 10}}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "llm.json"
            config.write_text(json.dumps({"model": "deepseek-v4-pro", "api_key": "key"}), encoding="utf-8")
            ranking = rank_selected_packages(selection, metadata, project, output=root, config_path=config, transport=fake_transport)
        task = ranking["tasks"][0]
        self.assertEqual(task["status"], "llm_ranked")
        self.assertEqual(len(task["ranking"]), 2)
        self.assertNotIn("invented", [item["candidate_id"] for item in task["ranking"]])

    def test_dynamic_llm_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "llm.json"
            path.write_text(json.dumps({"model": "deepseek-v4-pro", "api_key": "abc"}), encoding="utf-8")
            config = load_llm_config(path)
        self.assertEqual(config.resolved_api_key(), ("abc", "config"))

    def test_abi_package_names_share_logical_family(self) -> None:
        selection = candidate_pool_result()
        families = candidate_families(selection["candidate_pool"])
        codec = next(item for item in families if item["runtime_package"] == "libcodec")
        self.assertEqual(codec["coverage_count"], 8)


class SelectedBuildTests(unittest.TestCase):
    def test_shared_function_validation_cache_reuses_one_elf_across_cves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "libdemo.so"
            path.write_bytes(b"ELF")
            report = {
                "status": "ok",
                "reason": "ready",
                "unstripped_candidates": [
                    {
                        "unstripped_path": str(path),
                        "runtime_elf": "",
                        "debug_file": "",
                        "build_id": "build-id",
                    }
                ],
            }
            pair_a = PackagePair(
                cve_id="CVE-2024-1000",
                label="vuln",
                source_package="demo",
                source_version="1.0",
                series="focal",
                pocket="Security",
                component="main",
                runtime_url="https://example.test/demo.deb",
                debug_url="https://example.test/demo.ddeb",
                requested_functions=["decode_a"],
            )
            pair_b = PackagePair(**{**pair_a.to_json(), "cve_id": "CVE-2024-1001", "requested_functions": ["decode_b"]})
            report_cache = {}
            validation_cache = {}

            def validate_all(_path, functions):
                status = {
                    function: {
                        "status": "symbol_present",
                        "evidence": "test",
                        "symbol_name": function,
                    }
                    for function in functions
                }
                return {
                    "ok": True,
                    "available": True,
                    "availability": "symbol_present",
                    "found": list(functions),
                    "symbol_found": list(functions),
                    "dwarf_found": [],
                    "inline_only": [],
                    "dwarf_range_present": [],
                    "dwarf_abstract_only": [],
                    "missing": [],
                    "no_disassembly": [],
                    "symbol_names": {function: function for function in functions},
                    "function_status": status,
                }

            with patch("deployed.package_acquisition.artifacts.validate_functions", side_effect=validate_all) as validate:
                for pair in (pair_a, pair_b):
                    artifact = materialize_one(
                        demo_project(),
                        pair,
                        output=Path(directory),
                        verify_sha256=False,
                        resume=True,
                        cache=report_cache,
                        function_validation_cache=validation_cache,
                        validation_functions=["decode_a", "decode_b"],
                        materializer=lambda **_: report,
                    )
                    self.assertEqual(artifact.status, "ok")

            validate.assert_called_once_with(path, ["decode_a", "decode_b"])

    def test_requested_function_universe_includes_version_mapping(self) -> None:
        selection = balanced_selection(1)
        ranking = package_rankings(candidate_families(selection["candidate_pool"]), "pair_1")
        ranking["CVE-2024-1000"]["candidate_families"][0]["versions"][0]["source_validation"] = {
            "function_mappings": [
                {
                    "canonical_function": "decode_item",
                    "candidate_function": "legacy_decode_item",
                    "relationship": "semantic_equivalent",
                }
            ]
        }
        functions = requested_function_universe([selection], ranking)
        self.assertEqual(functions, ["decode_item", "legacy_decode_item"])

    def test_transient_materialization_failure_is_not_cached(self) -> None:
        pair = PackagePair(
            cve_id="CVE-2024-1000",
            label="vuln",
            source_package="demo",
            source_version="1.0",
            series="focal",
            pocket="Updates",
            component="main",
            runtime_package="libdemo",
            runtime_version="1.0",
            runtime_url="https://launchpad.test/libdemo.deb",
            runtime_filename="libdemo.deb",
            debug_package="libdemo-dbgsym",
            debug_version="1.0",
            debug_url="https://launchpad.test/libdemo.ddeb",
            debug_filename="libdemo.ddeb",
            status="paired",
            requested_functions=["decode_item"],
        )
        calls = []

        def unavailable(**kwargs):
            calls.append(kwargs)
            return {"status": "url_unreachable", "reason": "temporary 503", "pair": pair.to_json()}

        cache = {}
        for _ in range(2):
            artifact = materialize_one(
                demo_project(),
                pair,
                output=Path("/tmp"),
                verify_sha256=False,
                resume=True,
                cache=cache,
                materializer=unavailable,
            )
            self.assertEqual(artifact.status, "url_unreachable")
        self.assertEqual(len(calls), 2)
        self.assertEqual(cache, {})

    def test_package_validation_uses_version_specific_function_mapping(self) -> None:
        selection = balanced_selection(1)
        first_pair = selection["candidate_pool"]["pairs"][0]
        first_pair["vulnerable"]["source_validation"] = {
            "function_mappings": [
                {
                    "canonical_function": "decode_item",
                    "candidate_function": "legacy_decode_item",
                    "relationship": "semantic_equivalent",
                    "evidence": ["src/legacy.c"],
                }
            ]
        }
        first_pair["patch"]["source_validation"] = {
            "function_mappings": [
                {
                    "canonical_function": "decode_item",
                    "candidate_function": "decode_item",
                    "relationship": "exact",
                    "evidence": ["src/current.c"],
                }
            ]
        }
        first_pair["vulnerable"]["source_publication"]["date_published"] = "2024-03-27T11:54:44+00:00"
        first_pair["patch"]["source_publication"]["date_published"] = "2024-03-28T11:54:44+00:00"
        first_pair["vulnerable"]["binary_availability"]["runtime_debug_pairs"][0]["runtime"]["arch"] = "arm64"
        first_pair["vulnerable"]["binary_availability"]["runtime_debug_pairs"][0]["debug"]["arch"] = "arm64"
        first_pair["patch"]["binary_availability"]["runtime_debug_pairs"][0]["runtime"]["arch"] = "arm64"
        first_pair["patch"]["binary_availability"]["runtime_debug_pairs"][0]["debug"]["arch"] = "arm64"
        family = candidate_families(selection["candidate_pool"])[0]
        pairs = pairs_for_family(
            selection,
            {"function": "decode_item", "task_hash": "task"},
            family,
        )
        requested = {(item.label, item.requested_functions[0]) for item in pairs}
        self.assertEqual(requested, {("vuln", "legacy_decode_item"), ("patch", "decode_item")})
        self.assertEqual({item.architecture for item in pairs}, {"arm64"})
        self.assertEqual(
            {item.publication_date for item in pairs},
            {"2024-03-27T11:54:44+00:00", "2024-03-28T11:54:44+00:00"},
        )

    def test_selection_loader_accepts_balanced_3v3_and_2v2(self) -> None:
        for count in (3, 2):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                selection = balanced_selection(count)
                path = Path(directory) / "selected.json"
                path.write_text(json.dumps([selection]), encoding="utf-8")
                loaded = load_selection_results(path)
                labels = labels_from_selections(loaded, {"CVE-2024-1000": ranking_metadata()})
                self.assertEqual(len(labels), count * 2)
                self.assertEqual(sum(item.label == "vuln" for item in labels), count)
                if count == 2:
                    attempts = version_attempts(selection, max_attempts=4)
                    self.assertEqual([item["count_per_label"] for item in attempts], [2, 1, 1])

    def test_version_attempts_honors_one_per_label_limit(self) -> None:
        attempts = version_attempts(
            balanced_selection(3),
            max_attempts=4,
            max_per_label=1,
        )
        self.assertTrue(attempts)
        self.assertTrue(all(item["count_per_label"] == 1 for item in attempts))

    def test_package_materialization_accepts_2v2(self) -> None:
        selection = balanced_selection(2)
        families = candidate_families(selection["candidate_pool"])
        codec = next(item for item in families if item["runtime_package"] == "libcodec")
        rankings = package_rankings(families, codec["candidate_id"])

        with tempfile.TemporaryDirectory() as directory, patch(
            "deployed.package_acquisition.selected_build.result_for_cve",
            artifact_from_report,
        ):
            materialized_pairs, artifacts, report = materialize_ranked_selections(
                [selection],
                rankings,
                demo_project(),
                output=Path(directory),
                verify_sha256=False,
                resume=False,
                materializer=successful_materializer,
            )
        self.assertEqual(len(materialized_pairs), 4)
        self.assertEqual(len(artifacts), 4)
        self.assertEqual(report["selected_cves"], 1)

    def test_sequential_search_advances_after_anchor_failure(self) -> None:
        selection = selection_result()
        families = candidate_families(selection["selected"])
        bad = next(item for item in families if item["runtime_package"] == "demo")
        good = next(item for item in families if item["runtime_package"] == "libcodec")
        rankings = package_rankings(families, bad["candidate_id"], good["candidate_id"])
        calls = []

        def fake_materializer(*, pair, **kwargs):
            calls.append(pair.runtime_package)
            return {"status": "ok" if pair.runtime_package == "libcodec1" else "build_id_mismatch"}

        with tempfile.TemporaryDirectory() as directory, patch(
            "deployed.package_acquisition.selected_build.result_for_cve",
            artifact_from_report,
        ):
            pairs, artifacts, report = materialize_ranked_selections(
                [selection_result()],
                rankings,
                demo_project(),
                output=Path(directory),
                verify_sha256=False,
                resume=False,
                materializer=fake_materializer,
            )
        self.assertEqual(len(pairs), 6)
        self.assertEqual(len(artifacts), 6)
        self.assertEqual(report["selected_cves"], 1)
        self.assertEqual(calls[:2], ["demo", "libcodec1"])

    def test_version_search_replaces_failed_initial_pair(self) -> None:
        selection = candidate_pool_result()
        families = candidate_families(selection["candidate_pool"])
        codec = next(item for item in families if item["runtime_package"] == "libcodec")
        rankings = package_rankings(families, codec["candidate_id"])

        def fake_result(pair, functions, report, validation_cache=None, validation_functions=None):
            del validation_cache, validation_functions
            failed = pair.source_version in {"1.0-v3", "1.0-p3"}
            return artifact_from_report(
                pair,
                functions,
                report,
                status="function_missing" if failed else "ok",
            )

        with tempfile.TemporaryDirectory() as directory, patch(
            "deployed.package_acquisition.selected_build.result_for_cve",
            fake_result,
        ):
            pairs, _, report = materialize_ranked_selections(
                [selection],
                rankings,
                demo_project(),
                output=Path(directory),
                verify_sha256=False,
                resume=False,
                max_version_attempts=4,
                materializer=successful_materializer,
            )
        self.assertEqual(report["selected_cves"], 1)
        self.assertEqual(len(report["cves"][0]["version_attempts"]), 2)
        self.assertNotIn("1.0-v3", {item.source_version for item in pairs})
        self.assertEqual(len(version_attempts(selection, max_attempts=4)), 4)

    def test_version_search_downgrades_from_3v3_to_2v2(self) -> None:
        selection = candidate_pool_result()
        families = candidate_families(selection["candidate_pool"])
        codec = next(item for item in families if item["runtime_package"] == "libcodec")
        codec = {
            **codec,
            "versions": [
                item
                for item in codec["versions"]
                if item["source_version"] in {"1.0-v1", "1.0-p1", "1.0-v2", "1.0-p2"}
            ],
        }
        rankings = package_rankings([codec], codec["candidate_id"])

        with tempfile.TemporaryDirectory() as directory, patch(
            "deployed.package_acquisition.selected_build.result_for_cve",
            artifact_from_report,
        ):
            pairs, _, report = materialize_ranked_selections(
                [selection],
                rankings,
                demo_project(),
                output=Path(directory),
                verify_sha256=False,
                resume=False,
                max_version_attempts=4,
                materializer=successful_materializer,
            )
        attempts = report["cves"][0]["version_attempts"]
        self.assertEqual([item["selection"]["count_per_label"] for item in attempts], [3, 3, 2])
        self.assertEqual(report["resolved_selections"][0]["selected"]["count_per_label"], 2)
        self.assertEqual(len(pairs), 4)


class ExportTests(unittest.TestCase):
    def test_empty_dataset_fails_validation_and_prunes_stale_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exports = root / "exports"
            state = root / "state"
            stripped = root / "binaries" / "target" / "demo_stripped"
            debug = root / "binaries" / "target" / "demo_debug"
            for path in (exports, state, stripped, debug):
                path.mkdir(parents=True, exist_ok=True)
            for name, value in (
                ("testset.json", []),
                ("groundtruth.json", []),
                ("testset_detailed.json", []),
                ("artifacts.json", []),
            ):
                (exports / name).write_text(json.dumps(value), encoding="utf-8")
            (state / "package_search.json").write_text(
                json.dumps({"selected_cves": 0, "unresolved_cves": 1}),
                encoding="utf-8",
            )
            (stripped / "demo-1.0-libdemo.so-deployed").write_bytes(b"elf")
            (debug / "demo-1.0-libdemo.so-deployed.debug").write_bytes(b"debug")

            result = validate_dataset("demo", root)
            prune_unreferenced_binaries("demo", root, [], [])

            self.assertEqual(result["status"], "failed")
            self.assertIn("dataset contains no exported CVEs", result["errors"])
            self.assertIn("package search left 1 unresolved CVEs", result["warnings"])
            self.assertFalse(any(stripped.iterdir()))
            self.assertFalse(any(debug.iterdir()))

    def test_deployed_binary_name_uses_base_compatible_export_name(self) -> None:
        physical = deployed_target_binary_name("openssl", "3.5.0-2ubuntu1", "/usr/lib/libcrypto.so.3")
        self.assertEqual(physical, "openssl-3.5.0-2ubuntu1-libcrypto.so.3-deployed")
        self.assertEqual(deployed_export_name(physical), "openssl-3.5.0-2ubuntu1-libcrypto.so.3")

    def test_testset_strips_deployed_suffix_from_binary_names(self) -> None:
        physical = "openssl-3.5.0-2ubuntu1-libcrypto.so.3-deployed"
        artifact = ArtifactResult(
            cve_id="CVE-2024-1000",
            label="vuln",
            source_version="3.5.0-2ubuntu1",
            runtime_package="libssl3",
            runtime_version="3.5.0-2ubuntu1",
            debug_package="libssl3-dbgsym",
            debug_version="3.5.0-2ubuntu1",
            status="ok",
            stripped_path=f"/tmp/{physical}",
            debug_path=f"/tmp/{physical}.debug",
        )
        patch_physical = "openssl-3.5.1-1ubuntu1-libcrypto.so.3-deployed"
        patched = ArtifactResult(
            cve_id="CVE-2024-1000",
            label="patch",
            source_version="3.5.1-1ubuntu1",
            runtime_package="libssl3",
            runtime_version="3.5.1-1ubuntu1",
            debug_package="libssl3-dbgsym",
            debug_version="3.5.1-1ubuntu1",
            status="ok",
            stripped_path=f"/tmp/{patch_physical}",
            debug_path=f"/tmp/{patch_physical}.debug",
        )
        detailed = build_testset([artifact, patched], {"CVE-2024-1000": ranking_metadata()}, max_per_label=1)
        groundtruth = build_groundtruth(detailed)
        self.assertEqual(detailed[0]["vuln"][0]["name"], deployed_export_name(physical))
        self.assertEqual(groundtruth[0]["vuln"], [deployed_export_name(physical)])

    def test_testset_keeps_largest_available_balanced_set(self) -> None:
        for vulnerable, patched, expected in ((["1", "2", "3"], ["4", "5", "6"], 3), (["1", "2", "3"], ["4", "5"], 2)):
            with self.subTest(expected=expected):
                artifacts = export_artifacts(vulnerable, patched)
                testset = build_testset(artifacts, {"CVE-2024-1000": ranking_metadata()}, max_per_label=3)
                self.assertEqual(testset[0]["count_per_label"], expected)
                self.assertEqual(len(testset[0]["vuln"]), expected)
                self.assertEqual(len(testset[0]["patch"]), expected)
                groundtruth = build_groundtruth(testset)
                base_testset = build_base_testset(groundtruth)
                self.assertEqual(
                    set(base_testset[0]["binaries"]),
                    set(groundtruth[0]["vuln"] + groundtruth[0]["patch"]),
                )

    def test_final_dataset_validator_checks_binary_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exports = root / "exports"
            state = root / "state"
            stripped = root / "binaries" / "target" / "demo_stripped"
            debug = root / "binaries" / "target" / "demo_debug"
            for path in (exports, state, stripped, debug):
                path.mkdir(parents=True, exist_ok=True)
            vulnerable = [f"vuln-{index}" for index in range(3)]
            patched = [f"patch-{index}" for index in range(3)]
            truth = [{"CVE": "CVE-2024-1000", "functions": ["decode_item"], "vuln": vulnerable, "patch": patched}]
            testset = [{"CVE": "CVE-2024-1000", "functions": ["decode_item"], "binaries": vulnerable + patched}]
            detailed = [
                {
                    "CVE": "CVE-2024-1000",
                    "functions": ["decode_item"],
                    "vuln": [{"name": name, "source_version": name} for name in vulnerable],
                    "patch": [{"name": name, "source_version": name} for name in patched],
                }
            ]
            artifacts = []
            for label, names in (("vuln", vulnerable), ("patch", patched)):
                for name in names:
                    stripped_path = stripped / name
                    debug_path = debug / f"{name}.debug"
                    runtime_elf = f"/cache/usr/lib/{name}.so"
                    stripped_path.write_bytes(b"elf")
                    debug_path.write_bytes(b"debug")
                    artifacts.append(
                        {
                            "cve_id": "CVE-2024-1000",
                            "label": label,
                            "source_version": name,
                            "status": "ok",
                            "build_id": name,
                            "runtime_elf": runtime_elf,
                            "stripped_path": str(stripped_path),
                            "debug_path": str(debug_path),
                        }
                    )
            artifacts.append(
                {
                    "cve_id": "CVE-2024-9999",
                    "label": "vuln",
                    "source_version": "unused",
                    "status": "inline_only",
                    "build_id": "unused",
                    "stripped_path": str(stripped / "pruned"),
                    "debug_path": str(debug / "pruned.debug"),
                }
            )
            for name, value in (
                ("testset.json", testset),
                ("groundtruth.json", truth),
                ("testset_detailed.json", detailed),
                ("artifacts.json", artifacts),
            ):
                (exports / name).write_text(json.dumps(value), encoding="utf-8")
            (state / "package_search.json").write_text(
                json.dumps({"selected_cves": 1, "unresolved_cves": 0}),
                encoding="utf-8",
            )
            result = validate_dataset("demo", root)
        self.assertEqual(result["status"], "ok")

    def test_finalize_compacts_legacy_run_and_removes_work_caches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            legacy = root / "dataset"
            base_exports = Path(directory) / "base" / "exports"
            base_exports.mkdir(parents=True)
            (base_exports / "demo_metadata.json").write_text("{}", encoding="utf-8")
            (base_exports / "demo_reference.json").write_text("{}", encoding="utf-8")

            exports = legacy / "exports"
            state = legacy / "state"
            stripped = legacy / "binaries" / "target" / "demo_stripped"
            debug = legacy / "binaries" / "target" / "demo_debug"
            for path in (exports, state, stripped, debug):
                path.mkdir(parents=True, exist_ok=True)
            vulnerable = [f"vuln-{index}" for index in range(3)]
            patched = [f"patch-{index}" for index in range(3)]
            rows = {"vuln": [], "patch": []}
            artifacts = []
            for label, names in (("vuln", vulnerable), ("patch", patched)):
                for name in names:
                    stripped_path = stripped / name
                    debug_path = debug / f"{name}.debug"
                    runtime_elf = f"/cache/usr/lib/{name}.so"
                    stripped_path.write_bytes(b"elf")
                    debug_path.write_bytes(b"debug")
                    entry = {
                        "name": name,
                        "source_version": name,
                        "path": str(stripped_path),
                        "debug_path": str(debug_path),
                        "status": "ok",
                        "build_id": name,
                    }
                    rows[label].append(entry)
                    artifacts.append(
                        {
                            "cve_id": "CVE-2024-1000",
                            "label": label,
                            "source_version": name,
                            "status": "ok",
                            "build_id": name,
                            "runtime_elf": runtime_elf,
                            "stripped_path": str(stripped_path),
                            "debug_path": str(debug_path),
                        }
                    )
            truth = [{"CVE": "CVE-2024-1000", "functions": ["decode_item"], "vuln": vulnerable, "patch": patched}]
            testset = [{"CVE": "CVE-2024-1000", "functions": ["decode_item"], "binaries": vulnerable + patched}]
            detailed = [{"CVE": "CVE-2024-1000", "functions": ["decode_item"], **rows}]
            for name, value in (
                ("testset.json", testset),
                ("groundtruth.json", truth),
                ("testset_detailed.json", detailed),
                ("artifacts.json", artifacts),
            ):
                (exports / name).write_text(json.dumps(value), encoding="utf-8")
            (state / "package_search.json").write_text(
                json.dumps({"selected_cves": 1, "unresolved_cves": 0}),
                encoding="utf-8",
            )
            for path in (
                legacy / "artifacts" / "report.json",
                legacy / "downloads" / "package.deb",
                root / "selection" / "sources" / "source.txt",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("cache", encoding="utf-8")
            (root / "input" / "ubuntu-cves").mkdir(parents=True)

            self.assertEqual(validate_dataset("demo", legacy)["status"], "ok")
            manifest = finalize_run_output(root, project="demo", arch="x86", metadata=base_exports.parent)
            finalized = validate_dataset("demo", root, variant="ubuntu-amd64")
            removed = cleanup_work_caches(root)
            post_cleanup = validate_dataset("demo", root, variant="ubuntu-amd64")

            self.assertEqual(manifest["variant"], "ubuntu-amd64")
            self.assertTrue((root / "exports" / "testset.ubuntu-amd64.json").is_file())
            self.assertTrue((root / "exports" / "groundtruth.ubuntu-amd64.json").is_file())
            self.assertTrue((root / "exports" / "demo_metadata.json").is_file())
            self.assertTrue((root / "exports" / "demo_reference.json").is_file())
            self.assertTrue((root / "deployed" / "trace" / "testset_detailed.json").is_file())
            self.assertFalse((root / "dataset").exists())
            self.assertEqual(finalized["status"], "ok")
            self.assertEqual(post_cleanup["status"], "ok")
            self.assertEqual(len(removed), 3)
            rewritten = json.loads((root / "deployed" / "trace" / "testset_detailed.json").read_text(encoding="utf-8"))
            self.assertTrue(rewritten[0]["vuln"][0]["path"].startswith(str(root / "binaries")))
            expected_physical = deployed_target_binary_name("demo", "vuln-0", "vuln-0.so")
            self.assertTrue((root / "binaries" / "target" / "demo_stripped" / expected_physical).is_file())
            groundtruth = json.loads((root / "exports" / "groundtruth.ubuntu-amd64.json").read_text(encoding="utf-8"))
            self.assertIn(deployed_export_name(expected_physical), groundtruth[0]["vuln"])


class IncrementalTests(unittest.TestCase):
    def test_rebase_finalized_output_updates_resume_paths_after_move(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "current"
            previous = Path(directory) / "previous"
            exports = root / "exports"
            trace = root / "deployed" / "trace"
            state = root / "deployed" / "state"
            for path in (exports, trace, state):
                path.mkdir(parents=True, exist_ok=True)

            stripped = root / "binaries" / "target" / "demo_stripped" / "demo-1.0-deployed"
            debug = root / "binaries" / "target" / "demo_debug" / "demo-1.0-deployed.debug"
            stripped.parent.mkdir(parents=True)
            debug.parent.mkdir(parents=True)
            stripped.write_bytes(b"elf")
            debug.write_bytes(b"debug")
            old_stripped = previous / stripped.relative_to(root)
            old_debug = previous / debug.relative_to(root)

            write_json(exports / "testset.ubuntu-amd64.json", [{"CVE": "CVE-2024-1000", "binaries": ["demo-1.0"]}])
            write_json(exports / "groundtruth.ubuntu-amd64.json", [{"CVE": "CVE-2024-1000", "vuln": ["demo-1.0"], "patch": []}])
            write_json(
                trace / "testset_detailed.json",
                [{
                    "CVE": "CVE-2024-1000",
                    "vuln": [{
                        "name": "demo-1.0",
                        "source_version": "1.0",
                        "path": str(old_stripped),
                        "debug_path": str(old_debug),
                        "status": "ok",
                        "build_id": "build-id",
                    }],
                    "patch": [],
                }],
            )
            write_json(state / "artifact_results.json", [{
                "cve_id": "CVE-2024-1000",
                "stripped_path": str(old_stripped),
                "debug_path": str(old_debug),
                "status": "ok",
                "build_id": "build-id",
            }])
            write_json(root / "deployed" / "manifest.json", {
                "schema": "ubuntu-deployed-final-layout-v1",
                "testset": str(previous / "exports" / "testset.ubuntu-amd64.json"),
                "groundtruth": str(previous / "exports" / "groundtruth.ubuntu-amd64.json"),
            })

            replacements = rebase_finalized_output(root)

            self.assertEqual(replacements, {str(previous): str(root.resolve())})
            detail = json.loads((trace / "testset_detailed.json").read_text(encoding="utf-8"))
            self.assertEqual(detail[0]["vuln"][0]["path"], str(stripped))
            manifest = json.loads((root / "deployed" / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["testset"], str(exports / "testset.ubuntu-amd64.json"))

    def test_completed_cves_uses_balanced_final_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            exports = root / "exports"
            trace = root / "deployed" / "trace"
            state = root / "deployed" / "state"
            exports.mkdir(parents=True)
            trace.mkdir(parents=True)
            state.mkdir(parents=True)
            entries = {"vuln": [], "patch": []}
            state_artifacts = []
            for label, version in (("vuln", "1.0"), ("patch", "1.1")):
                stripped = root / "binaries" / f"demo-{version}-deployed"
                debug = root / "binaries" / f"demo-{version}-deployed.debug"
                stripped.parent.mkdir(parents=True, exist_ok=True)
                stripped.write_bytes(b"elf")
                debug.write_bytes(b"debug")
                entries[label].append(
                    {
                        "name": f"demo-{version}",
                        "source_version": version,
                        "path": str(stripped),
                        "debug_path": str(debug),
                        "status": "ok",
                        "build_id": version,
                    }
                )
                state_artifacts.append(
                    {
                        "cve_id": "CVE-2024-1000",
                        "stripped_path": str(stripped),
                        "debug_path": str(debug),
                        "status": "ok",
                        "build_id": version,
                    }
                )
            truth = [{"CVE": "CVE-2024-1000", "vuln": ["demo-1.0"], "patch": ["demo-1.1"]}]
            testset = [{"CVE": "CVE-2024-1000", "binaries": ["demo-1.0", "demo-1.1"]}]
            detailed = [{"CVE": "CVE-2024-1000", **entries}]
            (exports / "groundtruth.ubuntu-amd64.json").write_text(json.dumps(truth), encoding="utf-8")
            (exports / "testset.ubuntu-amd64.json").write_text(json.dumps(testset), encoding="utf-8")
            (trace / "testset_detailed.json").write_text(json.dumps(detailed), encoding="utf-8")
            (state / "resolved_3v3.json").write_text(
                json.dumps([{"cve_id": "CVE-2024-1000", "selected": {}}]),
                encoding="utf-8",
            )
            (state / "artifact_results.json").write_text(json.dumps(state_artifacts), encoding="utf-8")
            self.assertEqual(completed_cves(root, "demo", "x86"), {"CVE-2024-1000"})
            Path(entries["patch"][0]["debug_path"]).unlink()
            self.assertEqual(completed_cves(root, "demo", "x86"), set())

    def test_incremental_merge_preserves_old_cve_and_adds_new_cve(self) -> None:
        old_artifact = ArtifactResult(
            cve_id="CVE-2024-0001",
            label="vuln",
            source_version="1.0",
            runtime_package="demo",
            runtime_version="1.0",
            debug_package="demo-dbgsym",
            debug_version="1.0",
            status="ok",
        )
        new_artifact = ArtifactResult(
            cve_id="CVE-2024-0002",
            label="patch",
            source_version="2.0",
            runtime_package="demo",
            runtime_version="2.0",
            debug_package="demo-dbgsym",
            debug_version="2.0",
            status="ok",
        )
        previous = {
            "metadata": [CveMetadata("CVE-2024-0001", ["old"])],
            "labels": [],
            "pairs": [],
            "artifacts": [old_artifact],
            "selections": [{"cve_id": "CVE-2024-0001", "selected": {}}],
            "resolved_selections": [{"cve_id": "CVE-2024-0001", "selected": {}}],
            "rankings": {"CVE-2024-0001": {"tasks": []}},
            "search": {
                "cves": [{"cve_id": "CVE-2024-0001", "status": "selected"}],
                "resolved_selections": [{"cve_id": "CVE-2024-0001", "selected": {}}],
            },
        }
        current_selection = {"cve_id": "CVE-2024-0002", "selected": {"count_per_label": 1}}
        merged = merge_build_snapshot(
            previous,
            current_cves={"CVE-2024-0002"},
            metadata=[CveMetadata("CVE-2024-0002", ["new"])],
            labels=[],
            pairs=[],
            artifacts=[new_artifact],
            selections=[current_selection],
            resolved_selections=[current_selection],
            rankings={"CVE-2024-0002": {"tasks": []}},
            search={
                "cves": [{"cve_id": "CVE-2024-0002", "status": "selected"}],
                "resolved_selections": [current_selection],
            },
        )
        self.assertEqual({item.cve_id for item in merged["artifacts"]}, {"CVE-2024-0001", "CVE-2024-0002"})
        self.assertEqual(merged["search"]["selected_cves"], 2)
        self.assertEqual(set(merged["rankings"]), {"CVE-2024-0001", "CVE-2024-0002"})


class CliTests(unittest.TestCase):
    def test_only_current_workflow_commands_are_exposed(self) -> None:
        help_text = build_parser().format_help()
        self.assertIn("groundtruth", help_text)
        self.assertIn("source-groundtruth", help_text)
        self.assertIn("select-3v3", help_text)
        self.assertIn("build", help_text)
        self.assertIn("run", help_text)
        self.assertIn("finalize", help_text)
        self.assertNotIn("discover", help_text)
        self.assertNotIn("review-missing", help_text)

    def test_requested_cves_prefers_base_testset_then_metadata_functions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exports = root / "exports"
            exports.mkdir()
            metadata_path = exports / "demo_metadata.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "CVE-2024-0001": {"functions": ["foo"]},
                        "CVE-2024-0002": {"functions": ["bar"]},
                        "CVE-2024-0003": {"functions": []},
                    }
                ),
                encoding="utf-8",
            )
            (exports / "testset.json").write_text(
                json.dumps([{"CVE": "CVE-2024-0002"}, {"CVE": "CVE-2024-0001"}]),
                encoding="utf-8",
            )
            args = argparse.Namespace(cve=[], cve_file=[], cve_json=[], project="demo")
            self.assertEqual(resolve_requested_cves(args, metadata_path), ["CVE-2024-0001", "CVE-2024-0002"])
            (exports / "testset.json").unlink()
            self.assertEqual(resolve_requested_cves(args, metadata_path), ["CVE-2024-0001", "CVE-2024-0002"])

    def test_resume_skips_network_and_build_for_completed_cves(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "demo_metadata.json"
            metadata.write_text("{}", encoding="utf-8")
            args = run_args(root, metadata=metadata, resume=True)
            with (
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
                patch("deployed.command_run.resolve_requested_cves", return_value=["CVE-2024-0001"]),
                patch("deployed.command_run.completed_cves", return_value={"CVE-2024-0001"}),
                patch("deployed.command_run.validate_dataset", return_value={"status": "ok"}),
                patch("deployed.command_run.prepare_ubuntu_jsons") as prepare,
                patch("deployed.command_run.handle_select") as select,
                patch("deployed.command_run.handle_build") as build,
            ):
                self.assertEqual(handle_run(args), 0)
            prepare.assert_not_called()
            select.assert_not_called()
            build.assert_not_called()

    def test_run_retries_unresolved_cve_after_incremental_source_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            selection_dir = root / "deployed" / "selection"
            pending = root / "deployed" / "input" / "pending.json"
            state.mkdir(parents=True)
            selection = {"cve_id": "CVE-2024-1000", "selected": {"count_per_label": 1}}
            write_json(
                state / "package_search.json",
                {
                    "cves": [
                        {
                            "cve_id": "CVE-2024-1000",
                            "status": "unresolved",
                            "version_attempts": [
                                {
                                    "status": "rejected",
                                    "selection": {
                                        "vulnerable": [{"sampling_stratum": "far"}],
                                        "patch": [{"sampling_stratum": "far"}],
                                    },
                                }
                            ],
                        }
                    ]
                },
            )
            args = argparse.Namespace(
                project="demo",
                max_source_fallback_rounds=2,
                max_selection_minutes=1,
                source_download_timeout=30,
                source_review_timeout=300,
                refresh=False,
            )
            build_args = argparse.Namespace(selection_file=[], resume=False)

            def build(_args):
                self.assertTrue(_args.resume)
                write_json(
                    state / "package_search.json",
                    {"cves": [{"cve_id": "CVE-2024-1000", "status": "selected"}]},
                )
                return 0

            with (
                redirect_stderr(io.StringIO()),
                patch("deployed.command_run.load_metadata", return_value=[ranking_metadata()]),
                patch(
                    "deployed.command_run.expand_selection_result",
                    return_value={
                        "reviewed_candidate_ids": ["vuln-far", "patch-far"],
                        "new_pair_count": 1,
                        "reserve_candidate_count": 2,
                    },
                ) as expand,
                patch("deployed.command_run.persist_selection_updates") as persist,
                patch("deployed.command_run.handle_build", side_effect=build) as handle_build_mock,
            ):
                rc = run_source_fallbacks(
                    args,
                    output=root,
                    selection_dir=selection_dir,
                    pending_selection_file=pending,
                    selections=[selection],
                    metadata_path=root / "metadata.json",
                    build_args=build_args,
                )
            self.assertEqual(rc, 0)
            self.assertEqual(expand.call_args.kwargs["preferred_strata"], ["far"])
            persist.assert_called_once_with(selection_dir, [selection])
            handle_build_mock.assert_called_once()
            self.assertEqual(json.loads(pending.read_text(encoding="utf-8")), [selection])

    def test_ubuntu_json_failures_are_nonfatal_exclusions(self) -> None:
        cases = (
            ("HTTP Error 404: Not Found", "not found", "not_found"),
            ("<urlopen error timed out>", "tracker timed out", "unavailable"),
        )
        for ubuntu_error, tracker_error, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                with (
                    patch(
                        "deployed.command_run.download_file",
                        return_value=(False, ubuntu_error),
                    ) as download,
                    patch(
                        "deployed.command_run.fetch_tracker_cve",
                        return_value=(False, tracker_error),
                    ),
                ):
                    paths, report = prepare_ubuntu_jsons(
                        ["CVE-2024-0001"],
                        explicit_paths=[],
                        input_dir=Path(directory),
                        refresh=False,
                        timeout=30,
                    )
                self.assertEqual(paths, [])
                self.assertEqual(report[0]["status"], expected)
                self.assertEqual(download.call_args.kwargs["attempts"], 1)
                self.assertEqual(download.call_args.kwargs["timeout"], 5)

    def test_ubuntu_json_timeout_opens_circuit_and_uses_tracker(self) -> None:
        def tracker(cve_id, path, *, timeout):
            del timeout
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "id": cve_id,
                        "packages": [
                            {
                                "name": "demo",
                                "statuses": [
                                    {
                                        "release_codename": "focal",
                                        "status": "released",
                                        "description": "1.0-1ubuntu0.1",
                                        "pocket": "security",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            return True, "tracker fallback"

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch(
                    "deployed.command_run.download_file",
                    return_value=(False, "The read operation timed out"),
                ) as ubuntu,
                patch("deployed.command_run.fetch_tracker_cve", side_effect=tracker) as fallback,
            ):
                paths, report = prepare_ubuntu_jsons(
                    ["CVE-2024-0001", "CVE-2024-0002"],
                    explicit_paths=[],
                    input_dir=Path(directory),
                    refresh=False,
                    timeout=30,
                )
        self.assertEqual(len(paths), 2)
        self.assertEqual(ubuntu.call_count, 1)
        self.assertEqual(fallback.call_count, 2)
        self.assertEqual({item["source"] for item in report}, {"ubuntu_cve_tracker"})

    def test_run_builds_at_final_root_and_finalizes_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_exports = root / "base" / "exports"
            base_exports.mkdir(parents=True)
            (base_exports / "demo_metadata.json").write_text("{}", encoding="utf-8")
            output = root / "output"
            selected_json = root / "CVE-2024-0001.json"
            selected_json.write_text("{}", encoding="utf-8")
            args = run_args(root, metadata=base_exports.parent, output=output)
            captured = {}

            def fake_select(select_args):
                captured["selection_output"] = select_args.output
                selected = selection_result()
                selected["cve_id"] = "CVE-2024-0001"
                export_dir = select_args.output / "exports"
                export_dir.mkdir(parents=True, exist_ok=True)
                (export_dir / "selected_3v3.json").write_text(
                    json.dumps([selected]),
                    encoding="utf-8",
                )
                return 0

            def fake_build(build_args):
                captured["build_output"] = build_args.output
                return 0

            def fake_finalize(final_output, **kwargs):
                captured["finalize_output"] = final_output
                return {"status": "ok"}, {"schema": "manifest"}, ["cache"]

            download_report = [
                {"cve_id": "CVE-2024-0001", "path": str(selected_json), "status": "ok", "message": "reused"},
                {
                    "cve_id": "CVE-2024-0002",
                    "path": str(root / "CVE-2024-0002.json"),
                    "status": "unavailable",
                    "message": "HTTP Error 503: Service Unavailable",
                },
            ]
            with (
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
                patch("deployed.command_run.resolve_requested_cves", return_value=["CVE-2024-0001", "CVE-2024-0002"]),
                patch("deployed.command_run.prepare_ubuntu_jsons", return_value=([selected_json], download_report)),
                patch("deployed.command_run.handle_select", side_effect=fake_select),
                patch("deployed.command_run.handle_build", side_effect=fake_build),
                patch("deployed.command_run.finalize_verified_run", side_effect=fake_finalize),
            ):
                self.assertEqual(handle_run(args), 0)

            self.assertEqual(captured["build_output"], output.resolve())
            self.assertEqual(captured["selection_output"], output.resolve() / "deployed" / "selection")
            self.assertEqual(captured["finalize_output"], output.resolve())
            self.assertFalse((output / "dataset").exists())
            excluded = json.loads((output / "deployed" / "input" / "ubuntu_json_excluded.json").read_text(encoding="utf-8"))
            self.assertEqual([item["cve_id"] for item in excluded], ["CVE-2024-0002"])

    def test_config_contains_current_projects(self) -> None:
        config = load_config(Path(__file__).resolve().parents[1] / "config.json")
        self.assertEqual(set(config.projects), {"binutils", "curl", "ffmpeg", "libxml2", "openssl", "sqlite"})


def candidate(version: str, days_from_fix: float) -> dict:
    return {"source_version": version, "days_from_fix": days_from_fix}


def source_publication(version: str, published: str) -> SourcePublication:
    return SourcePublication(
        source_package="demo",
        source_version=version,
        series="focal",
        pocket="Security" if version >= "2.0" else "Updates",
        component="main",
        status="Published",
        self_link=f"https://launchpad.test/source/{version}",
        date_published=published,
        date_created=published,
    )


def balanced_pair(vulnerable: str, patched: str, series: str) -> dict:
    return {
        "series": series,
        "ubuntu_release": "26.04",
        "fixed_source_version": patched,
        "series_rank": 0,
        "within_series_rank": 0,
        "vulnerable": candidate(vulnerable, -1),
        "patch": candidate(patched, 0),
        "distance_mismatch_days": 1,
    }


def ranking_metadata() -> CveMetadata:
    return CveMetadata(
        cve_id="CVE-2024-1000",
        functions=["decode_item"],
        raw={"function_code": {"by_function": {"decode_item": {"file": "libcodec/decode.c"}}}},
    )


def demo_project() -> ProjectConfig:
    return ProjectConfig(
        project="demo",
        source_package="demo",
        binary_packages=NameRules(exact=("libcodec1", "demo")),
        debug_packages=DebugRules(exact=("libcodec1-dbgsym", "demo-dbgsym")),
        elf=ElfRules(),
    )


def source_review_candidates(entries, *, pocket: str = "Security") -> list[dict]:
    publication = SourcePublication(
        source_package="demo",
        source_version="1.0",
        series="focal",
        pocket=pocket,
        component="main",
        status="Published",
        self_link="https://launchpad.test/source/1",
        date_published="2024-01-01T00:00:00+00:00",
        date_created="2024-01-01T00:00:00+00:00",
    )
    candidates = []
    for side, version in entries:
        row = publication.to_json()
        row["source_version"] = version
        candidates.append(
            {
                "candidate_id": f"{side}-{version}",
                "side": side,
                "source_version": version,
                "series": "focal",
                "pocket": pocket,
                "source_publication": row,
                "precheck_ready": True,
                "eligible": False,
                "rejection_reasons": [],
                "source_materialization": {"status": "skipped", "extracted_path": ""},
                "source_validation": {},
            }
        )
    return candidates


def source_review_result(candidates: list[dict], *, swap_labels: bool = False) -> dict:
    return {
        "status": "ok",
        "items": [
            {
                "candidate_id": item["candidate_id"],
                "source_version": item["source_version"],
                "classified_label": (
                    "patch" if item["side"] == "vuln" else "vuln"
                ) if swap_labels else item["side"],
                "functions_available": True,
                "confidence": 1.0,
                "reason": "reviewed source",
                "evidence": ["src/demo.c"],
            }
            for item in candidates
        ],
        "notes": "",
    }


def balanced_selection(count: int) -> dict:
    selection = candidate_pool_result()
    pairs = selection["candidate_pool"]["pairs"][:count]
    selection["candidate_pool"].update(
        {
            "target_count_per_label": count,
            "pair_count": count,
            "vulnerable": [item["vulnerable"] for item in pairs],
            "patch": [item["patch"] for item in pairs],
            "pairs": pairs,
        }
    )
    selection["selected"] = selection_from_pairs(pairs)
    return selection


def package_rankings(families: list[dict], *candidate_ids: str) -> dict:
    return {
        "CVE-2024-1000": {
            "candidate_families": families,
            "tasks": [
                {
                    "task_hash": "task",
                    "function": "decode_item",
                    "source_file": "libcodec/decode.c",
                    "ranking": [{"candidate_id": candidate_id} for candidate_id in candidate_ids],
                }
            ],
        }
    }


def successful_materializer(*, pair, **kwargs) -> dict:
    del kwargs
    return {"status": "ok", "source_version": pair.source_version}


def artifact_from_report(
    pair,
    functions,
    report,
    validation_cache=None,
    validation_functions=None,
    *,
    status: str | None = None,
) -> ArtifactResult:
    del validation_cache, validation_functions
    artifact_status = status or report["status"]
    path_key = f"{pair.source_version}-{pair.runtime_package}"
    return ArtifactResult(
        cve_id=pair.cve_id,
        label=pair.label,
        source_version=pair.source_version,
        runtime_package=pair.runtime_package,
        runtime_version=pair.runtime_version,
        debug_package=pair.debug_package,
        debug_version=pair.debug_version,
        status=artifact_status,
        functions=functions,
        found_functions=functions if artifact_status == "ok" else [],
        stripped_path=f"/tmp/{path_key}",
        debug_path=f"/tmp/{path_key}.debug",
        report=report,
    )


def export_artifacts(vulnerable: list[str], patched: list[str]) -> list[ArtifactResult]:
    artifacts = []
    for label, versions in (("vuln", vulnerable), ("patch", patched)):
        for version in versions:
            artifacts.append(
                ArtifactResult(
                    cve_id="CVE-2024-1000",
                    label=label,
                    source_version=version,
                    runtime_package="libcodec1",
                    runtime_version=version,
                    debug_package="libcodec1-dbgsym",
                    debug_version=version,
                    status="ok",
                    stripped_path=f"/tmp/{label}-{version}-deployed",
                    debug_path=f"/tmp/{label}-{version}-deployed.debug",
                )
            )
    return artifacts


def run_args(root: Path, **overrides) -> argparse.Namespace:
    values = {
        "project": "demo",
        "metadata": root / "metadata",
        "output": root / "output",
        "config": root / "config.json",
        "llm_config": root / "llm.json",
        "cve": [],
        "cve_file": [],
        "cve_json": [],
        "cve_json_dir": None,
        "series": None,
        "arch": "x86",
        "include_esm": False,
        "max_candidates_per_side": 8,
        "max_selection_minutes": 20.0,
        "source_download_timeout": 90,
        "source_review_timeout": 300,
        "selection_jobs": 1,
        "refresh": False,
        "refresh_package_ranking": False,
        "max_package_families": 3,
        "max_version_attempts": 4,
        "max_search_minutes": 30.0,
        "skip_download": False,
        "resume": False,
        "no_sha256": False,
        "skip_validation": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def selection_result() -> dict:
    rows = []
    for index, label in enumerate(["vuln", "vuln", "vuln", "patch", "patch", "patch"], start=1):
        version = f"1.0-{index}"
        pairs = []
        for runtime in ("demo", "libcodec1"):
            pairs.append(
                {
                    "runtime": {
                        "package": runtime,
                        "version": version,
                        "arch": "amd64",
                        "filename": f"{runtime}_{version}_amd64.deb",
                        "url": f"https://example/{runtime}_{version}_amd64.deb",
                    },
                    "debug": {
                        "package": f"{runtime}-dbgsym",
                        "version": version,
                        "arch": "amd64",
                        "filename": f"{runtime}-dbgsym_{version}_amd64.ddeb",
                        "url": f"https://example/{runtime}-dbgsym_{version}_amd64.ddeb",
                    },
                }
            )
        rows.append(
            {
                "source_version": version,
                "series": "jammy",
                "pocket": "Security" if label == "patch" else "Updates",
                "component": "main",
                "days_from_fix": float(index - 4),
                "source_publication": {"source_package": "demo", "self_link": f"https://example/source/{version}"},
                "binary_availability": {"runtime_debug_pairs": pairs},
            }
        )
    return {
        "cve_id": "CVE-2024-1000",
        "source_package": "demo",
        "selected": {
            "series": "jammy",
            "ubuntu_release": "22.04",
            "vulnerable": rows[:3],
            "patch": rows[3:],
        },
    }


def candidate_pool_result() -> dict:
    pairs = []
    for index in range(1, 5):
        pair_rows = []
        for label, version in (("vuln", f"1.0-v{index}"), ("patch", f"1.0-p{index}")):
            package_suffix = "1" if index < 3 else "2"
            runtime = f"libcodec{package_suffix}"
            row = {
                "source_version": version,
                "series": "jammy" if index < 3 else "focal",
                "pocket": "Updates" if label == "vuln" else "Security",
                "component": "main",
                "days_from_fix": float(-index if label == "vuln" else index - 1),
                "source_publication": {"source_package": "demo", "self_link": f"https://example/{version}"},
                "binary_availability": {
                    "runtime_debug_pairs": [
                        {
                            "runtime": {
                                "package": runtime,
                                "version": version,
                                "filename": f"{runtime}_{version}_amd64.deb",
                                "url": f"https://example/{runtime}_{version}_amd64.deb",
                            },
                            "debug": {
                                "package": f"{runtime}-dbgsym",
                                "version": version,
                                "filename": f"{runtime}-dbgsym_{version}_amd64.ddeb",
                                "url": f"https://example/{runtime}-dbgsym_{version}_amd64.ddeb",
                            },
                            "match": "exact_package_name",
                        }
                    ]
                },
            }
            pair_rows.append(row)
        pairs.append(
            {
                "series": pair_rows[0]["series"],
                "ubuntu_release": "22.04" if index < 3 else "20.04",
                "fixed_source_version": "1.0-p1",
                "series_rank": 0 if index < 3 else 1,
                "within_series_rank": index - 1,
                "vulnerable": pair_rows[0],
                "patch": pair_rows[1],
                "distance_mismatch_days": 1.0,
            }
        )
    selected = {
        "series": "jammy+focal",
        "ubuntu_release": "22.04",
        "fixed_source_version": "1.0-p1",
        "vulnerable": [item["vulnerable"] for item in pairs[:3]],
        "patch": [item["patch"] for item in pairs[:3]],
    }
    return {
        "cve_id": "CVE-2024-1000",
        "source_package": "demo",
        "candidate_pool": {
            "target_count_per_label": 3,
            "pair_count": 4,
            "vulnerable": [item["vulnerable"] for item in pairs],
            "patch": [item["patch"] for item in pairs],
            "pairs": pairs,
        },
        "selected": selected,
    }


if __name__ == "__main__":
    unittest.main()
