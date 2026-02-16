#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIBRARIES_DIR = ROOT / "libraries"

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-fA-F0-9]{40}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$")
GITHUB_REPO_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/?$")


def fail(message: str) -> None:
    print(f"❌ {message}")
    sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate Coi registry entries")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip GitHub-derived checks (owner/license/commit/sha256)",
    )
    return parser.parse_args()


def http_json(url: str, token: str | None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "coi-registry-validator",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def validate_release(release: dict, lib_name: str, rel_idx: int, seen_versions: set[str]) -> None:
    """Validate a single release entry within a library."""
    required = ["version", "compiler-drop", "releasedAt"]
    for key in required:
        if key not in release:
            fail(f"{lib_name}: release[{rel_idx}] missing '{key}'")

    version = release["version"]
    if not isinstance(version, str) or not VERSION_RE.match(version):
        fail(f"{lib_name}: release[{rel_idx}].version must be semver (e.g. 1.0.0)")
    if version in seen_versions:
        fail(f"{lib_name}: duplicate release version: {version}")
    seen_versions.add(version)

    released_at = release.get("releasedAt")
    if not isinstance(released_at, str) or not DATE_RE.match(released_at):
        fail(f"{lib_name}: release[{rel_idx}].releasedAt must be YYYY-MM-DD")

    compiler_drop = release.get("compiler-drop")
    if not isinstance(compiler_drop, dict):
        fail(f"{lib_name}: release[{rel_idx}].compiler-drop must be an object")

    min_drop = compiler_drop.get("min")
    tested_on = compiler_drop.get("tested-on")

    if not isinstance(min_drop, int) or min_drop < 1:
        fail(f"{lib_name}: release[{rel_idx}].compiler-drop.min must be >= 1")

    if not isinstance(tested_on, int) or tested_on < 1:
        fail(f"{lib_name}: release[{rel_idx}].compiler-drop.tested-on must be an integer >= 1")
    if tested_on < min_drop:
        fail(f"{lib_name}: release[{rel_idx}].compiler-drop.tested-on must be >= min")

    source = release.get("source")
    if source is not None:
        if not isinstance(source, dict):
            fail(f"{lib_name}: release[{rel_idx}].source must be an object")
        commit = source.get("commit")
        sha256 = source.get("sha256")
        if commit is not None and (not isinstance(commit, str) or not COMMIT_RE.match(commit)):
            fail(f"{lib_name}: release[{rel_idx}].source.commit must be a 40-char hex string")
        if sha256 is not None and (not isinstance(sha256, str) or not SHA256_RE.match(sha256)):
            fail(f"{lib_name}: release[{rel_idx}].source.sha256 must be a 64-char hex string")


def validate_library_file(lib_path: Path, offline: bool, token: str | None) -> None:
    """Validate an individual library file under libraries/**/*.json."""
    lib_name = lib_path.stem

    try:
        data = json.loads(lib_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"{lib_name}: invalid JSON: {e}")

    if not isinstance(data, dict):
        fail(f"{lib_name}: root must be a JSON object")

    required = ["name", "schema-version", "repository", "releases", "createdAt"]
    for key in required:
        if key not in data:
            fail(f"{lib_name}: missing '{key}'")

    # Name must match filename
    if data["name"] != lib_name:
        fail(f"{lib_name}: name field '{data['name']}' does not match filename")

    schema_version = data.get("schema-version")
    if not isinstance(schema_version, int) or schema_version < 1:
        fail(f"{lib_name}: schema-version must be >= 1")

    created_at = data.get("createdAt")
    if not isinstance(created_at, str) or not DATE_RE.match(created_at):
        fail(f"{lib_name}: createdAt must be YYYY-MM-DD")

    repository = data["repository"]
    if not isinstance(repository, str):
        fail(f"{lib_name}: repository must be a string")
    match = GITHUB_REPO_RE.match(repository)
    if not match:
        fail(f"{lib_name}: repository must be a GitHub URL like https://github.com/owner/repo")
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]

    releases = data.get("releases")
    if not isinstance(releases, list) or len(releases) == 0:
        fail(f"{lib_name}: releases must be a non-empty array")

    seen_versions: set[str] = set()
    for idx, release in enumerate(releases):
        if not isinstance(release, dict):
            fail(f"{lib_name}: release[{idx}] must be an object")
        validate_release(release, lib_name, idx, seen_versions)

    if offline:
        return

    # Online checks: verify repository exists and has MIT license
    try:
        repo_meta = http_json(f"https://api.github.com/repos/{owner}/{repo}", token)
    except urllib.error.HTTPError as err:
        fail(f"{lib_name}: GitHub repo lookup failed ({err.code}) for {owner}/{repo}")
    except Exception as err:
        fail(f"{lib_name}: GitHub repo lookup failed: {err}")

    license_data = repo_meta.get("license") or {}
    spdx_id = license_data.get("spdx_id")
    if spdx_id != "MIT":
        fail(f"{lib_name}: license must be MIT (detected: {spdx_id or 'unknown'})")


def main() -> None:
    args = parse_args()
    token_value = os.environ.get("GITHUB_TOKEN")

    if not LIBRARIES_DIR.exists():
        fail(f"libraries directory not found: {LIBRARIES_DIR}")

    library_files = sorted(LIBRARIES_DIR.rglob("*.json"))
    if not library_files:
        fail("no library files found under libraries/")

    seen_names: set[str] = set()
    for lib_path in library_files:
        lib_name = lib_path.stem
        if not NAME_RE.match(lib_name):
            fail(f"invalid library filename: {lib_path}")
        if lib_name in seen_names:
            fail(f"duplicate library detected by filename: {lib_name}")
        seen_names.add(lib_name)
        validate_library_file(lib_path, args.offline, token_value)

    mode = "offline" if args.offline else "online"
    print(f"✅ Registry is valid ({len(library_files)} libraries, {mode} checks)")


if __name__ == "__main__":
    main()
