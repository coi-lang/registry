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
PACKAGES_DIR = ROOT / "packages"

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SCOPED_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}/[a-z0-9][a-z0-9._-]{0,62}$")
NAME_SEGMENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
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
    parser.add_argument(
        "--promote-incoming",
        action="store_true",
        help="Move incoming/*.json files to packages/<scope>/<name>.json",
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


def validate_release(
    release: dict,
    package_name: str,
    rel_idx: int,
    seen_versions: set[str],
    offline: bool,
) -> None:
    """Validate a single release entry within a package."""
    required = ["version", "compiler", "releasedAt", "source"]
    for key in required:
        if key not in release:
            fail(f"{package_name}: release[{rel_idx}] missing '{key}'")

    version = release["version"]
    if not isinstance(version, str) or not VERSION_RE.match(version):
        fail(f"{package_name}: release[{rel_idx}].version must be semver (e.g. 1.0.0)")
    if version in seen_versions:
        fail(f"{package_name}: duplicate release version: {version}")
    seen_versions.add(version)

    released_at = release.get("releasedAt")
    if not isinstance(released_at, str) or not DATE_RE.match(released_at):
        fail(f"{package_name}: release[{rel_idx}].releasedAt must be YYYY-MM-DD")

    compiler = release.get("compiler")
    if not isinstance(compiler, dict):
        fail(f"{package_name}: release[{rel_idx}].compiler must be an object")

    pond = compiler.get("pond")
    min_drop = compiler.get("min-drop")

    if not isinstance(pond, int) or pond < 0:
        fail(f"{package_name}: release[{rel_idx}].compiler.pond must be an integer >= 0")

    if not isinstance(min_drop, int) or min_drop < 1:
        fail(f"{package_name}: release[{rel_idx}].compiler.min-drop must be >= 1")

    source = release.get("source")
    if not isinstance(source, dict):
        fail(f"{package_name}: release[{rel_idx}].source must be an object")

    commit = source.get("commit")
    sha256 = source.get("sha256")

    if not isinstance(commit, str):
        fail(f"{package_name}: release[{rel_idx}].source.commit must be a string")
    if not isinstance(sha256, str):
        fail(f"{package_name}: release[{rel_idx}].source.sha256 must be a string")

    if not offline:
        if not COMMIT_RE.match(commit):
            fail(f"{package_name}: release[{rel_idx}].source.commit must be a 40-char hex string")
        if not SHA256_RE.match(sha256):
            fail(f"{package_name}: release[{rel_idx}].source.sha256 must be a 64-char hex string")


def validate_package_file(package_path: Path, offline: bool, token: str | None) -> None:
    """Validate an individual package file under packages/**/*.json."""
    package_name = package_path.relative_to(PACKAGES_DIR).with_suffix("").as_posix()

    try:
        data = json.loads(package_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"{package_name}: invalid JSON: {e}")

    if not isinstance(data, dict):
        fail(f"{package_name}: root must be a JSON object")

    required = ["name", "schema-version", "repository", "releases", "createdAt"]
    for key in required:
        if key not in data:
            fail(f"{package_name}: missing '{key}'")

    # Name must match package path under packages/ (scope/name)
    if data["name"] != package_name:
        fail(f"{package_name}: name field '{data['name']}' does not match package path")

    schema_version = data.get("schema-version")
    if not isinstance(schema_version, int) or schema_version < 1:
        fail(f"{package_name}: schema-version must be >= 1")

    created_at = data.get("createdAt")
    if not isinstance(created_at, str) or not DATE_RE.match(created_at):
        fail(f"{package_name}: createdAt must be YYYY-MM-DD")

    repository = data["repository"]
    if not isinstance(repository, str):
        fail(f"{package_name}: repository must be a string")
    match = GITHUB_REPO_RE.match(repository)
    if not match:
        fail(f"{package_name}: repository must be a GitHub URL like https://github.com/owner/repo")
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]

    releases = data.get("releases")
    if not isinstance(releases, list) or len(releases) == 0:
        fail(f"{package_name}: releases must be a non-empty array")

    seen_versions: set[str] = set()
    for idx, release in enumerate(releases):
        if not isinstance(release, dict):
            fail(f"{package_name}: release[{idx}] must be an object")
        validate_release(release, package_name, idx, seen_versions, offline)

    if offline:
        return

    # Online checks: verify repository exists and has MIT license
    try:
        repo_meta = http_json(f"https://api.github.com/repos/{owner}/{repo}", token)
    except urllib.error.HTTPError as err:
        fail(f"{package_name}: GitHub repo lookup failed ({err.code}) for {owner}/{repo}")
    except Exception as err:
        fail(f"{package_name}: GitHub repo lookup failed: {err}")

    license_data = repo_meta.get("license") or {}
    spdx_id = license_data.get("spdx_id")
    if spdx_id != "MIT":
        fail(f"{package_name}: license must be MIT (detected: {spdx_id or 'unknown'})")


INCOMING_DIR = ROOT / "incoming"


def get_tarball_sha256(owner: str, repo: str, commit: str, token: str | None) -> str | None:
    """Download tarball and compute SHA256 hash."""
    import hashlib
    import tempfile

    url = f"https://github.com/{owner}/{repo}/archive/{commit}.tar.gz"
    headers = {"User-Agent": "coi-registry-validator"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as response:
            with tempfile.NamedTemporaryFile(delete=True) as tmp:
                data = response.read()
                tmp.write(data)
                tmp.flush()
                return hashlib.sha256(data).hexdigest()
    except Exception as e:
        print(f"  ⚠ Could not fetch tarball: {e}")
        return None


def promote_incoming(offline: bool, token: str | None) -> int:
    """Move incoming/**/*.json files to packages/<scope>/<name>.json.

    Scope is derived from repository owner/org; package name segment is preserved.
    """
    if not INCOMING_DIR.exists():
        print("ℹ No incoming/ directory found, nothing to promote.")
        return 0

    incoming_files = list(INCOMING_DIR.rglob("*.json"))
    if not incoming_files:
        print("ℹ No files in incoming/, nothing to promote.")
        return 0

    promoted = 0
    for file_path in incoming_files:
        print(f"Processing: {file_path.relative_to(ROOT)}")

        try:
            content = file_path.read_text(encoding="utf-8")
            data = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"  ❌ Invalid JSON: {e}")
            continue

        if not isinstance(data, dict):
            print(f"  ❌ Root must be a JSON object")
            continue

        repository = data.get("repository", "")
        match = GITHUB_REPO_RE.match(repository)
        if not match:
            print(f"  ❌ Invalid repository URL: '{repository}'")
            print(f"     Must be https://github.com/<owner>/<repo>")
            continue

        owner = match.group(1).lower()
        repo_name = match.group(2).lower()
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        # Auto-set only the scope from repository owner/org.
        # Keep package name segment from existing name field, supporting either:
        # - "my-package"
        # - "anyscope/my-package"
        existing_name = data.get("name", "")
        if not isinstance(existing_name, str) or not existing_name.strip():
            print("  ❌ name must be set before promotion")
            print("     Example: my-package")
            continue

        existing_name = existing_name.strip().lower()
        pkg_name = existing_name.split("/", 1)[1] if "/" in existing_name else existing_name
        if not NAME_SEGMENT_RE.match(pkg_name):
            print(f"  ❌ Invalid package name segment: '{pkg_name}'")
            print("     Must be lowercase and match: [a-z0-9][a-z0-9._-]{0,62}")
            continue

        canonical_name = f"{owner}/{pkg_name}"
        data["name"] = canonical_name
        print(f"  ✓ Scope auto-set: {existing_name} → {canonical_name}")

        # Handle commit/sha256 placeholders (online mode only)
        releases = data.get("releases", [])
        if releases and not offline:
            for rel in releases:
                source = rel.get("source", {})
                commit = source.get("commit", "")
                sha256 = source.get("sha256", "")

                # If commit is still a placeholder, try to get latest commit
                if commit.startswith("__") or not COMMIT_RE.match(commit):
                    try:
                        commits_data = http_json(
                            f"https://api.github.com/repos/{owner}/{repo_name}/commits?per_page=1",
                            token
                        )
                        if commits_data:
                            source["commit"] = commits_data[0]["sha"]
                            print(f"  ✓ Auto-filled commit: {source['commit'][:12]}...")
                    except Exception as e:
                        print(f"  ⚠ Could not fetch latest commit: {e}")

                # If sha256 is still a placeholder and we have a valid commit, compute it
                commit = source.get("commit", "")
                if (sha256.startswith("__") or not SHA256_RE.match(sha256)) and COMMIT_RE.match(commit):
                    computed_sha = get_tarball_sha256(owner, repo_name, commit, token)
                    if computed_sha:
                        source["sha256"] = computed_sha
                        print(f"  ✓ Auto-filled sha256: {computed_sha[:16]}...")

        # Validate the canonical name
        name = data.get("name", "")
        if not SCOPED_NAME_RE.match(name):
            print(f"  ❌ Invalid package name: '{name}' (must be scope/name format)")
            continue

        # Build destination path
        scope, pkg_name = name.split("/", 1)
        dest_dir = PACKAGES_DIR / scope
        dest_path = dest_dir / f"{pkg_name}.json"

        if dest_path.exists():
            print(f"  ⚠ Destination already exists: {dest_path.relative_to(ROOT)}")
            print(f"    Skipping (delete existing file to re-promote)")
            continue

        # Create scope directory if needed
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Write the processed file
        with open(dest_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

        # Remove the incoming file
        file_path.unlink()

        # Clean up empty parent directories in incoming/
        parent = file_path.parent
        while parent != INCOMING_DIR:
            if not any(parent.iterdir()):
                parent.rmdir()
            parent = parent.parent

        print(f"  ✓ Promoted to: {dest_path.relative_to(ROOT)}")
        promoted += 1

    return promoted


def main() -> None:
    args = parse_args()
    token_value = os.environ.get("GITHUB_TOKEN")

    # Handle --promote-incoming first
    if args.promote_incoming:
        promoted = promote_incoming(args.offline, token_value)
        if promoted > 0:
            print(f"✅ Promoted {promoted} package(s) from incoming/")
        print()

    if not PACKAGES_DIR.exists():
        fail(f"packages directory not found: {PACKAGES_DIR}")

    package_files = sorted(PACKAGES_DIR.rglob("*.json"))
    if not package_files:
        print("ℹ No package files found under packages/ (registry is empty)")
        return

    seen_names: set[str] = set()
    for package_path in package_files:
        package_name = package_path.relative_to(PACKAGES_DIR).with_suffix("").as_posix()
        if not SCOPED_NAME_RE.match(package_name):
            fail(f"invalid package filename: {package_path}")
        if package_name in seen_names:
            fail(f"duplicate package detected by path: {package_name}")
        seen_names.add(package_name)
        validate_package_file(package_path, args.offline, token_value)

    mode = "offline" if args.offline else "online"
    print(f"✅ Registry is valid ({len(package_files)} packages, {mode} checks)")


if __name__ == "__main__":
    main()
