<div align="center">
    <img src="images/logo.svg" alt="Coi Registry Logo" width="265"/>

# Coi Package Registry

Community package index for Coi.

</div>

If you want to create a new package first, see Getting Started:

- [Create a package (Coi Getting Started)](https://github.com/io-eric/coi/blob/main/docs/getting-started.md)
- [Coi Versioning (Pond & Drop)](https://github.com/io-eric/coi/blob/main/docs/versioning.md)

## Structure

```
registry/
├── incoming/
│   └── ...                  # Optional staging area (drop package.json here first)
├── packages/
│   ├── coi/
│   │   └── supabase.json  # Scoped package file (coi/supabase)
│   └── ...
└── schema/
    └── package.schema.json   # Schema for package files
```

- `packages/<scope>/<name>.json` — individual package files (discovered automatically)

## Add a package

Simplest workflow:

1. Copy your `package.json` into `incoming/` (any subfolder works, e.g. `incoming/my-pkg/package.json`)
2. Set `name` to just the package name (e.g. `my-pkg`)
3. Set the `repository` field to your GitHub repo URL
4. Run promotion:

```bash
python3 scripts/validate_registry.py --promote-incoming --offline
```

That's it! The script will:
- Auto-set only the scope from repository owner/org (`github.com/alice/my-pkg` → scope `alice`)
- Keep your package name unchanged (e.g. `my-lib` → `alice/my-lib`)
- Move the file to `packages/<owner>/<package-name>.json`

Then validate:

```bash
python3 scripts/validate_registry.py --offline
```

### Placeholder behavior

| Placeholder | Filled from | When |
|-------------|-------------|------|
| `__COMMIT_SHA__` | GitHub API (latest commit) | Online mode only |
| `__TARBALL_SHA256__` | Downloaded tarball hash | Online mode only |

## Package file format

Schema: `schema/package.schema.json`

Each package file contains:

- `name`: package id in `scope/name` format (must match `packages/<scope>/<name>.json` path)
- `schema-version`: package entry format version
- `repository`: GitHub URL
- `releases`: array of version releases (newest first)
- `createdAt`: when package was first added

Each release contains:

- `version`: semver (e.g. `1.0.0`, `0.2.1-beta`)
- `compiler.pond`: compiler contract version
- `compiler.min-drop`: optimistic minimum supported compiler drop within that pond
- `source.commit`: pinned git commit SHA (required)
- `source.sha256`: SHA256 hash of that commit tarball (required)
- `releasedAt`: release date

Pond vs Drop:

- Pond: the contract. If this number changes, syntax/core compatibility is broken.
- Drop: the velocity. Features/fixes/platform support are poured into the current pond.

## Validate locally

Offline (no GitHub API calls):

```bash
python3 scripts/validate_registry.py --offline
```

Online (same as CI):

```bash
python3 scripts/validate_registry.py
```
