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
├── packages/
│   ├── supabase.json  # Individual package file
│   └── ...
└── schema/
    └── package.schema.json   # Schema for package files
```

- `packages/**/*.json` — individual package files (discovered automatically)

## Add a package

1. Copy `coi/templates/pkg/package.json` from the compiler repo
2. Save as `packages/{your-package-name}.json` (or shard path like `packages/ab/{your-package-name}.json`)
3. Fill in `repository`, `description`, `keywords`
4. Run validation:

```bash
python3 scripts/validate_registry.py --offline
```

## Package file format

Schema: `schema/package.schema.json`

Each package file contains:

- `name`: package id (must match filename)
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
