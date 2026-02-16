<div align="center">
    <img src="images/logo.svg" alt="Coi Registry Logo" width="265"/>

# Coi Package Registry

Community package index for Coi.

</div>

If you want to create a new package first, see Getting Started:

- [Create a package (Coi Getting Started)](https://github.com/io-eric/coi/blob/main/docs/getting-started.md)

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

1. Copy `coi/templates/pkg/registry-entry.json` from the compiler repo
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
- `compiler-drop.min`: optimistic minimum supported compiler drop
- `compiler-drop.tested-on`: compiler drop actually tested
- `source`: optional commit/sha256 for pinning
- `releasedAt`: release date

## Validate locally

Offline (no GitHub API calls):

```bash
python3 scripts/validate_registry.py --offline
```

Online (same as CI):

```bash
python3 scripts/validate_registry.py
```
