# Coi Library Registry

This repository stores the community library index for Coi libraries.

If you want to create a new library first, see Getting Started:

- [Create a library (Coi Getting Started)](https://github.com/io-eric/coi/blob/main/docs/getting-started.md#creating-a-library)

## Structure

```
registry/
├── libraries/
│   ├── lib-supabase.json  # Individual library file
│   └── ...
└── schema/
    └── library.schema.json   # Schema for library files
```

- `libraries/**/*.json` — individual library files (discovered automatically)

## Add a library

1. Copy `coi/templates/lib/registry-entry.json` from the compiler repo
2. Save as `libraries/{your-lib-name}.json` (or shard path like `libraries/ab/{your-lib-name}.json`)
3. Fill in `repository`, `description`, `keywords`
4. Run validation:

```bash
python3 scripts/validate_registry.py --offline
```

## Library file format

Schema: `schema/library.schema.json`

Each library file contains:

- `name`: package id (must match filename)
- `schema-version`: library entry format version
- `repository`: GitHub URL
- `releases`: array of version releases (newest first)
- `createdAt`: when library was first added

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
