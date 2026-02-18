## Package Submission

### Summary
- Package name:
- Repository URL:
- First release version:

### Checklist
- [ ] Added package metadata (you can stage as `incoming/**/package.json` first)
- [ ] Ran `python3 scripts/validate_registry.py --promote-incoming --offline` to move it to `packages/<scope>/<name>.json`
- [ ] `schema-version` is set
- [ ] `repository` points to the correct GitHub repo
- [ ] `compiler.pond` is set (compiler contract version)
- [ ] `compiler.min-drop` is set (minimum required drop in this pond)
- [ ] `releases` contains at least one release entry
- [ ] `createdAt` and `releasedAt` use `YYYY-MM-DD`
- [ ] Package repository license is MIT
- [ ] Ran `python3 scripts/validate_registry.py --offline` locally

### Notes (optional)
- Any extra context for reviewers
