# Release Checklist

## 1. Dependency Audit & Update

- [ ] Run `npm outdated` - check for outdated packages
- [ ] Run `npm audit` - check for security vulnerabilities
- [ ] Update critical dependencies:
  - [ ] `@modelcontextprotocol/sdk` - check [npm](https://www.npmjs.com/package/@modelcontextprotocol/sdk) for latest
  - [ ] `patchright` - browser automation
  - [ ] Other security-related packages
- [ ] Run `npm audit fix` if vulnerabilities found
- [ ] Test build after updates: `npm run build`

## 2. Documentation Updates

### README.md
- [ ] Update feature list if new features added
- [ ] Update configuration section if new env vars
- [ ] Update version badges/references
- [ ] Add any new usage examples
- [ ] Update comparison table if relevant

### SECURITY.md
- [ ] Document any security fixes
- [ ] Update security features list
- [ ] Add any new compliance features

### CHANGELOG.md (if exists)
- [ ] Add version entry with date
- [ ] List all changes: Added, Changed, Fixed, Security
- [ ] Credit contributors

### Other Docs
- [ ] Update `docs/` folder if applicable
- [ ] Update API documentation
- [ ] Update troubleshooting guide if bugs fixed

## 3. Package Metadata (npm visibility)

### package.json - Keep Updated!
- [ ] `description` - compelling, keyword-rich description
- [ ] `keywords` - comprehensive tags for discoverability
- [ ] `homepage` - links to GitHub
- [ ] `bugs` - issue tracker URL
- [ ] `repository` - GitHub repo URL

### What Shows on npm:
- README.md is displayed - make it count!
- Include badges (version, license, downloads)
- Clear installation instructions
- Feature highlights with examples
- Links to documentation

## 4. Pre-Release Verification

- [ ] Run `npm run build` - verify no TypeScript errors
- [ ] Run `npm test` (if tests exist)
- [ ] Manual test critical features if major changes

## 5. Version Bump

- [ ] Determine version type:
  - `patch` (2026.1.x) - bug fixes, dependency updates
  - `minor` (2026.x.0) - new features, non-breaking
  - `major` (x.0.0) - breaking changes
- [ ] Run `npm version patch|minor|major --no-git-tag-version`
- [ ] Commit: `git add . && git commit -m "chore: bump version to X.X.X"`

## 6. Publish

- [ ] Push to GitHub: `git push origin main`
- [ ] Publish to npm: `npm publish --access public`

## 7. GitHub Release (REQUIRED!)

**Don't skip this step!** GitHub releases are how users discover updates.

- [ ] Create GitHub release with detailed notes:
  ```bash
  gh release create vX.X.X --title "vX.X.X - Title" --notes "$(cat <<'EOF'
  ## What's New
  - Change 1
  - Change 2
  EOF
  )"
  ```
- [ ] Verify release: `gh release list --limit 3`

### Release Notes Template
```markdown
## What's New in vX.X.X

### Features
- Feature 1 description
- Feature 2 description

### Bug Fixes
- Fixed issue with X
- Resolved Y problem

### Security
- Updated dependencies
- Fixed vulnerability in Z

### Dependencies
- `@modelcontextprotocol/sdk` updated to X.X.X

### Full Changelog
https://github.com/OhJayGee/notebooklm-mcp-secure/compare/vPREV...vX.X.X
```

## 8. Post-Release Verification & Promotion

### Verify Publication
- [ ] npm: `npm view @ohjaygee/notebooklm-mcp-secure version`
- [ ] GitHub: Check release page exists
- [ ] npm page: https://www.npmjs.com/package/@ohjaygee/notebooklm-mcp-secure

### Promote the Release
- [ ] Update any dependent projects
- [ ] Post to relevant communities if major release
- [ ] Update any blog/documentation sites

---

## Quick Commands

```bash
# Full dependency check
npm outdated && npm audit

# Update specific package
npm install @modelcontextprotocol/sdk@latest --save

# Check what npm will publish
npm pack --dry-run

# View npm page info
npm view @ohjaygee/notebooklm-mcp-secure

# Full release flow
npm run build && \
npm version patch --no-git-tag-version && \
git add . && \
git commit -m "chore: release vX.X.X" && \
git push origin main && \
npm publish --access public && \
gh release create vX.X.X --generate-notes
```

---

## npm Page Optimization Tips

Your npm page is your storefront - make it shine!

1. **README First Impression**: First 200 chars matter most
2. **Badges**: Show build status, version, downloads, license
3. **Clear Value Prop**: What problem does this solve?
4. **Quick Start**: 3-step installation to first result
5. **Feature List**: Bullet points, scannable
6. **Screenshots/GIFs**: If applicable
7. **Links**: Docs, issues, discussions, changelog

Remember: Every release is a chance to show active development!
