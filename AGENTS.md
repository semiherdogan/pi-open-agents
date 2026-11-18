# Agent instructions

- Run tests with `scripts/test-isolated.sh`. It unsets inherited `PI_OPEN_AGENTS_*` env vars, which a parent pi process exports and which break tests.
- Typecheck with `npm run typecheck`.
- This is a personal fork synced periodically from upstream andrea-tomassi/pi-open-agents:
  - Put new behavior in new files.
  - Touch upstream files only with minimal hook calls.
  - Never rename or restructure upstream files.
- Permission-policy work lives in `src/permission/` (`loader.ts`, `resolver.ts`, more to come) with tests in `test/permission-*.test.ts`.
- The permission policy design (formats, precedence, delegation, limitations) is documented in `PERMISSIONS.md`.
- Profile work lives in `src/profile/` with tests in `test/profile-*.test.ts`; the design is documented in `PROFILES.md`.
- Do not use the em dash character in code, comments, or docs.

## Upstream sync

- `.github/workflows/upstream-sync.yml` runs weekly (and on manual dispatch) in three jobs: `merge` (git only, write token), `checks` (upstream code, read-only token), `report`. A clean merge pushes `sync/upstream` and opens or updates a PR into `main`.
- Merge the sync PR with a merge commit (not squash or rebase). Otherwise upstream never becomes an ancestor of `main` and every run opens a new no-op PR.
- On conflict, or when upstream changes `.github/workflows/*` without `SYNC_TOKEN`, nothing is pushed: the run ends red and one open issue "Upstream sync needs a local merge" carries the recipe (`git merge upstream/main` on `main`, tests, typecheck, push, close the issue). If Issues are disabled, the same report goes to the run's step summary instead.
- Keep conflicts small: new files first, minimal hooks in upstream files, no renames or restructuring. Leave `.github/workflows/publish.yml` in place (avoids modify/delete conflicts).
- Setup: enable Actions and this workflow in the fork's Actions tab (scheduled workflows are off on forks by default, and GitHub disables them after 60 days without repository activity), and enable "Allow GitHub Actions to create and approve pull requests". Also enable Issues (Settings > General > Features) to get the conflict report as an issue.
- Optional: secret `SYNC_TOKEN` (fine-grained PAT, this repo only, Contents, Pull requests and Workflows read/write) so upstream workflow changes sync automatically. Upstream workflows are never run automatically on the sync branch (the merge commit carries `[skip ci]`), so review the PR before merging.

## Pi version bump

- The three devDependencies `@earendil-works/pi-ai`, `pi-coding-agent` and `pi-tui` stay pinned to one identical exact version, never a range: `pi-coding-agent@X` depends on exactly `pi-ai@X` and `pi-tui@X`, so any mismatch installs nested duplicate copies that break typecheck.
- After a pi update run `scripts/bump-pi.sh [version]`; without an argument it takes the active version from `~/Library/Application Support/PiBoard/runtime/pi/current.json`, then pins, installs, fails on duplicate copies and runs typecheck and tests.
