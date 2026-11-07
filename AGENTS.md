# Agent instructions

- Run tests with `scripts/test-isolated.sh`. It unsets inherited `PI_OPEN_AGENTS_*` env vars, which a parent pi process exports and which break tests.
- Typecheck with `npm run typecheck`.
- This is a personal fork synced periodically from upstream andrea-tomassi/pi-open-agents:
  - Put new behavior in new files.
  - Touch upstream files only with minimal hook calls.
  - Never rename or restructure upstream files.
- Permission-policy work lives in `src/permission/` (`loader.ts`, `resolver.ts`, more to come) with tests in `test/permission-*.test.ts`.
- Do not use the em dash character in code, comments, or docs.
