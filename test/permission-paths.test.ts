/**
 * Tests for tool path normalization (mirrors pi's file-tool resolution) and
 * the candidate spellings the policy gate evaluates.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { normalizeToolPath, pathCandidates } from "../src/permission/paths.ts";

const CWD = "/work/proj";
const HOME = "/home/me";

test("paths: strips one leading @", () => {
  assert.equal(normalizeToolPath("@src/a.ts", CWD, HOME), "/work/proj/src/a.ts");
  assert.equal(normalizeToolPath("@@a", CWD, HOME), "/work/proj/@a");
});

test("paths: expands ~ and ~/", () => {
  assert.equal(normalizeToolPath("~", CWD, HOME), HOME);
  assert.equal(normalizeToolPath("~/x", CWD, HOME), "/home/me/x");
  assert.equal(normalizeToolPath("@~/x", CWD, HOME), "/home/me/x");
  assert.equal(normalizeToolPath("~x", CWD, HOME), "/work/proj/~x");
});

test("paths: converts file:// URLs", () => {
  const url = pathToFileURL("/etc/some file").href;
  assert.equal(normalizeToolPath(url, CWD, HOME), "/etc/some file");
});

test("paths: unicode spaces become plain spaces", () => {
  assert.equal(normalizeToolPath("a\u00A0b\u202Fc\u3000d", CWD, HOME), "/work/proj/a b c d");
});

test("paths: relative with .. resolves lexically and keeps in-cwd relative forms", () => {
  assert.equal(normalizeToolPath("src/../.pi/x", CWD, HOME), "/work/proj/.pi/x");
  const identity = (p: string) => p;
  assert.deepEqual(pathCandidates("src/../.pi/x", CWD, { home: HOME, realpath: identity }), [
    "/work/proj/.pi/x",
    ".pi/x",
  ]);
  assert.deepEqual(pathCandidates("../other/x", CWD, { home: HOME, realpath: identity }), ["/work/other/x"]);
});

test("paths: symlinked cwd yields lexical and canonical spellings", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-paths-")));
  try {
    const real = join(root, "real");
    const link = join(root, "link");
    mkdirSync(join(real, "src"), { recursive: true });
    symlinkSync(real, link);
    assert.deepEqual(pathCandidates("src/a.ts", link, { home: HOME }), [
      join(link, "src/a.ts"),
      join(real, "src/a.ts"),
      "src/a.ts",
    ]);
    // Absolute real-path spelling still produces the relative form against the canonical cwd.
    assert.deepEqual(pathCandidates(join(real, "src/a.ts"), link, { home: HOME }), [
      join(real, "src/a.ts"),
      "src/a.ts",
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
