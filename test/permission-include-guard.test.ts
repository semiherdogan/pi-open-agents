/**
 * Include guard: in strict mode an agent markdown `include:` is refused for
 * read-protected paths, invalid policy files and project-agent includes that
 * leave the project. Every test runs on real files in a tmp box.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import type { DiscoveryPath } from "../src/config/paths.ts";
import { loadAgents } from "../src/discovery/loader.ts";
import { createIncludeGuard } from "../src/permission/include-guard.ts";
import { POLICY_FILE_NAME, POLICY_VERSION } from "../src/permission/loader.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";
import { SNAPSHOT_STATUS } from "../src/permission/policy-snapshot.ts";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const SECRET = "TOP-SECRET";
const SHARED = "shared rules";
const PROJECT_AGENT = "proj";
const GLOBAL_AGENT = "glob";
// Relative to <cwd>/.pi/agents: two levels up is the project root, three is outside it.
const INSIDE_PROJECT = "../../notes.md";
const OUTSIDE_PROJECT = "../../../outside.txt";
const LINK_IN_PROJECT = "../../link.txt";
const PROJECT_SECRET = "../../secrets/token.txt";
// Relative to <agentDir>/agents: three levels up is the home dir.
const HOME_SECRET = "../../../secrets/key.txt";
const HOME_SHARED = "../../../shared/rules.md";
// Relative to the project root, where the nested fragment lives.
const NESTED_OUTSIDE = "../outside.txt";
const SNAPSHOT_REASON = "policy snapshot is unreadable";

interface Box {
  root: string;
  cwd: string;
  home: string;
  agentDir: string;
}

function withBox(fn: (box: Box) => Promise<void>): () => Promise<void> {
  return async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-inc-")));
    try {
      const home = join(root, "home");
      const box = { root, cwd: join(root, "proj"), home, agentDir: join(home, ".pi", "agent") };
      for (const dir of [box.cwd, box.agentDir]) mkdirSync(dir, { recursive: true });
      await fn(box);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
}

function put(filePath: string, content: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, content);
}

function agentBody(name: string, include: string): string {
  return `---\nname: ${name}\nmode: subagent\n---\nIntro\ninclude: ${include}\nOutro`;
}

function projectAgent(box: Box, include: string): void {
  put(join(box.cwd, ".pi", "agents", `${PROJECT_AGENT}.md`), agentBody(PROJECT_AGENT, include));
}

function globalAgent(box: Box, include: string): void {
  put(join(box.agentDir, "agents", `${GLOBAL_AGENT}.md`), agentBody(GLOBAL_AGENT, include));
}

function writeUserPolicy(box: Box, body: Record<string, unknown> = {}): void {
  put(join(box.agentDir, POLICY_FILE_NAME), JSON.stringify({ version: POLICY_VERSION, ...body }));
}

function resolvedPrompt(content: string): string {
  return `Intro\n${content}\nOutro`;
}

function literalPrompt(include: string): string {
  return `Intro\ninclude: ${include}\nOutro`;
}

/** Loads the box's agents through the guard; returns prompts by agent name and the stderr warnings. */
async function load(
  box: Box,
  runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home }),
): Promise<{ prompts: Map<string, string>; warnings: string[] }> {
  // Explicit paths: auto-detection would also scan the real OpenCode config dirs.
  const paths: DiscoveryPath[] = [
    { dir: join(box.agentDir, "agents"), source: "global", family: "pi", subdirs: [""] },
    { dir: join(box.cwd, ".pi", "agents"), source: "project", family: "pi", subdirs: [""] },
  ];
  const warnings: string[] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "));
  };
  try {
    const result = await loadAgents({
      cwd: box.cwd,
      agentDir: box.agentDir,
      paths,
      includeGuard: createIncludeGuard(runtime, box.cwd),
    });
    return { prompts: new Map(result.agents.map((agent) => [agent.name, agent.prompt])), warnings };
  } finally {
    console.error = original;
  }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

test("include guard: without a policy file includes are not restricted", withBox(async (box) => {
  put(join(box.root, "outside.txt"), SECRET);
  projectAgent(box, OUTSIDE_PROJECT);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(PROJECT_AGENT), resolvedPrompt(SECRET));
  assert.deepEqual(warnings, []);
}));

test("include guard: a project agent cannot include a file outside its project", withBox(async (box) => {
  writeUserPolicy(box);
  put(join(box.root, "outside.txt"), SECRET);
  projectAgent(box, OUTSIDE_PROJECT);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(PROJECT_AGENT), literalPrompt(OUTSIDE_PROJECT));
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /outside the project/);
}));

test("include guard: a project agent includes files inside its project", withBox(async (box) => {
  writeUserPolicy(box);
  put(join(box.cwd, "notes.md"), SHARED);
  projectAgent(box, INSIDE_PROJECT);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(PROJECT_AGENT), resolvedPrompt(SHARED));
  assert.deepEqual(warnings, []);
}));

test("include guard: a symlink inside the project cannot point out of it", withBox(async (box) => {
  writeUserPolicy(box);
  put(join(box.root, "outside.txt"), SECRET);
  symlinkSync(join(box.root, "outside.txt"), join(box.cwd, "link.txt"));
  projectAgent(box, LINK_IN_PROJECT);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(PROJECT_AGENT), literalPrompt(LINK_IN_PROJECT));
  assert.match(warnings[0], /outside the project/);
}));

test("include guard: alwaysDeny.paths blocks an include, also for a global agent", withBox(async (box) => {
  writeUserPolicy(box, { alwaysDeny: { paths: ["~/secrets/**"] } });
  put(join(box.home, "secrets", "key.txt"), SECRET);
  globalAgent(box, HOME_SECRET);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(GLOBAL_AGENT), literalPrompt(HOME_SECRET));
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /read-protected/);
}));

test("include guard: a global agent includes unprotected files outside its directory", withBox(async (box) => {
  writeUserPolicy(box, { alwaysDeny: { paths: ["~/secrets/**"] } });
  put(join(box.home, "shared", "rules.md"), SHARED);
  globalAgent(box, HOME_SHARED);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(GLOBAL_AGENT), resolvedPrompt(SHARED));
  assert.deepEqual(warnings, []);
}));

test("include guard: a project-relative alwaysDeny.paths entry blocks an include inside the project", withBox(async (box) => {
  writeUserPolicy(box, { alwaysDeny: { paths: ["secrets/**"] } });
  put(join(box.cwd, "secrets", "token.txt"), SECRET);
  projectAgent(box, PROJECT_SECRET);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(PROJECT_AGENT), literalPrompt(PROJECT_SECRET));
  assert.match(warnings[0], /read-protected/);
}));

test("include guard: an invalid policy file blocks every include", withBox(async (box) => {
  put(join(box.agentDir, POLICY_FILE_NAME), "{ not json");
  put(join(box.cwd, "notes.md"), SHARED);
  projectAgent(box, INSIDE_PROJECT);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(PROJECT_AGENT), literalPrompt(INSIDE_PROJECT));
  assert.match(warnings[0], /invalid policy file/);
}));

test("include guard: a nested include is checked too", withBox(async (box) => {
  writeUserPolicy(box);
  put(join(box.root, "outside.txt"), SECRET);
  put(join(box.cwd, "notes.md"), `Before\ninclude: ${NESTED_OUTSIDE}\nAfter`);
  projectAgent(box, INSIDE_PROJECT);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(PROJECT_AGENT), resolvedPrompt(`Before\ninclude: ${NESTED_OUTSIDE}\nAfter`));
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /outside the project/);
}));

test("include guard: read in alwaysDeny.tools blocks every include", withBox(async (box) => {
  writeUserPolicy(box, { alwaysDeny: { tools: ["read"] } });
  put(join(box.cwd, "notes.md"), SHARED);
  projectAgent(box, INSIDE_PROJECT);
  const { prompts, warnings } = await load(box);
  assert.equal(prompts.get(PROJECT_AGENT), literalPrompt(INSIDE_PROJECT));
  assert.match(warnings[0], /read-protected/);
}));

test("include guard: an unreadable parent snapshot blocks every include", withBox(async (box) => {
  put(join(box.cwd, "notes.md"), SHARED);
  projectAgent(box, INSIDE_PROJECT);
  const runtime = new PolicyRuntime({
    agentDir: box.agentDir,
    home: box.home,
    received: { status: SNAPSHOT_STATUS.invalid, reason: SNAPSHOT_REASON },
  });
  const { prompts, warnings } = await load(box, runtime);
  assert.equal(prompts.get(PROJECT_AGENT), literalPrompt(INSIDE_PROJECT));
  assert.ok(warnings[0].includes(SNAPSHOT_REASON));
}));
