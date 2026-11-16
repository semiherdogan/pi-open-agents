/**
 * `/permissions init`: creates the project policy file from the starter
 * template and never overwrites an existing one. Every test runs in a tmp box.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PERMISSIONS_COMMAND, registerPermissionCommands, SUBCOMMAND } from "../src/permission/commands.ts";
import { INIT_STATUS, initProjectPolicy, PROJECT_POLICY_TEMPLATE } from "../src/permission/init.ts";
import { loadProjectPolicy, POLICY_FILE_NAME, POLICY_FILE_STATUS, POLICY_VERSION, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const LEVEL_INFO = "info";
const LEVEL_WARNING = "warning";
const LEVEL_ERROR = "error";
const STRICT_ON = /Strict mode is now on/;
const UTF8 = "utf-8";

interface Box {
  cwd: string;
  home: string;
  agentDir: string;
}

interface Notice {
  text: string;
  level: string;
}

type CommandSpec = {
  handler: (args: string, ctx: unknown) => Promise<void>;
  getArgumentCompletions?: (prefix: string) => { value: string }[] | null;
};

// The box has no `.pi` dir: init must create it.
function withBox(fn: (box: Box) => Promise<void> | void): () => Promise<void> {
  return async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-init-")));
    try {
      const home = join(root, "home");
      const box = { cwd: join(root, "proj"), home, agentDir: join(home, ".pi", "agent") };
      for (const dir of [box.cwd, box.agentDir]) mkdirSync(dir, { recursive: true });
      await fn(box);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
}

function projectFile(box: Box): string {
  return join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME);
}

function harness(box: Box, idle = true) {
  const commands = new Map<string, CommandSpec>();
  const notices: Notice[] = [];
  const pi = {
    registerCommand: (name: string, spec: CommandSpec) => commands.set(name, spec),
    getActiveTools: () => [],
  };
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  registerPermissionCommands(pi as never, { runtime, resolveAgent: () => undefined, getAgents: () => [], inheritedRules: () => [], env: {} });
  const ctx = {
    cwd: box.cwd,
    hasUI: true,
    isIdle: () => idle,
    ui: { notify: (text: string, level: string) => notices.push({ text, level }) },
  };
  const run = async (args: string): Promise<Notice> => {
    const spec = commands.get(PERMISSIONS_COMMAND);
    assert.ok(spec, "command registered");
    await spec.handler(args, ctx);
    const last = notices.at(-1);
    assert.ok(last);
    return last;
  };
  return { run, commands };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

test("init: creates the project file from the template and loads it", withBox(async (box) => {
  const h = harness(box);
  const { text, level } = await h.run(SUBCOMMAND.init);
  assert.equal(level, LEVEL_INFO);
  assert.ok(text.includes(`Created ${projectFile(box)}`));
  assert.match(text, STRICT_ON);
  assert.deepEqual(JSON.parse(readFileSync(projectFile(box), UTF8)), PROJECT_POLICY_TEMPLATE);
  assert.equal(loadProjectPolicy(box.cwd).status, POLICY_FILE_STATUS.loaded);
  const source = await h.run(SUBCOMMAND.source);
  assert.ok(source.text.includes(`Project policy: ${projectFile(box)}: ${POLICY_FILE_STATUS.loaded}`));
}));

test("init: an existing file is never overwritten, even an invalid one", withBox(async (box) => {
  const broken = "{ not json";
  mkdirSync(join(box.cwd, PROJECT_POLICY_DIR));
  writeFileSync(projectFile(box), broken);
  const { text, level } = await harness(box).run(SUBCOMMAND.init);
  assert.equal(level, LEVEL_WARNING);
  assert.match(text, /already exists; nothing was written/);
  assert.equal(readFileSync(projectFile(box), UTF8), broken);
}));

test("init: with a user policy strict mode was already on and is not announced", withBox(async (box) => {
  writeFileSync(join(box.agentDir, POLICY_FILE_NAME), JSON.stringify({ version: POLICY_VERSION }));
  const { text, level } = await harness(box).run(SUBCOMMAND.init);
  assert.equal(level, LEVEL_INFO);
  assert.ok(text.includes(`Created ${projectFile(box)}`));
  assert.doesNotMatch(text, STRICT_ON);
}));

test("init: during a run the file is created and applies from the next run", withBox(async (box) => {
  const { text, level } = await harness(box, false).run(SUBCOMMAND.init);
  assert.equal(level, LEVEL_INFO);
  assert.ok(existsSync(projectFile(box)));
  assert.match(text, /applies from the next run/);
  assert.doesNotMatch(text, /Reloaded/);
}));

test("init: a failure to create the file is an error", withBox(async (box) => {
  // `.pi` as a regular file: the policy dir cannot be created.
  writeFileSync(join(box.cwd, PROJECT_POLICY_DIR), "");
  const { text, level } = await harness(box).run(SUBCOMMAND.init);
  assert.equal(level, LEVEL_ERROR);
  assert.ok(text.startsWith(`Could not create ${projectFile(box)}`));
}));

test("initProjectPolicy: created first, exists afterwards", withBox((box) => {
  assert.deepEqual(initProjectPolicy(box.cwd), { path: projectFile(box), status: INIT_STATUS.created });
  assert.deepEqual(initProjectPolicy(box.cwd), { path: projectFile(box), status: INIT_STATUS.exists });
}));

test("init: offered as a completion", withBox((box) => {
  const complete = harness(box).commands.get(PERMISSIONS_COMMAND)?.getArgumentCompletions;
  assert.ok(complete);
  assert.deepEqual(complete("in")?.map((item) => item.value), [SUBCOMMAND.init]);
}));
