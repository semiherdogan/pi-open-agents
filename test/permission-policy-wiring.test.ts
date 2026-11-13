/**
 * index.ts wiring: the legacy gate decides without policy files; with a policy
 * file present it stands down and the policy gate decides.
 *
 * Drives the real factory with a fake ExtensionAPI, like reload.test.ts.
 * PI_CODING_AGENT_DIR points getAgentDir() at a tmp dir, never ~/.pi/agent;
 * HOME and USERPROFILE point at a tmp dir so home discovery never reads the real home.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { POLICY_FILE_NAME, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";

type PiOpenAgents = typeof import("../src/index.ts").default;
let piOpenAgents: PiOpenAgents | undefined;
try {
  ({ default: piOpenAgents } = await import("../src/index.ts"));
} catch {
  piOpenAgents = undefined;
}

const run = piOpenAgents ? test : test.skip;

const AGENT_DIR_ENV = "PI_CODING_AGENT_DIR";
const HOME_ENVS = ["HOME", "USERPROFILE"];
const AGENT_NAME = "wiring-agent";
const LEGACY_DENY = /^Permission denied: agent rules deny/;
const POLICY_DENY = /^Permission denied\.\nOperation:/;
const NO_AGENT_FLAG = null;
const DEPTH_ENV = "PI_OPEN_AGENTS_DEPTH";
const CHILD_DEPTH = "1";
const UNLISTED_BASH = /unlisted bash operations are denied/;

type Handler = (event: unknown, ctx: unknown) => Promise<unknown> | unknown;
type Block = { block: true; reason: string } | undefined;

function makeWorkspace() {
  const root = mkdtempSync(join(tmpdir(), "poa-wiring-"));
  const agentsDir = join(root, PROJECT_POLICY_DIR, "agents");
  mkdirSync(agentsDir, { recursive: true });
  const agentDir = join(root, "agent-home");
  mkdirSync(join(agentDir, "agents"), { recursive: true });
  const home = join(root, "user-home");
  mkdirSync(home, { recursive: true });
  const overrides: Record<string, string> = { [AGENT_DIR_ENV]: agentDir };
  for (const name of HOME_ENVS) overrides[name] = home;
  const previous = new Map(Object.keys(overrides).map((name) => [name, process.env[name]]));
  Object.assign(process.env, overrides);
  writeFileSync(
    join(agentsDir, `${AGENT_NAME}.agent.md`),
    `---\nname: ${AGENT_NAME}\nmode: primary\ndescription: wiring\npermission:\n  bash:\n    "rm *": deny\n---\nBody.\n`,
  );
  return {
    root,
    writeProjectPolicy: () =>
      writeFileSync(join(root, PROJECT_POLICY_DIR, POLICY_FILE_NAME), JSON.stringify({ version: 1, agents: {} })),
    dispose: () => {
      rmSync(root, { recursive: true, force: true });
      for (const [name, value] of previous) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    },
  };
}

async function startSession(cwd: string, agentFlag: string | null = AGENT_NAME) {
  assert.ok(piOpenAgents, "factory available");
  const handlers = new Map<string, Handler[]>();
  const builtinTools = ["read", "bash", "edit", "write", "grep", "find", "ls"];
  const flags = new Map<string, string>(agentFlag === NO_AGENT_FLAG ? [] : [["agent", agentFlag]]);
  const pi = {
    on: (event: string, handler: Handler) => {
      handlers.set(event, [...(handlers.get(event) ?? []), handler]);
      return () => {};
    },
    registerFlag: () => {},
    registerCommand: () => {},
    registerTool: () => {},
    registerShortcut: () => {},
    getFlag: (name: string) => flags.get(name),
    getAllTools: () => builtinTools.map((name) => ({ name, sourceInfo: { source: "builtin" } })),
    getActiveTools: () => builtinTools.slice(),
    setActiveTools: () => {},
    getThinkingLevel: () => "off",
    setThinkingLevel: () => {},
    setModel: async () => true,
    appendEntry: () => {},
  };
  const ctx = {
    cwd,
    model: undefined,
    mode: "tui",
    hasUI: false,
    ui: {
      notify: () => {},
      select: async () => undefined,
      theme: { bold: (s: string) => s, fg: (_c: string, s: string) => s },
      setWidget: () => {},
    },
    modelRegistry: { find: () => undefined, getAvailable: () => [] },
    sessionManager: { getEntries: () => [], getSessionFile: () => undefined, getLeafId: () => undefined },
  };
  piOpenAgents(pi as never);
  for (const handler of handlers.get("session_start") ?? []) await handler({ type: "session_start", reason: "startup" }, ctx);
  for (const handler of handlers.get("before_agent_start") ?? []) await handler({}, ctx);

  // pi stops at the first handler that blocks.
  return async (toolName: string, input: Record<string, unknown>): Promise<Block> => {
    for (const handler of handlers.get("tool_call") ?? []) {
      const result = (await handler({ toolName, input }, ctx)) as Block;
      if (result) return result;
    }
    return undefined;
  };
}

run("policy wiring: without policy files the legacy gate decides", async () => {
  const ws = makeWorkspace();
  try {
    const call = await startSession(ws.root);
    assert.equal(await call("bash", { command: "ls" }), undefined);
    assert.match((await call("bash", { command: "rm -rf x" }))?.reason ?? "", LEGACY_DENY);
  } finally {
    ws.dispose();
  }
});

run("policy wiring: with a project policy file the policy gate decides", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProjectPolicy();
    const call = await startSession(ws.root);
    const rm = await call("bash", { command: "rm -rf x" });
    assert.match(rm?.reason ?? "", POLICY_DENY);
    // Legacy allows unmatched bash; strict mode denies it by default.
    assert.match((await call("bash", { command: "ls" }))?.reason ?? "", /unlisted bash operations are denied/);
  } finally {
    ws.dispose();
  }
});

run("policy wiring: a primary session without an agent is not restricted by the policy", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProjectPolicy();
    const call = await startSession(ws.root, NO_AGENT_FLAG);
    assert.equal(await call("bash", { command: "ls" }), undefined);
    assert.equal(await call("bash", { command: "rm -rf x" }), undefined);
  } finally {
    ws.dispose();
  }
});

run("policy wiring: a subagent process without a resolvable agent stays under the policy", async () => {
  const ws = makeWorkspace();
  const previous = process.env[DEPTH_ENV];
  process.env[DEPTH_ENV] = CHILD_DEPTH;
  try {
    ws.writeProjectPolicy();
    const call = await startSession(ws.root, NO_AGENT_FLAG);
    assert.match((await call("bash", { command: "ls" }))?.reason ?? "", UNLISTED_BASH);
  } finally {
    if (previous === undefined) delete process.env[DEPTH_ENV];
    else process.env[DEPTH_ENV] = previous;
    ws.dispose();
  }
});
