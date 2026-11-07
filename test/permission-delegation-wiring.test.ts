/**
 * index.ts wiring in a child process: the subagent tool resolves the child's own
 * definition (allowedAgents applies when it delegates further), and an invalid
 * policy snapshot blocks every tool call.
 *
 * PI_CODING_AGENT_DIR, HOME and USERPROFILE point at tmp dirs; the real home is never read.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { POLICY_SNAPSHOT_ENV } from "../src/permission/policy-snapshot.ts";

type PiOpenAgents = typeof import("../src/index.ts").default;
let piOpenAgents: PiOpenAgents | undefined;
try {
  ({ default: piOpenAgents } = await import("../src/index.ts"));
} catch {
  piOpenAgents = undefined;
}

const run = piOpenAgents ? test : test.skip;

const CHILD_NAME = "lead";
type Handler = (event: unknown, ctx: unknown) => Promise<unknown> | unknown;
type Tool = { name: string; execute: (...args: unknown[]) => Promise<unknown> };

function agentFile(name: string, mode: string, extra = ""): string {
  return `---\nname: ${name}\nmode: ${mode}\ndescription: ${name}\n${extra}---\nBody.\n`;
}

async function startChild(env: Record<string, string>) {
  assert.ok(piOpenAgents);
  const root = mkdtempSync(join(tmpdir(), "poa-deleg-wiring-"));
  const agentsDir = join(root, PROJECT_POLICY_DIR, "agents");
  mkdirSync(agentsDir, { recursive: true });
  const agentDir = join(root, "agent-home");
  mkdirSync(join(agentDir, "agents"), { recursive: true });
  const home = join(root, "user-home");
  mkdirSync(home, { recursive: true });
  writeFileSync(join(agentsDir, `${CHILD_NAME}.agent.md`), agentFile(CHILD_NAME, "all", "allowedAgents: [helper]\n"));
  writeFileSync(join(agentsDir, "helper.agent.md"), agentFile("helper", "subagent"));
  writeFileSync(join(agentsDir, "other.agent.md"), agentFile("other", "subagent"));

  const overrides: Record<string, string> = {
    PI_CODING_AGENT_DIR: agentDir,
    HOME: home,
    USERPROFILE: home,
    PI_OPEN_AGENTS_DEPTH: "1",
    PI_OPEN_AGENTS_NAME: CHILD_NAME,
    ...env,
  };
  const previous = new Map(Object.keys(overrides).map((name) => [name, process.env[name]]));
  Object.assign(process.env, overrides);
  const restore = () => {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    rmSync(root, { recursive: true, force: true });
  };

  const handlers = new Map<string, Handler[]>();
  const tools: Tool[] = [];
  const builtinTools = ["read", "bash", "edit", "write", "grep", "find", "ls"];
  const pi = {
    on: (event: string, handler: Handler) => {
      handlers.set(event, [...(handlers.get(event) ?? []), handler]);
      return () => {};
    },
    registerFlag: () => {},
    registerCommand: () => {},
    registerTool: (tool: Tool) => tools.push(tool),
    registerShortcut: () => {},
    getFlag: () => undefined,
    getAllTools: () => builtinTools.map((name) => ({ name, sourceInfo: { source: "builtin" } })),
    getActiveTools: () => builtinTools.slice(),
    setActiveTools: () => {},
    getThinkingLevel: () => "off",
    setThinkingLevel: () => {},
    setModel: async () => true,
    appendEntry: () => {},
  };
  const ctx = {
    cwd: root,
    hasUI: false,
    ui: { notify: () => {}, select: async () => undefined, setWidget: () => {}, setStatus: () => {}, theme: { bold: (s: string) => s, fg: (_c: string, s: string) => s } },
    sessionManager: { getEntries: () => [], getSessionFile: () => undefined, getLeafId: () => undefined },
  };
  try {
    piOpenAgents(pi as never);
    for (const handler of handlers.get("session_start") ?? []) await handler({ type: "session_start", reason: "startup" }, ctx);
  } catch (error) {
    restore();
    throw error;
  }
  const callTool = async (toolName: string, input: Record<string, unknown>) => {
    for (const handler of handlers.get("tool_call") ?? []) {
      const result = (await handler({ toolName, input }, ctx)) as { block: true; reason: string } | undefined;
      if (result) return result;
    }
    return undefined;
  };
  return { tools, ctx, callTool, restore };
}

run("delegation wiring: a child delegating further is held to its own allowedAgents", async () => {
  const child = await startChild({});
  try {
    const tool = child.tools.find((t) => t.name === "subagent");
    assert.ok(tool, "subagent tool registered in the child");
    await assert.rejects(
      tool.execute("1", { agent: "other", task: "t" }, undefined, undefined, child.ctx),
      /Agent "lead" can only delegate to: helper/,
    );
  } finally {
    child.restore();
  }
});

run("delegation wiring: an invalid snapshot blocks every tool call in the child", async () => {
  const child = await startChild({ [POLICY_SNAPSHOT_ENV]: "{not json" });
  try {
    const blocked = await child.callTool("read", { path: "a.txt" });
    assert.match(blocked?.reason ?? "", new RegExp(`invalid ${POLICY_SNAPSHOT_ENV}`));
  } finally {
    child.restore();
  }
});
