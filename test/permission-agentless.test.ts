/**
 * A primary session without an active agent is exempt from the permission
 * policy (plain pi). Subagent processes are never exempt.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { AgentDefinition, PermissionConfig } from "../src/types.ts";
import { registerPermissionAwareness, SUMMARY_HEADER } from "../src/permission/awareness.ts";
import { PERMISSIONS_COMMAND, registerPermissionCommands, SUBCOMMAND } from "../src/permission/commands.ts";
import { createDelegationPlanner } from "../src/permission/delegation.ts";
import { POLICY_FILE_NAME, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { registerPolicyGate } from "../src/permission/policy-gate.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";
import { POLICY_SNAPSHOT_ENV, readPolicySnapshot, SNAPSHOT_STATUS } from "../src/permission/policy-snapshot.ts";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const ACTIVE_TOOLS = ["read", "bash", "edit", "write", "grep"];
const BASE_PROMPT = "You are pi.";
const WORKER = "worker";
const LEVEL_INFO = "info";
const CHILD_ENV = { PI_OPEN_AGENTS_DEPTH: "1" };
const EXEMPT_NOTE = /no agent is active/i;
const USER_POLICY = {
  version: 1,
  alwaysDeny: { gitWrite: true, paths: ["secrets/**"], tools: [], bash: [] },
  agents: { "*": { bash: { "git status": "allow" } } },
};

interface Box {
  root: string;
  cwd: string;
  home: string;
  agentDir: string;
}

/** A tmp box whose user policy file exists, so strict mode is on. */
function withBox(fn: (box: Box) => Promise<void> | void): () => Promise<void> {
  return async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-agentless-")));
    try {
      const home = join(root, "home");
      const box = { root, cwd: join(root, "proj"), home, agentDir: join(home, ".pi", "agent") };
      for (const dir of [join(box.cwd, "src"), box.agentDir]) mkdirSync(dir, { recursive: true });
      writeFileSync(join(box.agentDir, POLICY_FILE_NAME), JSON.stringify(USER_POLICY));
      await fn(box);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
}

/** The runtime of a primary process, as index.ts builds it. */
function primaryRuntime(box: Box): PolicyRuntime {
  return new PolicyRuntime({ agentDir: box.agentDir, home: box.home, exemptAgentless: true });
}

/** The runtime of a subagent process that received no snapshot. */
function childRuntime(box: Box): PolicyRuntime {
  return new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
}

function secretPath(box: Box): string {
  return join(box.cwd, "secrets", "key.txt");
}

function defineAgent(box: Box, name: string, permission?: PermissionConfig): AgentDefinition {
  const filePath = join(box.root, `${name}.agent.md`);
  writeFileSync(filePath, `---\nname: ${name}\n---\nBody.\n`);
  return {
    name,
    mode: "all",
    hidden: false,
    disable: false,
    thinking: "off",
    systemPrompt: "replace",
    maxDepth: 3,
    prompt: "Body.",
    source: "global",
    filePath,
    permission,
  };
}

type Handler = (event: unknown, ctx: unknown) => Promise<unknown> | unknown;
type Block = { block: true; reason: string } | undefined;
type CommandSpec = { handler: (args: string, ctx: unknown) => Promise<void> };

interface HarnessOptions {
  runtime: PolicyRuntime;
  agent: AgentDefinition | undefined;
  agents: AgentDefinition[];
  cwd: string;
}

/** The policy gate, the awareness section and the command on a fake pi. */
function harness(options: HarnessOptions) {
  const handlers = new Map<string, Handler[]>();
  const commands = new Map<string, CommandSpec>();
  const notices: { text: string; level: string }[] = [];
  const pi = {
    on: (event: string, handler: Handler) => handlers.set(event, [...(handlers.get(event) ?? []), handler]),
    registerCommand: (name: string, spec: CommandSpec) => commands.set(name, spec),
    getActiveTools: () => ACTIVE_TOOLS.slice(),
  };
  const resolveAgent = () => options.agent;
  const inheritedRules = () => [];
  const { runtime } = options;
  registerPolicyGate(pi as never, { runtime, resolveAgent, inheritedRules });
  registerPermissionAwareness(pi as never, { runtime, resolveAgent, inheritedRules, agents: options.agents, env: {} });
  registerPermissionCommands(pi as never, { runtime, resolveAgent, getAgents: () => options.agents, inheritedRules, env: {} });
  const ctx = {
    cwd: options.cwd,
    hasUI: true,
    isIdle: () => true,
    ui: { notify: (text: string, level: string) => notices.push({ text, level }), select: async () => undefined },
  };
  const start = async (): Promise<string> => {
    let prompt = BASE_PROMPT;
    for (const handler of handlers.get("before_agent_start") ?? []) {
      const result = (await handler({ type: "before_agent_start", prompt: "", systemPrompt: prompt }, ctx)) as
        | { systemPrompt?: string }
        | undefined;
      if (result?.systemPrompt !== undefined) prompt = result.systemPrompt;
    }
    return prompt;
  };
  const call = async (toolName: string, input: Record<string, unknown>): Promise<Block> => {
    for (const handler of handlers.get("tool_call") ?? []) {
      const result = (await handler({ toolName, input }, ctx)) as Block;
      if (result) return result;
    }
    return undefined;
  };
  const run = async (args = ""): Promise<{ text: string; level: string }> => {
    const spec = commands.get(PERMISSIONS_COMMAND);
    assert.ok(spec, "command registered");
    await spec.handler(args, ctx);
    const last = notices.at(-1);
    assert.ok(last);
    return last;
  };
  const setAgent = (agent: AgentDefinition | undefined) => {
    options.agent = agent;
  };
  return { start, call, run, notices, setAgent };
}

/** The snapshot `runtime` hands to `agent` when the delegating session has no agent. */
function childSnapshot(box: Box, runtime: PolicyRuntime, agent: AgentDefinition) {
  const plan = createDelegationPlanner({ runtime })({
    activeAgent: undefined,
    agent,
    cwd: box.cwd,
    childCwd: box.cwd,
    legacy: { parentCeiling: undefined, parentRules: undefined },
  });
  const raw = plan.extraEnv?.[POLICY_SNAPSHOT_ENV];
  assert.ok(raw, "snapshot handed to the child");
  const received = readPolicySnapshot({ ...CHILD_ENV, PI_OPEN_AGENTS_NAME: agent.name, [POLICY_SNAPSHOT_ENV]: raw });
  if (received?.status !== SNAPSHOT_STATUS.valid) throw new Error("expected a valid snapshot");
  return received;
}

// ─── Runtime ─────────────────────────────────────────────────────────────────

test("agentless: a primary session without an agent has no policy, a named agent keeps its own", withBox((box) => {
  const runtime = primaryRuntime(box);
  const worker = defineAgent(box, WORKER);
  assert.equal(runtime.isActive(box.cwd), true);
  assert.equal(runtime.isExempt(undefined), true);
  assert.equal(runtime.policyFor(undefined, box.cwd), undefined);
  assert.equal(runtime.isExempt(worker), false);
  assert.equal(runtime.policyFor(worker, box.cwd)?.agentName, WORKER);
}));

test("agentless: a subagent process keeps the * policy for an unresolved agent", withBox((box) => {
  const runtime = childRuntime(box);
  assert.equal(runtime.isExempt(undefined), false);
  const policy = runtime.policyFor(undefined, box.cwd);
  assert.ok(policy);
  assert.equal(policy.agentName, undefined);
}));

// ─── Gate and prompt ─────────────────────────────────────────────────────────

test("agentless: the gate lets every call through, hard denies and unknown tools included", withBox(async (box) => {
  const h = harness({ runtime: primaryRuntime(box), agent: undefined, agents: [], cwd: box.cwd });
  await h.start();
  assert.equal(await h.call("bash", { command: "rm -rf build" }), undefined);
  assert.equal(await h.call("bash", { command: "git push" }), undefined);
  assert.equal(await h.call("edit", { path: secretPath(box) }), undefined);
  assert.equal(await h.call("write", { path: join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME) }), undefined);
  assert.equal(await h.call("webfetch", { url: "https://example.com" }), undefined);
  assert.deepEqual(h.notices, []);
}));

test("agentless: selecting an agent enforces the policy, clearing it lifts it again", withBox(async (box) => {
  const worker = defineAgent(box, WORKER);
  const h = harness({ runtime: primaryRuntime(box), agent: undefined, agents: [worker], cwd: box.cwd });
  await h.start();
  h.setAgent(worker);
  assert.equal((await h.call("bash", { command: "ls" }))?.block, true);
  assert.equal((await h.call("bash", { command: "git push" }))?.block, true);
  assert.equal((await h.call("edit", { path: secretPath(box) }))?.block, true);
  h.setAgent(undefined);
  assert.equal(await h.call("bash", { command: "ls" }), undefined);
  assert.equal(await h.call("edit", { path: secretPath(box) }), undefined);
}));

test("agentless: no Runtime Permissions section is added to the prompt", withBox(async (box) => {
  const worker = defineAgent(box, WORKER);
  const h = harness({ runtime: primaryRuntime(box), agent: undefined, agents: [worker], cwd: box.cwd });
  assert.equal(await h.start(), BASE_PROMPT);
  h.setAgent(worker);
  assert.ok((await h.start()).includes(SUMMARY_HEADER));
}));

// ─── Delegation ──────────────────────────────────────────────────────────────

test("agentless: a child of an agentless session runs under its own policy without a ceiling", withBox((box) => {
  const worker = defineAgent(box, WORKER, { bash: { "npm test": "allow" } });
  const exempt = childSnapshot(box, primaryRuntime(box), worker).snapshot;
  assert.equal(exempt.self.agentName, WORKER);
  assert.deepEqual(exempt.ceilings, []);
  // Without the exemption the delegating process's own * policy is the ceiling.
  const strict = childSnapshot(box, childRuntime(box), worker).snapshot;
  assert.equal(strict.ceilings.length, 1);
  assert.equal(strict.ceilings[0].agentName, undefined);
}));

test("agentless: a process on a parent snapshot is never exempt", withBox((box) => {
  const worker = defineAgent(box, WORKER);
  const received = childSnapshot(box, primaryRuntime(box), worker);
  const child = new PolicyRuntime({ agentDir: box.agentDir, home: box.home, received, exemptAgentless: true });
  assert.equal(child.isExempt(undefined), false);
  assert.equal(child.policyFor(undefined, box.cwd)?.agentName, WORKER);
}));

// ─── Commands ────────────────────────────────────────────────────────────────

test("agentless: /permissions says the policy is not applied", withBox(async (box) => {
  const h = harness({ runtime: primaryRuntime(box), agent: undefined, agents: [], cwd: box.cwd });
  const { text, level } = await h.run();
  assert.equal(level, LEVEL_INFO);
  assert.match(text, EXEMPT_NOTE);
  assert.doesNotMatch(text, /no policy file exists/);
}));

test("agentless: /permissions <agent> still shows that agent's policy", withBox(async (box) => {
  const worker = defineAgent(box, WORKER);
  const h = harness({ runtime: primaryRuntime(box), agent: undefined, agents: [worker], cwd: box.cwd });
  const { text } = await h.run(WORKER);
  assert.ok(text.startsWith(SUMMARY_HEADER));
  assert.match(text, new RegExp(`^Agent: ${WORKER}$`, "m"));
}));

test("agentless: /permissions source reports the policy as not applied", withBox(async (box) => {
  const h = harness({ runtime: primaryRuntime(box), agent: undefined, agents: [], cwd: box.cwd });
  const { text } = await h.run(SUBCOMMAND.source);
  assert.match(text, /^Strict mode: not applied \(no active agent\)$/m);
  assert.match(text, /^Agent: \(no agent\)$/m);
  assert.doesNotMatch(text, /^Trusted:/m);
}));

test("agentless: /permissions explain agrees with the gate", withBox(async (box) => {
  const h = harness({ runtime: primaryRuntime(box), agent: undefined, agents: [], cwd: box.cwd });
  const { text } = await h.run(`${SUBCOMMAND.explain} bash rm -rf build`);
  assert.match(text, /^Action: allow$/m);
  assert.match(text, /^Hard: no$/m);
  assert.match(text, EXEMPT_NOTE);
  assert.equal(await h.call("bash", { command: "rm -rf build" }), undefined);
}));

test("agentless: /permissions reload notes the exemption", withBox(async (box) => {
  const h = harness({ runtime: primaryRuntime(box), agent: undefined, agents: [], cwd: box.cwd });
  const { text } = await h.run(SUBCOMMAND.reload);
  assert.match(text, EXEMPT_NOTE);
}));
