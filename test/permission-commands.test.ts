/**
 * `/permissions` command: read-only reports built from the same engine the
 * gates use. Every test runs in a tmp box with an injected agentDir and home.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { AgentDefinition, PermissionConfig } from "../src/types.ts";
import { PERMISSIONS_COMMAND, registerPermissionCommands, SUBCOMMAND } from "../src/permission/commands.ts";
import { createDelegationPlanner } from "../src/permission/delegation.ts";
import { registerPermissionGate } from "../src/permission/gate.ts";
import { POLICY_FILE_NAME, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { registerPolicyGate } from "../src/permission/policy-gate.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";
import { POLICY_SNAPSHOT_ENV, readPolicySnapshot } from "../src/permission/policy-snapshot.ts";
import { SUMMARY_HEADER } from "../src/permission/awareness.ts";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const ACTIVE_TOOLS = ["read", "bash", "edit", "write", "grep"];
const LEVEL_INFO = "info";
const LEVEL_WARNING = "warning";
const LEVEL_ERROR = "error";
const NO_ANSWER = /no answer was given/;
const ALLOW = "allow";
const ASK = "ask";
const DENY = "deny";
const CHILD_ENV = { PI_OPEN_AGENTS_DEPTH: "1" };

interface Box {
  root: string;
  cwd: string;
  home: string;
  agentDir: string;
}

function withBox(fn: (box: Box) => Promise<void> | void): () => Promise<void> {
  return async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-cmd-")));
    try {
      const home = join(root, "home");
      const box = { root, cwd: join(root, "proj"), home, agentDir: join(home, ".pi", "agent") };
      for (const dir of [join(box.cwd, "src"), join(box.cwd, PROJECT_POLICY_DIR), box.agentDir]) mkdirSync(dir, { recursive: true });
      await fn(box);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
}

function projectFile(box: Box): string {
  return join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME);
}

function userFile(box: Box): string {
  return join(box.agentDir, POLICY_FILE_NAME);
}

function writeProjectPolicy(box: Box, agents: Record<string, PermissionConfig> = {}): void {
  writeFileSync(projectFile(box), JSON.stringify({ version: 1, agents }));
}

function writeUserPolicy(box: Box, body: Record<string, unknown> = {}): void {
  writeFileSync(userFile(box), JSON.stringify({ version: 1, ...body }));
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

function team(box: Box) {
  const implementer = defineAgent(box, "implementer", { edit: "allow", write: "allow", bash: { "npm test": "allow", "git status": "allow" } });
  const reviewer = defineAgent(box, "reviewer", { bash: { rg: "allow" } });
  return { implementer, reviewer, agents: [implementer, reviewer] };
}

type Handler = (event: unknown, ctx: unknown) => Promise<unknown> | unknown;
type CommandSpec = {
  handler: (args: string, ctx: unknown) => Promise<void>;
  getArgumentCompletions?: (prefix: string) => { value: string }[] | null;
};

interface HarnessOptions {
  runtime: PolicyRuntime;
  agent: AgentDefinition | undefined;
  agents: AgentDefinition[];
  cwd: string;
}

/** The command plus both gates on a fake pi, so explain can be checked against real gate decisions. */
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
  registerPermissionGate(pi as never, { resolveAgent: () => (runtime.isActive(options.cwd) ? undefined : resolveAgent()) });
  registerPolicyGate(pi as never, { runtime, resolveAgent, inheritedRules });
  registerPermissionCommands(pi as never, { runtime, resolveAgent, getAgents: () => options.agents, inheritedRules, env: {} });
  let idle = true;
  const ctx = {
    cwd: options.cwd,
    hasUI: true,
    isIdle: () => idle,
    ui: { notify: (text: string, level: string) => notices.push({ text, level }), select: async () => undefined },
  };
  const run = async (args = ""): Promise<{ text: string; level: string }> => {
    const spec = commands.get(PERMISSIONS_COMMAND);
    assert.ok(spec, "command registered");
    await spec.handler(args, ctx);
    const last = notices.at(-1);
    assert.ok(last);
    return last;
  };
  /** The gate's verdict: blocked on "no answer" means it asked. */
  const gate = async (toolName: string, input: Record<string, unknown>): Promise<string> => {
    for (const handler of handlers.get("tool_call") ?? []) {
      const result = (await handler({ toolName, input }, ctx)) as { block: true; reason: string } | undefined;
      if (result) return NO_ANSWER.test(result.reason) ? ASK : DENY;
    }
    return ALLOW;
  };
  const setIdle = (value: boolean) => {
    idle = value;
  };
  return { run, gate, commands, setIdle };
}

function field(text: string, name: string): string | undefined {
  return new RegExp(`^${name}: (\\S+)`, "m").exec(text)?.[1];
}

// ─── Summary ─────────────────────────────────────────────────────────────────

test("permissions: summary of the active agent with a source note", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent: implementer, agents, cwd: box.cwd });
  const { text, level } = await h.run();
  assert.equal(level, LEVEL_INFO);
  assert.ok(text.startsWith(SUMMARY_HEADER));
  assert.match(text, /^Agent: implementer$/m);
  assert.match(text, /npm test/);
  assert.ok(text.includes(`user ${userFile(box)} (missing)`));
  assert.ok(text.includes(`project ${projectFile(box)} (loaded)`));
}));

test("permissions: without a policy file strict mode is reported off with both paths", withBox(async (box) => {
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const { text } = await harness({ runtime, agent: implementer, agents, cwd: box.cwd }).run();
  assert.match(text, /Strict permission mode is off/);
  assert.ok(text.includes(userFile(box)));
  assert.ok(text.includes(projectFile(box)));
  assert.match(text, /legacy frontmatter gate/);
}));

test("permissions <agent>: the named agent is evaluated as a primary", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const { text, level } = await harness({ runtime, agent: implementer, agents, cwd: box.cwd }).run("reviewer");
  assert.equal(level, LEVEL_INFO);
  assert.match(text, /^Agent: reviewer$/m);
  assert.doesNotMatch(text, /npm test/);
}));

test("permissions <agent>: an unknown agent is an error listing the known ones", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const { text, level } = await harness({ runtime, agent: implementer, agents, cwd: box.cwd }).run("ghost");
  assert.equal(level, LEVEL_ERROR);
  assert.match(text, /Unknown agent "ghost"\. Known agents: implementer, reviewer/);
}));

// ─── Source ──────────────────────────────────────────────────────────────────

test("permissions source: missing user file, loaded project file, untrusted", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const { text, level } = await harness({ runtime, agent: implementer, agents, cwd: box.cwd }).run(SUBCOMMAND.source);
  assert.equal(level, LEVEL_INFO);
  assert.ok(text.includes(`User policy: ${userFile(box)}: missing`));
  assert.ok(text.includes(`Project policy: ${projectFile(box)}: loaded`));
  assert.match(text, /^Trusted: no$/m);
  assert.ok(text.includes(`Agent: implementer (global, ${implementer.filePath})`));
  assert.doesNotMatch(text, /parent snapshot/);
}));

test("permissions source: trusted project names the matching trustedProjects entry", withBox(async (box) => {
  writeUserPolicy(box, { trustedProjects: [box.root] });
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const { text } = await harness({ runtime, agent: implementer, agents, cwd: box.cwd }).run(SUBCOMMAND.source);
  assert.ok(text.includes(`User policy: ${userFile(box)}: loaded`));
  assert.ok(text.includes(`Trusted: yes (trustedProjects entry ${box.root})`));
}));

test("permissions source: an invalid file is reported with its error", withBox(async (box) => {
  writeFileSync(projectFile(box), "{broken");
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const { text, level } = await harness({ runtime, agent: implementer, agents, cwd: box.cwd }).run(SUBCOMMAND.source);
  assert.equal(level, LEVEL_ERROR);
  assert.match(text, /Project policy: .*: invalid \(invalid JSON/);
}));

test("permissions source: a child reports the parent snapshot", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, reviewer, agents } = team(box);
  const parent = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const plan = createDelegationPlanner({ runtime: parent })({
    activeAgent: implementer,
    agent: reviewer,
    cwd: box.cwd,
    childCwd: box.cwd,
    legacy: { parentCeiling: undefined, parentRules: undefined },
  });
  const snapshot = plan.extraEnv?.[POLICY_SNAPSHOT_ENV];
  assert.ok(snapshot);
  const received = readPolicySnapshot({ ...CHILD_ENV, PI_OPEN_AGENTS_NAME: reviewer.name, [POLICY_SNAPSHOT_ENV]: snapshot });
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home, received });
  const { text } = await harness({ runtime, agent: reviewer, agents, cwd: box.cwd }).run(SUBCOMMAND.source);
  assert.match(text, /^Policy received from parent snapshot: 1 ceiling\(s\), 0 inherited rule\(s\)$/m);
}));

// ─── Reload ──────────────────────────────────────────────────────────────────

test("permissions reload: picks up an edited file and reports an invalid one as error", withBox(async (box) => {
  writeUserPolicy(box, { trustedProjects: [box.root] });
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent: implementer, agents, cwd: box.cwd });
  const explainPytest = `${SUBCOMMAND.explain} bash pytest -q`;
  assert.equal(field((await h.run(explainPytest)).text, "Action"), DENY);

  writeProjectPolicy(box, { implementer: { bash: { pytest: "allow" } } });
  assert.equal(field((await h.run(explainPytest)).text, "Action"), DENY, "no reload, same snapshot");

  h.setIdle(false);
  const busy = await h.run(SUBCOMMAND.reload);
  assert.equal(busy.level, LEVEL_WARNING);
  assert.equal(field((await h.run(explainPytest)).text, "Action"), DENY, "a running agent keeps its policy");
  h.setIdle(true);

  const reloaded = await h.run(SUBCOMMAND.reload);
  assert.equal(reloaded.level, LEVEL_INFO);
  assert.match(reloaded.text, /next run/);
  assert.equal(field((await h.run(explainPytest)).text, "Action"), ALLOW);

  writeFileSync(projectFile(box), "{broken");
  const invalid = await h.run(SUBCOMMAND.reload);
  assert.equal(invalid.level, LEVEL_ERROR);
  assert.match(invalid.text, /Project policy: .*: invalid/);
  assert.match(invalid.text, /^Warning: .*blocked until it is fixed$/m);
}));

// ─── Explain ─────────────────────────────────────────────────────────────────

const EXPLAIN_CASES: { tool: string; argument: string; action: string; hard: string }[] = [
  { tool: "bash", argument: "git push origin main", action: DENY, hard: "yes" },
  { tool: "edit", argument: ".git/config", action: DENY, hard: "yes" },
  { tool: "bash", argument: "curl https://example.com", action: DENY, hard: "no" },
  { tool: "bash", argument: "npm test", action: ALLOW, hard: "no" },
  { tool: "read", argument: "src/a.ts", action: ALLOW, hard: "no" },
  { tool: "edit", argument: "src/a.ts", action: ALLOW, hard: "no" },
  { tool: "webfetch", argument: "https://x", action: ASK, hard: "no" },
];

test("permissions explain: matches the policy gate for the same input", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent: implementer, agents, cwd: box.cwd });
  for (const { tool, argument, action, hard } of EXPLAIN_CASES) {
    const { text } = await h.run(`${SUBCOMMAND.explain} ${tool} ${argument}`);
    const label = `${tool} ${argument}`;
    assert.equal(field(text, "Action"), action, label);
    assert.equal(field(text, "Hard"), hard, label);
    const key = tool === "bash" ? "command" : "path";
    assert.equal(await h.gate(tool, { [key]: argument }), action, `gate agrees: ${label}`);
    assert.match(text, /^Nothing was executed\.$/m);
  }
}));

test("permissions explain: apply_patch text is a non-path input, a hard deny like the gate", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent: implementer, agents, cwd: box.cwd });
  const { text } = await h.run(`${SUBCOMMAND.explain} apply_patch *** Begin Patch src/a.ts`);
  assert.equal(field(text, "Action"), DENY);
  assert.equal(field(text, "Hard"), "yes");
  assert.match(text, /^Reason: cannot verify the target path/m);
  assert.equal(await h.gate("apply_patch", { input: "*** Begin Patch src/a.ts" }), DENY);
}));

test("permissions explain: ask notes the headless deny and protected paths name the reason", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent: implementer, agents, cwd: box.cwd });
  assert.match((await h.run(`${SUBCOMMAND.explain} webfetch https://x`)).text, /headless: deny/);
  assert.match((await h.run(`${SUBCOMMAND.explain} edit .git/config`)).text, /^Reason: path is protected/m);
  assert.match((await h.run(`${SUBCOMMAND.explain} bash git push origin main`)).text, /^Reason: git write operations are disabled/m);
}));

test("permissions explain: legacy mode uses the frontmatter gate and says so", withBox(async (box) => {
  const agent = defineAgent(box, "legacy", { bash: { "rm *": "deny" }, read: { ".env": "ask" } });
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent, agents: [agent], cwd: box.cwd });
  const cases = [
    { tool: "bash", key: "command", argument: "rm -rf build", action: DENY },
    { tool: "bash", key: "command", argument: "ls", action: ALLOW },
    { tool: "read", key: "path", argument: ".env", action: ASK },
    { tool: "edit", key: "path", argument: "src/a.ts", action: ALLOW },
  ];
  for (const { tool, key, argument, action } of cases) {
    const { text } = await h.run(`${SUBCOMMAND.explain} ${tool} ${argument}`);
    assert.match(text, /Legacy mode/);
    assert.equal(field(text, "Action"), action, `${tool} ${argument}`);
    assert.equal(await h.gate(tool, { [key]: argument }), action, `legacy gate agrees: ${tool} ${argument}`);
  }
}));

test("permissions explain: a missing argument is an error with usage", withBox(async (box) => {
  writeProjectPolicy(box);
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const { text, level } = await harness({ runtime, agent: implementer, agents, cwd: box.cwd }).run(`${SUBCOMMAND.explain} bash`);
  assert.equal(level, LEVEL_ERROR);
  assert.match(text, /Usage:/);
}));

// ─── Help ────────────────────────────────────────────────────────────────────

test("permissions help and unknown subcommands print usage", withBox(async (box) => {
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent: implementer, agents, cwd: box.cwd });
  const help = await h.run(SUBCOMMAND.help);
  assert.equal(help.level, LEVEL_INFO);
  assert.match(help.text, /\/permissions explain <tool> <argument\.\.\.>/);
  const unknown = await h.run("frobnicate now");
  assert.equal(unknown.level, LEVEL_WARNING);
  assert.match(unknown.text, /Unknown subcommand "frobnicate"/);
  assert.match(unknown.text, /Usage:/);
}));

test("permissions completions offer subcommands and agent names", withBox(async (box) => {
  const { implementer, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent: implementer, agents, cwd: box.cwd });
  const complete = h.commands.get(PERMISSIONS_COMMAND)?.getArgumentCompletions;
  assert.ok(complete);
  assert.deepEqual(complete("re")?.map((item) => item.value), [SUBCOMMAND.reload, "reviewer"]);
  assert.equal(complete("explain b"), null);
}));
