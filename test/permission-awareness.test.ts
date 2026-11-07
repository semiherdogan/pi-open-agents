/**
 * Permission awareness: the "Runtime Permissions" prompt section is built from
 * the same engine the policy gate enforces with, for primaries and children.
 * Every test runs in a tmp box with an injected agentDir and home.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { AgentDefinition, PermissionConfig, PermissionRule } from "../src/types.ts";
import {
  buildPermissionSummary,
  probeCommand,
  PROBE_FILE,
  PROBE_CHAR,
  PROBE_WORD,
  probePath,
  registerPermissionAwareness,
  SUMMARY_HEADER,
  SUMMARY_UNAVAILABLE,
} from "../src/permission/awareness.ts";
import { createDelegationPlanner, DELEGATION_MODE, type DelegationMode } from "../src/permission/delegation.ts";
import { POLICY_FILE_NAME, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { matchPattern } from "../src/permission/matcher.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";
import { registerPolicyGate } from "../src/permission/policy-gate.ts";
import { POLICY_SNAPSHOT_ENV, readPolicySnapshot } from "../src/permission/policy-snapshot.ts";

type PiOpenAgents = typeof import("../src/index.ts").default;
let piOpenAgents: PiOpenAgents | undefined;
try {
  ({ default: piOpenAgents } = await import("../src/index.ts"));
} catch {
  piOpenAgents = undefined;
}
const runWiring = piOpenAgents ? test : test.skip;

// ─── Fixtures ────────────────────────────────────────────────────────────────

const BASE_PROMPT = "Base prompt.";
const SUBAGENT_TOOL = "subagent";
const SAFE_TOOL = "grep";
const CUSTOM_TOOL = "web_fetch";
const ACTIVE_TOOLS = ["read", "bash", "edit", "write", CUSTOM_TOOL, SAFE_TOOL, SUBAGENT_TOOL];
const LINE_BUDGET = 35;
const PATH_LENGTH = 150;
const MTIME_BUMP_MS = 5000;
const NO_ANSWER = /no answer was given/;
const ALLOWED_LINE = "Bash allowed command prefixes:";
const CHILD_ENV = { PI_OPEN_AGENTS_DEPTH: "1" };
const NAME_ENV = "PI_OPEN_AGENTS_NAME";

interface Box {
  root: string;
  cwd: string;
  home: string;
  agentDir: string;
}

function withBox(fn: (box: Box) => Promise<void> | void): () => Promise<void> {
  return async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-aware-")));
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

function writeProjectPolicy(box: Box, agents: Record<string, PermissionConfig> = {}): void {
  writeFileSync(join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), JSON.stringify({ version: 1, agents }));
}

function defineAgent(
  box: Box,
  name: string,
  fields: { permission?: PermissionConfig; allowedAgents?: string[]; delegation?: Record<string, DelegationMode> },
): AgentDefinition {
  const filePath = join(box.root, `${name}.agent.md`);
  const delegation = Object.entries(fields.delegation ?? {}).map(([child, mode]) => `  ${child}: ${mode}\n`).join("");
  writeFileSync(filePath, `---\nname: ${name}\n${delegation ? `delegation:\n${delegation}` : ""}---\nBody.\n`);
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
    permission: fields.permission,
    allowedAgents: fields.allowedAgents,
  };
}

const IMPLEMENTER_PERMISSION: PermissionConfig = {
  edit: "allow",
  write: "allow",
  bash: { "git status": "allow", "npm test": "allow" },
};

function team(box: Box, implementerMode: DelegationMode = DELEGATION_MODE.role, implementerPermission = IMPLEMENTER_PERMISSION) {
  const architect = defineAgent(box, "architect", {
    permission: { edit: "deny", write: "deny", bash: { "git status": "allow", rg: "allow" } },
    allowedAgents: ["implementer", "reviewer"],
    delegation: { implementer: implementerMode },
  });
  const implementer = defineAgent(box, "implementer", { permission: implementerPermission });
  const reviewer = defineAgent(box, "reviewer", { permission: { bash: { rg: "allow" } } });
  return { architect, implementer, reviewer, agents: [architect, implementer, reviewer] };
}

type Handler = (event: unknown, ctx: unknown) => Promise<unknown> | unknown;
type Block = { block: true; reason: string } | undefined;

interface HarnessOptions {
  runtime: PolicyRuntime;
  agent: AgentDefinition | undefined;
  agents: AgentDefinition[];
  cwd: string;
  hasUI: boolean;
  env?: Record<string, string>;
  inherited?: PermissionRule[];
  readFile?: (filePath: string) => string;
}

/** The policy gate and the awareness section on a fake pi, chained like pi's runner. */
function harness(options: HarnessOptions) {
  const handlers = new Map<string, Handler[]>();
  const notices: string[] = [];
  const pi = {
    on: (event: string, handler: Handler) => handlers.set(event, [...(handlers.get(event) ?? []), handler]),
    getActiveTools: () => ACTIVE_TOOLS.slice(),
  };
  const resolveAgent = () => options.agent;
  const inheritedRules = () => options.inherited ?? [];
  registerPolicyGate(pi as never, { runtime: options.runtime, resolveAgent, inheritedRules });
  registerPermissionAwareness(pi as never, {
    runtime: options.runtime,
    resolveAgent,
    inheritedRules,
    agents: options.agents,
    env: options.env ?? {},
    readFile: options.readFile,
  });
  const ctx = {
    cwd: options.cwd,
    hasUI: options.hasUI,
    ui: { notify: (message: string) => notices.push(message), select: async () => undefined },
  };
  const start = async (systemPrompt = BASE_PROMPT): Promise<string> => {
    let prompt = systemPrompt;
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
  const setAgent = (agent: AgentDefinition | undefined) => {
    options.agent = agent;
  };
  return { start, call, notices, ctx, setAgent };
}

/** readFileSync that counts how often the awareness section reads agent files. */
function countingReader() {
  const counter = { reads: 0, readFile: (filePath: string) => {
    counter.reads++;
    return readFileSync(filePath, "utf8");
  } };
  return counter;
}

function section(prompt: string): string {
  const index = prompt.indexOf(SUMMARY_HEADER);
  assert.notEqual(index, -1, "permission section present");
  return prompt.slice(index);
}

function line(summary: string, prefix: string): string | undefined {
  return summary.split("\n").find((l) => l.startsWith(prefix));
}

function listedPrefixes(summary: string): string[] {
  const allowed = line(summary, ALLOWED_LINE);
  return allowed === undefined ? [] : [...allowed.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
}

const VERDICT_ACTION: Record<string, string> = {
  allowed: "allow",
  denied: "deny",
  "denied (no approval in subagents)": "deny",
  "asks for approval": "ask",
};

function fileVerdicts(summary: string): Record<string, string> {
  const files = line(summary, "Files") ?? "";
  const verdicts: Record<string, string> = {};
  for (const tool of ["read", "edit", "write"]) {
    const match = files.match(new RegExp(`${tool} ([^;.]+(?:\\([^)]*\\))?)`));
    assert.ok(match, `verdict for ${tool}`);
    verdicts[tool] = VERDICT_ACTION[match[1].trim()];
  }
  return verdicts;
}

/** What the gate does with the call: allow, deny, or ask (the fake UI never answers). */
async function gateAction(call: (toolName: string, input: Record<string, unknown>) => Promise<Block>, toolName: string, input: Record<string, unknown>): Promise<string> {
  const block = await call(toolName, input);
  if (block === undefined) return "allow";
  return NO_ANSWER.test(block.reason) ? "ask" : "deny";
}

async function childOf(
  box: Box,
  mode: DelegationMode,
  implementerPermission = IMPLEMENTER_PERMISSION,
  readFile?: (filePath: string) => string,
) {
  writeProjectPolicy(box);
  const { architect, implementer, agents } = team(box, mode, implementerPermission);
  const parent = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  parent.beginRun(box.cwd, architect);
  const plan = createDelegationPlanner({ runtime: parent })({
    activeAgent: architect,
    agent: implementer,
    cwd: box.cwd,
    childCwd: box.cwd,
    legacy: { parentCeiling: undefined, parentRules: undefined },
  });
  assert.equal(plan.mode, mode);
  const received = readPolicySnapshot({ ...CHILD_ENV, [NAME_ENV]: implementer.name, [POLICY_SNAPSHOT_ENV]: plan.extraEnv?.[POLICY_SNAPSHOT_ENV] });
  assert.ok(received);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home, received });
  return harness({ runtime, agent: implementer, agents, cwd: box.cwd, hasUI: false, env: CHILD_ENV, readFile });
}

/** A child restrict-delegated by a parent with the given permission; the parent becomes the ceiling. */
function restrictChild(box: Box, parentPermission: PermissionConfig, childPermission: PermissionConfig) {
  writeProjectPolicy(box);
  const child = defineAgent(box, "child", { permission: childPermission });
  const lead = defineAgent(box, "lead", { permission: parentPermission, delegation: { child: DELEGATION_MODE.restrict } });
  const parent = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  parent.beginRun(box.cwd, lead);
  const plan = createDelegationPlanner({ runtime: parent })({
    activeAgent: lead,
    agent: child,
    cwd: box.cwd,
    childCwd: box.cwd,
    legacy: { parentCeiling: undefined, parentRules: undefined },
  });
  assert.equal(plan.mode, DELEGATION_MODE.restrict);
  const received = readPolicySnapshot({ ...CHILD_ENV, [NAME_ENV]: child.name, [POLICY_SNAPSHOT_ENV]: plan.extraEnv?.[POLICY_SNAPSHOT_ENV] });
  assert.ok(received);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home, received });
  return harness({ runtime, agent: child, agents: [lead, child], cwd: box.cwd, hasUI: false, env: CHILD_ENV });
}

async function architectHarness(box: Box, readFile?: (filePath: string) => string) {
  writeProjectPolicy(box);
  const { architect, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  return harness({ runtime, agent: architect, agents, cwd: box.cwd, hasUI: true, readFile });
}

/** A primary agent with the given permission under an empty project policy. */
function primary(box: Box, name: string, permission: PermissionConfig, inherited?: PermissionRule[]) {
  writeProjectPolicy(box);
  const agent = defineAgent(box, name, { permission });
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  return harness({ runtime, agent, agents: [agent], cwd: box.cwd, hasUI: true, inherited });
}

// ─── Summary content ─────────────────────────────────────────────────────────

test("awareness: architect sees read-only files, its bash prefixes, git and delegation modes", withBox(async (box) => {
  const h = await architectHarness(box);
  const prompt = await h.start();
  assert.ok(prompt.startsWith(`${BASE_PROMPT}\n\n${SUMMARY_HEADER}`));
  const summary = section(prompt);
  assert.match(summary, /^Agent: architect$/m);
  assert.deepEqual(fileVerdicts(summary), { read: "allow", edit: "deny", write: "deny" });
  assert.deepEqual(listedPrefixes(summary), ["git status", "rg"]);
  assert.match(summary, /Bash: any other command: denied\./);
  assert.match(summary, /committing, pushing/);
  assert.match(summary, /implementer: role \(own permissions\)/);
  assert.match(summary, /reviewer: restrict \(limited to your permissions\)/);
  assert.match(summary, /Never write to: \.git, \.pi, \.opencode, \.agents \(any project\)/);
  assert.match(summary, /^Other tools: allowed: grep; asks for approval: web_fetch\.$/m);
  assert.equal(await gateAction(h.call, SAFE_TOOL, {}), "allow");
  assert.equal(await gateAction(h.call, CUSTOM_TOOL, {}), "ask");
  assert.ok(summary.split("\n").length < LINE_BUDGET, `under ${LINE_BUDGET} lines`);
}));

test("awareness: a child under a restrict ceiling sees edit denied and only ceiling-approved prefixes", withBox(async (box) => {
  const summary = section(await (await childOf(box, DELEGATION_MODE.restrict)).start());
  assert.match(summary, /^Agent: implementer$/m);
  assert.equal(fileVerdicts(summary).edit, "deny");
  assert.deepEqual(listedPrefixes(summary), ["git status"], "npm test is allowed by the child but not by the ceiling");
  assert.match(summary, /^Other tools: allowed: grep; denied: web_fetch\.$/m);
}));

test("awareness: a child's own path allow under a read-only ceiling is not listed as allowed", withBox(async (box) => {
  const permission: PermissionConfig = { edit: { "src/**": "allow" }, bash: { "git status": "allow" } };
  const h = await childOf(box, DELEGATION_MODE.restrict, permission);
  const summary = section(await h.start());
  assert.equal(fileVerdicts(summary).edit, "deny");
  assert.doesNotMatch(summary, /edit `src\/\*\*`: allowed/);
  assert.equal(await gateAction(h.call, "edit", { path: probePath("src/**") }), "deny");
}));

test("awareness: path rules show the engine verdict and a later override removes them", withBox(async (box) => {
  const h = primary(box, "docs", { edit: { "docs/**": "allow" } });
  const summary = section(await h.start());
  assert.equal(fileVerdicts(summary).edit, "deny");
  assert.match(summary, /^Path rules: edit `docs\/\*\*`: allowed$/m);
  assert.equal(await gateAction(h.call, "edit", { path: probePath("docs/**") }), "allow");

  writeProjectPolicy(box, { docs: { edit: { "*": "deny" } } });
  const overridden = section(await h.start());
  assert.equal(line(overridden, "Path rules"), undefined);
  assert.equal(await gateAction(h.call, "edit", { path: probePath("docs/**") }), "deny");
}));

test("awareness: a narrower own deny after a broader allow is listed as an exception", withBox(async (box) => {
  const h = primary(box, "publisher", { bash: { "npm *": "allow", "npm publish*": "deny" } });
  const summary = section(await h.start());
  assert.deepEqual(listedPrefixes(summary), ["npm *"]);
  assert.match(summary, /^Bash exceptions \(denied\): `npm publish\*`$/m);
  assert.equal(await gateAction(h.call, "bash", { command: probeCommand("npm publish*") }), "deny");
  assert.equal(await gateAction(h.call, "bash", { command: probeCommand("npm *") }), "allow");
}));

test("awareness: a deny listed as an exception is not repeated under Denied commands", withBox(async (box) => {
  const h = primary(box, "publisher", { bash: { "*": "allow", "npm *": "allow", "npm publish*": "deny", "rm *": "deny" } });
  const summary = section(await h.start());
  assert.match(summary, /^Bash exceptions \(denied\): `npm publish\*`$/m);
  assert.match(summary, /^Denied commands: `rm \*`$/m);
}));

test("awareness: a ceiling deny under a blanket allow is listed as denied", withBox(async (box) => {
  const h = restrictChild(box, { bash: { "*": "allow", "git push *": "deny" } }, { bash: { "*": "allow" } });
  const summary = section(await h.start());
  assert.match(summary, /^Bash: any command not listed below as forbidden\.$/m);
  assert.match(summary, /^Denied commands: `git push \*`$/m);
  assert.equal(await gateAction(h.call, "bash", { command: probeCommand("git push *") }), "deny");
}));

test("awareness: an inherited deny under a blanket allow is listed as denied", withBox(async (box) => {
  const inherited: PermissionRule[] = [{ permission: "bash", pattern: "rm *", action: "deny" }];
  const h = primary(box, "free", { bash: { "*": "allow" } }, inherited);
  const summary = section(await h.start());
  assert.match(summary, /^Denied commands: `rm \*`$/m);
  assert.equal(await gateAction(h.call, "bash", { command: probeCommand("rm *") }), "deny");
}));

test("awareness: an own ask under an allowed prefix is listed once, as an exception", withBox(async (box) => {
  const h = primary(box, "publisher", { bash: { "npm *": "allow", "npm publish*": "ask" } });
  const summary = section(await h.start());
  assert.match(summary, /^Bash exceptions \(asks\): `npm publish\*`$/m);
  assert.equal(line(summary, "Bash commands that ask for approval"), undefined);
  assert.equal(await gateAction(h.call, "bash", { command: probeCommand("npm publish*") }), "ask");
}));

test("awareness: a ceiling path deny under the child's edit allow is listed", withBox(async (box) => {
  const h = restrictChild(box, { edit: { "*": "allow", "*.env": "deny" } }, { edit: "allow" });
  const summary = section(await h.start());
  assert.equal(fileVerdicts(summary).edit, "allow");
  assert.match(line(summary, "Path rules") ?? "", /edit `\*\.env`: denied/);
  assert.equal(await gateAction(h.call, "edit", { path: probePath("*.env") }), "deny");
}));

test("awareness: read path rules are listed against the generic read verdict", withBox(async (box) => {
  const h = primary(box, "reader", { read: { "**/.env": "deny" } });
  const summary = section(await h.start());
  assert.equal(fileVerdicts(summary).read, "allow");
  assert.match(line(summary, "Path rules") ?? "", /read `\*\*\/\.env`: denied/);
  assert.equal(await gateAction(h.call, "read", { path: probePath("**/.env") }), "deny");
}));

test("awareness: a probe built from a pattern matches that pattern", () => {
  assert.equal(probePath("a?.ts"), `a${PROBE_CHAR}.ts`);
  assert.equal(probePath("src/**"), `src/${PROBE_WORD}`);
  for (const pattern of ["a?.ts", "src/**", "*.env", "**/.env"]) {
    assert.ok(matchPattern(pattern, probePath(pattern)), pattern);
  }
  assert.equal(probeCommand("npm run *"), `npm run ${PROBE_WORD}`);
  assert.ok(matchPattern("npm run *", probeCommand("npm run *")));
});

test("awareness: long filesystem paths in Never write to are not cut at the item cap", withBox((box) => {
  writeProjectPolicy(box);
  const agentDir = join(box.root, "d".repeat(PATH_LENGTH), ".pi", "agent");
  const { architect } = team(box);
  const runtime = new PolicyRuntime({ agentDir, home: box.home });
  const policy = runtime.policyFor(architect, box.cwd);
  assert.ok(policy);
  const summary = buildPermissionSummary({ policy, ceilings: [], inherited: [], cwd: box.cwd, home: box.home, delegates: [], headless: false });
  assert.ok(summary.includes(`(${agentDir})`), "full agent dir listed");
}));

test("awareness: an edit to the delegating agent file invalidates the cached summary", withBox(async (box) => {
  const h = await architectHarness(box);
  const first = section(await h.start());
  assert.match(first, /implementer: role \(own permissions\)/);
  const { architect } = team(box, DELEGATION_MODE.restrict);
  const later = new Date(Date.now() + MTIME_BUMP_MS);
  utimesSync(architect.filePath, later, later);
  const second = section(await h.start());
  assert.notEqual(second, first);
  assert.match(second, /implementer: restrict \(limited to your permissions\)/);
}));

test("awareness: an inherited deny under a listed allow is listed as an exception", withBox(async (box) => {
  const inherited: PermissionRule[] = [{ permission: "bash", pattern: "npm publish*", action: "deny" }];
  const h = primary(box, "publisher", { bash: { "npm *": "allow" } }, inherited);
  const summary = section(await h.start());
  assert.deepEqual(listedPrefixes(summary), ["npm *"]);
  assert.match(summary, /^Bash exceptions \(denied\): `npm publish\*`$/m);
  assert.equal(await gateAction(h.call, "bash", { command: probeCommand("npm publish*") }), "deny");
}));

test("awareness: policy text is sanitized before it reaches the prompt", withBox(async (box) => {
  const long = `docs/${"a".repeat(120)}`;
  const h = primary(box, "sneaky", { edit: { "docs/\n## injected `x`/**": "allow", [long]: "allow" } });
  const summary = section(await h.start());
  assert.ok(!summary.split("\n").some((l) => l.startsWith("## injected")), "no injected line");
  const paths = line(summary, "Path rules") ?? "";
  assert.ok(paths.includes("`docs/ ## injected 'x'/**`: allowed"), paths);
  assert.ok(paths.includes(`\`docs/${"a".repeat(74)}\u2026\`: allowed`), paths);
  assert.ok(!paths.includes(long));
}));

test("awareness: a child delegated in role mode sees its own edit permission", withBox(async (box) => {
  const summary = section(await (await childOf(box, DELEGATION_MODE.role)).start());
  assert.equal(fileVerdicts(summary).edit, "allow");
  assert.deepEqual(listedPrefixes(summary), ["git status", "npm test"]);
}));

// ─── Prompt and enforcement agree ────────────────────────────────────────────

const AGREEMENT_CASES: Array<{ name: string; make: (box: Box) => Promise<ReturnType<typeof harness>> }> = [
  { name: "architect primary", make: architectHarness },
  { name: "implementer child, restrict", make: (box) => childOf(box, DELEGATION_MODE.restrict) },
  { name: "implementer child, role", make: (box) => childOf(box, DELEGATION_MODE.role) },
];

for (const { name, make } of AGREEMENT_CASES) {
  test(`awareness: prompt and gate agree (${name})`, withBox(async (box) => {
    const h = await make(box);
    const summary = section(await h.start());
    for (const [tool, action] of Object.entries(fileVerdicts(summary))) {
      assert.equal(await gateAction(h.call, tool, { path: PROBE_FILE }), action, `${tool} ${PROBE_FILE}`);
    }
    const prefixes = listedPrefixes(summary);
    assert.ok(prefixes.length > 0);
    for (const prefix of prefixes) {
      assert.equal(await gateAction(h.call, "bash", { command: probeCommand(prefix) }), "allow", prefix);
    }
  }));
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

test("awareness: without a policy file nothing is appended", withBox(async (box) => {
  const { architect, agents } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const h = harness({ runtime, agent: architect, agents, cwd: box.cwd, hasUI: true });
  assert.equal(await h.start(), BASE_PROMPT);
}));

test("awareness: deterministic per policy, rebuilt after a policy change", withBox(async (box) => {
  const h = await architectHarness(box);
  const first = await h.start();
  assert.equal(await h.start(), first);
  writeProjectPolicy(box, { architect: { bash: { rg: "deny" } } });
  const changed = section(await h.start());
  assert.notEqual(changed, section(first));
  assert.deepEqual(listedPrefixes(changed), ["git status"]);
}));

test("awareness: without an active tool list the other-tools line falls back to the category defaults", withBox((box) => {
  writeProjectPolicy(box);
  const { architect } = team(box);
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const policy = runtime.policyFor(architect, box.cwd);
  assert.ok(policy);
  const base = { policy, ceilings: [], inherited: [], cwd: box.cwd, home: box.home, delegates: [] };
  assert.match(buildPermissionSummary({ ...base, headless: false }), /^Other tools: grep, find, ls allowed; any other tool asks for approval\.$/m);
  assert.match(buildPermissionSummary({ ...base, headless: true }), /^Other tools: grep, find, ls allowed; any other tool denied\.$/m);
}));

test("awareness: a cache hit skips the delegation-mode file reads", withBox(async (box) => {
  const reader = countingReader();
  const h = await architectHarness(box, reader.readFile);
  const first = await h.start();
  const reads = reader.reads;
  assert.ok(reads > 0, "the miss read the agent file");
  assert.equal(await h.start(), first);
  assert.equal(reader.reads, reads);
}));

test("awareness: the cache is invalidated by an agent switch", withBox(async (box) => {
  const h = await architectHarness(box);
  assert.match(section(await h.start()), /^Agent: architect$/m);
  h.setAgent(team(box).reviewer);
  const switched = section(await h.start());
  assert.match(switched, /^Agent: reviewer$/m);
  assert.deepEqual(listedPrefixes(switched), ["rg"]);
}));

test("awareness: the cache is invalidated by a cwd change under a constant snapshot", withBox(async (box) => {
  const reader = countingReader();
  const h = await childOf(box, DELEGATION_MODE.restrict, IMPLEMENTER_PERMISSION, reader.readFile);
  await h.start();
  await h.start();
  const reads = reader.reads;
  h.ctx.cwd = join(box.cwd, "src");
  await h.start();
  assert.ok(reader.reads > reads, "rebuilt for the new cwd");
}));

test("awareness: an unreadable snapshot appends the fallback line and keeps the run going", withBox(async (box) => {
  const { implementer, agents } = team(box);
  const received = readPolicySnapshot({ ...CHILD_ENV, [NAME_ENV]: implementer.name, [POLICY_SNAPSHOT_ENV]: "{not json" });
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home, received });
  const h = harness({ runtime, agent: implementer, agents, cwd: box.cwd, hasUI: false, env: CHILD_ENV });
  assert.equal(await h.start(), `${BASE_PROMPT}\n\n${SUMMARY_UNAVAILABLE}`);
}));

// ─── index.ts wiring ─────────────────────────────────────────────────────────

const WIRED_AGENT = "wired";

async function startWired(box: Box, env: Record<string, string>): Promise<string> {
  assert.ok(piOpenAgents);
  const agentsDir = join(box.cwd, PROJECT_POLICY_DIR, "agents");
  mkdirSync(agentsDir, { recursive: true });
  writeFileSync(
    join(agentsDir, `${WIRED_AGENT}.agent.md`),
    `---\nname: ${WIRED_AGENT}\nmode: all\ndescription: wired\nsystemPrompt: replace-all\npermission:\n  bash:\n    rg: allow\n---\nWired body.\n`,
  );
  const overrides: Record<string, string> = { PI_CODING_AGENT_DIR: box.agentDir, HOME: box.home, USERPROFILE: box.home, ...env };
  const previous = new Map(Object.keys(overrides).map((name) => [name, process.env[name]]));
  Object.assign(process.env, overrides);
  try {
    const handlers = new Map<string, Handler[]>();
    const builtinTools = ["read", "bash", "edit", "write", "grep", "find", "ls"];
    const flags = new Map<string, string>([["agent", WIRED_AGENT]]);
    const pi = {
      on: (event: string, handler: Handler) => handlers.set(event, [...(handlers.get(event) ?? []), handler]),
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
      cwd: box.cwd,
      hasUI: false,
      model: undefined,
      ui: { notify: () => {}, select: async () => undefined, setWidget: () => {}, setStatus: () => {}, theme: { bold: (s: string) => s, fg: (_c: string, s: string) => s } },
      modelRegistry: { find: () => undefined, getAvailable: () => [] },
      sessionManager: { getEntries: () => [], getSessionFile: () => undefined, getLeafId: () => undefined },
    };
    piOpenAgents(pi as never);
    for (const handler of handlers.get("session_start") ?? []) await handler({ type: "session_start", reason: "startup" }, ctx);
    let prompt = BASE_PROMPT;
    for (const handler of handlers.get("before_agent_start") ?? []) {
      const result = (await handler({ type: "before_agent_start", prompt: "", systemPrompt: prompt }, ctx)) as { systemPrompt?: string } | undefined;
      if (result?.systemPrompt !== undefined) prompt = result.systemPrompt;
    }
    return prompt;
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

runWiring("awareness wiring: a replace-all primary prompt still ends with the permission section", withBox(async (box) => {
  writeProjectPolicy(box);
  const prompt = await startWired(box, {});
  assert.ok(!prompt.includes(BASE_PROMPT), "replace-all dropped the base prompt");
  assert.ok(prompt.includes("Wired body."));
  const summary = section(prompt);
  assert.ok(prompt.endsWith(summary));
  assert.match(summary, /^Agent: wired$/m);
  assert.deepEqual(listedPrefixes(summary), ["rg"]);
}));

runWiring("awareness wiring: a child process with a snapshot ends with its own section", withBox(async (box) => {
  writeProjectPolicy(box);
  const { architect } = team(box);
  const wired = defineAgent(box, WIRED_AGENT, { permission: { bash: { rg: "allow" } } });
  const parent = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  const plan = createDelegationPlanner({ runtime: parent })({
    activeAgent: architect,
    agent: wired,
    cwd: box.cwd,
    childCwd: box.cwd,
    legacy: { parentCeiling: undefined, parentRules: undefined },
  });
  const snapshot = plan.extraEnv?.[POLICY_SNAPSHOT_ENV];
  assert.ok(snapshot);
  const prompt = await startWired(box, { ...CHILD_ENV, [NAME_ENV]: WIRED_AGENT, [POLICY_SNAPSHOT_ENV]: snapshot });
  const summary = section(prompt);
  assert.ok(prompt.startsWith(BASE_PROMPT), "children keep the executor's prompt");
  assert.ok(prompt.endsWith(summary));
  assert.match(summary, /^Agent: wired$/m);
  // restrict: rg passes the architect ceiling too.
  assert.deepEqual(listedPrefixes(summary), ["rg"]);
  assert.match(summary, /^Other tools: allowed: find, grep, ls\.$/m);
}));

runWiring("awareness wiring: without a policy file the prompt has no permission section", withBox(async (box) => {
  const prompt = await startWired(box, {});
  assert.ok(!prompt.includes(SUMMARY_HEADER));
  assert.ok(prompt.includes("Wired body."));
}));
