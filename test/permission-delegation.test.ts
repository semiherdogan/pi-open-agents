/**
 * Strict-mode delegation: restrict / role modes, the policy snapshot handed to
 * children, ceilings in the policy gate and fail-closed snapshot handling.
 * Every test runs in a tmp box with an injected agentDir and home.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";

import type { AgentDefinition, PermissionConfig } from "../src/types.ts";
import {
  createDelegationPlanner,
  DELEGATION_MODE,
  parseDelegationConfig,
  type DelegationInput,
  type DelegationPlan,
  type LegacyDelegation,
} from "../src/permission/delegation.ts";
import { POLICY_FILE_NAME, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";
import { registerPolicyGate } from "../src/permission/policy-gate.ts";
import {
  POLICY_SNAPSHOT_ENV,
  readPolicySnapshot,
  SNAPSHOT_STATUS,
  type PolicySnapshot,
} from "../src/permission/policy-snapshot.ts";

type ToolModule = typeof import("../src/subagent/tool.ts");
let toolMod: ToolModule | undefined;
try {
  toolMod = await import("../src/subagent/tool.ts");
} catch {
  toolMod = undefined;
}
const runTool = toolMod ? test : test.skip;

// ─── Fixtures ────────────────────────────────────────────────────────────────

const ROLE = DELEGATION_MODE.role;
const RESTRICT = DELEGATION_MODE.restrict;
const DEPTH_ENV = "PI_OPEN_AGENTS_DEPTH";
const NAME_ENV = "PI_OPEN_AGENTS_NAME";
const PARENT_RULES_ENV = "PI_OPEN_AGENTS_PARENT_RULES";
const SNAPSHOT_BLOCK = new RegExp(`invalid ${POLICY_SNAPSHOT_ENV}`);
const NO_LEGACY: LegacyDelegation = { parentCeiling: ["read", "grep"], parentRules: [{ permission: "edit", pattern: "*", action: "deny" }] };

interface Box {
  root: string;
  cwd: string;
  home: string;
  agentDir: string;
}

function withBox(fn: (box: Box) => Promise<void> | void): () => Promise<void> {
  return async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-deleg-")));
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

function writeUserPolicy(box: Box, extra: Record<string, unknown> = {}): void {
  writeFileSync(join(box.agentDir, POLICY_FILE_NAME), JSON.stringify({ version: 1, ...extra }));
}

function writeProjectPolicy(box: Box): void {
  writeFileSync(join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), JSON.stringify({ version: 1, agents: {} }));
}

function writeProjectAgents(dir: string, agents: Record<string, PermissionConfig>): void {
  mkdirSync(join(dir, PROJECT_POLICY_DIR), { recursive: true });
  writeFileSync(join(dir, PROJECT_POLICY_DIR, POLICY_FILE_NAME), JSON.stringify({ version: 1, agents }));
}

function defineAgent(
  box: Box,
  name: string,
  fields: { permission?: PermissionConfig; allowedAgents?: string[]; source?: "global" | "project"; delegation?: Record<string, string> },
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
    source: fields.source ?? "global",
    filePath,
    permission: fields.permission,
    allowedAgents: fields.allowedAgents,
  };
}

const ARCHITECT_PERMISSION: PermissionConfig = { edit: "deny", write: "deny", bash: { "git status": "allow" } };
const IMPLEMENTER_PERMISSION: PermissionConfig = { edit: "allow", write: "allow", bash: { "*": "allow" } };

function team(box: Box, source: "global" | "project" = "global") {
  const architect = defineAgent(box, "architect", {
    permission: ARCHITECT_PERMISSION,
    allowedAgents: ["implementer", "reviewer"],
    delegation: { implementer: ROLE },
    source,
  });
  const implementer = defineAgent(box, "implementer", {
    permission: IMPLEMENTER_PERMISSION,
    allowedAgents: ["explorer"],
    source,
  });
  const reviewer = defineAgent(box, "reviewer", {
    permission: { bash: { "*": "allow" } },
    allowedAgents: ["implementer"],
    delegation: { implementer: ROLE },
    source,
  });
  const explorer = defineAgent(box, "explorer", { permission: { bash: { "*": "allow" } }, source });
  return { architect, implementer, reviewer, explorer };
}

function primaryRuntime(box: Box): PolicyRuntime {
  return new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
}

function plan(
  runtime: PolicyRuntime,
  box: Box,
  parent: AgentDefinition,
  child: AgentDefinition,
  childCwd: string = box.cwd,
): DelegationPlan {
  const input: DelegationInput = { activeAgent: parent, agent: child, cwd: box.cwd, childCwd, legacy: NO_LEGACY };
  return createDelegationPlanner({ runtime })(input);
}

function childEnv(child: AgentDefinition, delegation: DelegationPlan): Record<string, string> {
  const snapshot = delegation.extraEnv?.[POLICY_SNAPSHOT_ENV];
  assert.ok(snapshot, "strict-mode plan carries a snapshot");
  return { [DEPTH_ENV]: "1", [NAME_ENV]: child.name, [POLICY_SNAPSHOT_ENV]: snapshot };
}

function childRuntime(box: Box, env: Record<string, string>): PolicyRuntime {
  return new PolicyRuntime({ agentDir: box.agentDir, home: box.home, received: readPolicySnapshot(env) });
}

function decoded(delegation: DelegationPlan): PolicySnapshot {
  return JSON.parse(delegation.extraEnv![POLICY_SNAPSHOT_ENV]) as PolicySnapshot;
}

type Block = { block: true; reason: string } | undefined;
type Handler = (event: unknown, ctx: unknown) => unknown;

function gate(box: Box, runtime: PolicyRuntime, agent: AgentDefinition | undefined, cwd: string = box.cwd) {
  const handlers = new Map<string, Handler>();
  const pi = { on: (event: string, handler: Handler) => handlers.set(event, handler) };
  const notes: string[] = [];
  registerPolicyGate(pi as never, {
    runtime,
    resolveAgent: () => agent,
    inheritedRules: () => [{ permission: "read", pattern: "*", action: "deny" }],
  });
  const ctx = { cwd, hasUI: false, ui: { notify: (message: string) => notes.push(message), select: async () => undefined } };
  return {
    notes,
    start: () => handlers.get("before_agent_start")!({}, ctx),
    call: async (toolName: string, input: Record<string, unknown>) => (await handlers.get("tool_call")!({ toolName, input }, ctx)) as Block,
  };
}

// ─── Frontmatter ─────────────────────────────────────────────────────────────

test("delegation config: role, restrict, invalid and missing", () => {
  const config = parseDelegationConfig(
    "---\nname: a\ndelegation:\n  implementer: role\n  reviewer: restrict\n  explorer: admin\n---\nBody.\n",
    "/x/a.md",
  );
  assert.deepEqual(config.modes, { implementer: ROLE, reviewer: RESTRICT, explorer: RESTRICT });
  assert.equal(config.warnings.length, 1);
  assert.match(config.warnings[0], /delegation\.explorer must be restrict or role, got "admin"/);
  const missing = parseDelegationConfig("---\nname: a\n---\nBody.\n", "/x/a.md");
  assert.deepEqual(missing, { modes: {}, warnings: [] });
  const scalar = parseDelegationConfig("---\nname: a\ndelegation: role\n---\nBody.\n", "/x/a.md");
  assert.deepEqual(scalar.modes, {});
  assert.match(scalar.warnings[0], /must map agent names/);
});

// ─── Role ────────────────────────────────────────────────────────────────────

test(
  "delegation: role lets a trusted implementer edit under a read-only architect",
  withBox(async (box) => {
    writeUserPolicy(box);
    const { architect, implementer } = team(box);
    const delegation = plan(primaryRuntime(box), box, architect, implementer);
    assert.equal(delegation.mode, ROLE);
    assert.equal(delegation.parentCeiling, undefined);
    assert.equal(delegation.parentRules, undefined);
    assert.deepEqual(decoded(delegation).ceilings, []);

    const child = gate(box, childRuntime(box, childEnv(implementer, delegation)), implementer);
    assert.equal(await child.call("edit", { path: "src/a.ts" }), undefined);
    assert.match((await child.call("write", { path: ".pi/x" }))?.reason ?? "", /protected/);
    assert.match((await child.call("bash", { command: "git commit -m x" }))?.reason ?? "", /git write operations are disabled/);
    // Legacy PARENT_RULES are not used with a snapshot (a read deny was injected).
    assert.equal(await child.call("read", { path: "src/a.ts" }), undefined);
  }),
);

test(
  "delegation: role is refused without listing, without trust, and without a policy",
  withBox((box) => {
    const { architect, implementer } = team(box);

    // No policy file: exactly the legacy values, no snapshot.
    const legacy = plan(primaryRuntime(box), box, architect, implementer);
    assert.deepEqual(legacy, { mode: RESTRICT, ...NO_LEGACY, notes: [] });

    writeUserPolicy(box);
    const unlisted = { ...architect, allowedAgents: ["reviewer"] };
    const refused = plan(primaryRuntime(box), box, unlisted, implementer);
    assert.equal(refused.mode, RESTRICT);
    assert.deepEqual(refused.parentCeiling, NO_LEGACY.parentCeiling);
    assert.equal(refused.parentRules, undefined);
    assert.match(refused.notes.join("\n"), /not listed in allowedAgents/);

    const project = team(box, "project");
    const untrusted = plan(primaryRuntime(box), box, project.architect, project.implementer);
    assert.equal(untrusted.mode, RESTRICT);
    assert.match(untrusted.notes.join("\n"), /"architect" is a project agent in an untrusted project/);

    const mixed = plan(primaryRuntime(box), box, architect, project.implementer);
    assert.equal(mixed.mode, RESTRICT);
    assert.match(mixed.notes.join("\n"), /"implementer" is a project agent in an untrusted project/);

    writeUserPolicy(box, { trustedProjects: [box.cwd] });
    const trusted = plan(primaryRuntime(box), box, project.architect, project.implementer);
    assert.equal(trusted.mode, ROLE);
  }),
);

// ─── Restrict ────────────────────────────────────────────────────────────────

test(
  "delegation: a restrict hop keeps the child under the parent's effective policy",
  withBox(async (box) => {
    writeUserPolicy(box);
    const { architect, implementer } = team(box);
    const restricted = { ...architect, allowedAgents: ["implementer"], filePath: join(box.root, "missing.md") };
    const delegation = plan(primaryRuntime(box), box, restricted, implementer);
    assert.equal(delegation.mode, RESTRICT);
    assert.deepEqual(delegation.parentCeiling, NO_LEGACY.parentCeiling);
    assert.deepEqual(decoded(delegation).ceilings.map((c) => c.agentName), ["architect"]);

    const child = gate(box, childRuntime(box, childEnv(implementer, delegation)), implementer);
    const edit = await child.call("edit", { path: "src/a.ts" });
    assert.match(edit?.reason ?? "", /delegating agent "architect"/);
    assert.match((await child.call("bash", { command: "npm test" }))?.reason ?? "", /unlisted command "npm test"/);
    assert.match((await child.call("bash", { command: "echo x > a.txt" }))?.reason ?? "", /cannot change files/);
    assert.equal(await child.call("bash", { command: "git status" }), undefined);
  }),
);

// ─── Nesting ─────────────────────────────────────────────────────────────────

test(
  "delegation: nested hops compose ceilings; role never drops upper ceilings",
  withBox(async (box) => {
    writeUserPolicy(box);
    const { architect, implementer, reviewer, explorer } = team(box);

    const toImplementer = plan(primaryRuntime(box), box, architect, implementer);
    const implementerRuntime = childRuntime(box, childEnv(implementer, toImplementer));
    const toExplorer = plan(implementerRuntime, box, implementer, explorer);
    assert.equal(toExplorer.mode, RESTRICT);
    assert.deepEqual(decoded(toExplorer).ceilings.map((c) => c.agentName), ["implementer"]);

    const toReviewer = plan(primaryRuntime(box), box, { ...architect, allowedAgents: ["reviewer"] }, reviewer);
    assert.equal(toReviewer.mode, RESTRICT);
    const reviewerRuntime = childRuntime(box, childEnv(reviewer, toReviewer));
    const toNested = plan(reviewerRuntime, box, reviewer, implementer);
    assert.equal(toNested.mode, ROLE);
    assert.deepEqual(decoded(toNested).ceilings.map((c) => c.agentName), ["architect"]);
    const nested = gate(box, childRuntime(box, childEnv(implementer, toNested)), implementer);
    assert.match((await nested.call("edit", { path: "src/a.ts" }))?.reason ?? "", /delegating agent "architect"/);
  }),
);

// ─── Child cwd ───────────────────────────────────────────────────────────────

function lead(box: Box, mode: string = ROLE): { lead: AgentDefinition; worker: AgentDefinition } {
  const worker = defineAgent(box, "worker", { permission: { bash: { "*": "allow" } } });
  const lead = defineAgent(box, "lead", { permission: { bash: { "*": "allow" } }, allowedAgents: ["worker"], delegation: { worker: mode } });
  return { lead, worker };
}

test(
  "child cwd: an untrusted parent project's rules never reach a child in a trusted cwd",
  withBox(async (box) => {
    const trustedDir = join(box.root, "trusted");
    writeUserPolicy(box, { trustedProjects: [trustedDir] });
    writeProjectAgents(box.cwd, { scout: { bash: { "npm test": "allow" } } });
    writeProjectAgents(trustedDir, { scout: { bash: { make: "allow" } } });
    const scout = defineAgent(box, "scout", {});
    const parent = defineAgent(box, "lead", { permission: { bash: { "*": "allow" } }, allowedAgents: ["scout"], delegation: { scout: ROLE } });

    const delegation = plan(primaryRuntime(box), box, parent, scout, trustedDir);
    assert.equal(delegation.mode, ROLE);
    const snapshot = decoded(delegation);
    assert.equal(snapshot.files.project.path, join(trustedDir, PROJECT_POLICY_DIR, POLICY_FILE_NAME));
    assert.equal(snapshot.self.trusted, true);

    const child = gate(box, childRuntime(box, childEnv(scout, delegation)), scout, trustedDir);
    assert.equal(await child.call("bash", { command: "make" }), undefined);
    assert.match((await child.call("bash", { command: "npm test" }))?.reason ?? "", /unlisted command "npm test"/);
  }),
);

test(
  "child cwd: the child cwd's own project denies apply under role and restrict",
  withBox(async (box) => {
    writeUserPolicy(box);
    const otherDir = join(box.root, "other");
    writeProjectAgents(otherDir, { "*": { bash: { "rm *": "deny" } } });
    for (const mode of [ROLE, RESTRICT]) {
      const pair = lead(box, mode);
      const delegation = plan(primaryRuntime(box), box, pair.lead, pair.worker, otherDir);
      assert.equal(delegation.mode, mode);
      const child = gate(box, childRuntime(box, childEnv(pair.worker, delegation)), pair.worker, otherDir);
      assert.match((await child.call("bash", { command: "rm -rf x" }))?.reason ?? "", /rm/, mode);
      assert.equal(await child.call("bash", { command: "ls" }), undefined, mode);
    }

    // An invalid child project file fails closed.
    writeFileSync(join(otherDir, PROJECT_POLICY_DIR, POLICY_FILE_NAME), "{broken");
    const pair = lead(box);
    const delegation = plan(primaryRuntime(box), box, pair.lead, pair.worker, otherDir);
    const child = gate(box, childRuntime(box, childEnv(pair.worker, delegation)), pair.worker, otherDir);
    assert.match((await child.call("bash", { command: "ls" }))?.reason ?? "", /invalid policy file/);
  }),
);

test(
  "child cwd: the same cwd reuses the parent's snapshot project file",
  withBox(async (box) => {
    writeUserPolicy(box);
    writeProjectAgents(box.cwd, { worker: { bash: { "rm *": "deny" } } });
    const pair = lead(box);
    const runtime = primaryRuntime(box);
    runtime.beginRun(box.cwd, pair.lead);
    writeProjectAgents(box.cwd, {});

    const delegation = plan(runtime, box, pair.lead, pair.worker, box.cwd);
    assert.deepEqual(decoded(delegation).files.project.policy?.agents, { worker: { bash: { "rm *": "deny" } } });
    const child = gate(box, childRuntime(box, childEnv(pair.worker, delegation)), pair.worker);
    assert.match((await child.call("bash", { command: "rm x" }))?.reason ?? "", /rm/);
  }),
);

test(
  "child cwd: a subdirectory of the parent cwd keeps the parent's project rules and trust",
  withBox(async (box) => {
    const srcDir = join(box.cwd, "src");
    writeUserPolicy(box, { trustedProjects: [srcDir] });
    writeProjectAgents(box.cwd, { worker: { bash: { "rm *": "deny" } }, "*": { bash: { "curl *": "deny" } } });
    for (const mode of [ROLE, RESTRICT]) {
      const pair = lead(box, mode);
      const delegation = plan(primaryRuntime(box), box, pair.lead, pair.worker, srcDir);
      assert.equal(delegation.mode, mode);
      const snapshot = decoded(delegation);
      assert.equal(snapshot.files.project.path, join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME));
      // Trust is the parent cwd's, not the subdirectory's.
      assert.equal(snapshot.self.trusted, false, mode);
      const child = gate(box, childRuntime(box, childEnv(pair.worker, delegation)), pair.worker, srcDir);
      assert.match((await child.call("bash", { command: "rm -rf x" }))?.reason ?? "", /rm/, mode);
      assert.match((await child.call("bash", { command: "curl x" }))?.reason ?? "", /curl/, mode);
      assert.equal(await child.call("bash", { command: "ls" }), undefined, mode);
    }
  }),
);

test(
  "child cwd: outside the parent cwd the nearest ancestor project file and its trust apply",
  withBox(async (box) => {
    const otherDir = join(box.root, "other");
    const subDir = join(otherDir, "sub");
    mkdirSync(subDir, { recursive: true });
    writeUserPolicy(box, { trustedProjects: [otherDir] });
    writeProjectAgents(otherDir, { worker: { bash: { "rm *": "deny" } } });
    const pair = lead(box);
    const delegation = plan(primaryRuntime(box), box, pair.lead, pair.worker, subDir);
    assert.equal(delegation.mode, ROLE);
    const snapshot = decoded(delegation);
    assert.equal(snapshot.files.project.path, join(otherDir, PROJECT_POLICY_DIR, POLICY_FILE_NAME));
    assert.equal(snapshot.self.trusted, true);
    const child = gate(box, childRuntime(box, childEnv(pair.worker, delegation)), pair.worker, subDir);
    assert.match((await child.call("bash", { command: "rm x" }))?.reason ?? "", /rm/);
    assert.equal(await child.call("bash", { command: "ls" }), undefined);
  }),
);

test(
  "child cwd: a relative cwd is resolved against process.cwd() like the spawn",
  withBox((box) => {
    writeUserPolicy(box);
    const otherDir = join(box.root, "other");
    writeProjectAgents(otherDir, { worker: { bash: { "rm *": "deny" } } });
    const pair = lead(box);
    const delegation = plan(primaryRuntime(box), box, pair.lead, pair.worker, relative(process.cwd(), otherDir));
    assert.equal(decoded(delegation).files.project.path, join(otherDir, PROJECT_POLICY_DIR, POLICY_FILE_NAME));
  }),
);

test(
  "child cwd: a role child in a subdirectory cannot write the project root's protected paths",
  withBox(async (box) => {
    const srcDir = join(box.cwd, "src");
    writeUserPolicy(box, { alwaysDeny: { paths: ["secrets/**"] } });
    writeProjectPolicy(box);
    const { architect, implementer } = team(box);
    const delegation = plan(primaryRuntime(box), box, architect, implementer, srcDir);
    assert.equal(delegation.mode, ROLE);
    const patterns = decoded(delegation).self.hardRules.map((rule) => rule.pattern);
    assert.ok(patterns.includes(join(box.cwd, ".pi/**")));
    assert.ok(patterns.includes(join(srcDir, ".pi/**")));

    const child = gate(box, childRuntime(box, childEnv(implementer, delegation)), implementer, srcDir);
    assert.equal(await child.call("edit", { path: "a.ts" }), undefined);
    for (const target of [join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), join(box.cwd, ".git", "config"), join(box.cwd, "secrets", "key")]) {
      assert.match((await child.call("edit", { path: target }))?.reason ?? "", /protected/, target);
    }
    assert.match((await child.call("bash", { command: "echo x > ../.pi/permissions.json" }))?.reason ?? "", /protected/);
    // Deleting the project root itself removes its anchored protected locations.
    assert.match((await child.call("bash", { command: `rm -rf ${box.cwd}` }))?.reason ?? "", /protected location/);
  }),
);

test(
  "protected paths: .pi, .git, .opencode and .agents are protected in every directory",
  withBox(async (box) => {
    writeUserPolicy(box);
    const worker = defineAgent(box, "worker", { permission: { edit: "allow", write: "allow", bash: { "*": "allow" } } });
    const primary = gate(box, primaryRuntime(box), worker);
    const other = join(box.root, "b");
    for (const target of [join(other, ".pi", POLICY_FILE_NAME), join(other, ".GIT", "config"), join(other, ".git"), join(other, ".agents", "x.md"), join(other, ".opencode", "x")]) {
      assert.match((await primary.call("edit", { path: target }))?.reason ?? "", /protected/, target);
    }
    assert.match((await primary.call("bash", { command: `rm -rf ${join(other, ".pi")}` }))?.reason ?? "", /protected/);
    assert.match((await primary.call("bash", { command: `echo x > ${join(other, ".git", "config")}` }))?.reason ?? "", /protected/);
    assert.equal(await primary.call("bash", { command: `rm -rf ${join(other, "build")}` }), undefined);
    assert.equal(await primary.call("bash", { command: `rm -rf ${join(other, "build")}/*.o` }), undefined);
    assert.equal(await primary.call("edit", { path: join(other, "src", "a.ts") }), undefined);
  }),
);

// ─── Inherited ───────────────────────────────────────────────────────────────

test(
  "inherited: a legacy grandparent's deny survives a strict child and a role grandchild",
  withBox(async (box) => {
    writeProjectPolicy(box);
    const { implementer, reviewer, explorer } = team(box);
    const grandparentDeny = { permission: "edit", pattern: "*", action: "deny" as const };
    // Strict via its own project file, no snapshot: the legacy parent's env rules seed its inherited set.
    const strictChild = new PolicyRuntime({ agentDir: box.agentDir, home: box.home, inherited: [grandparentDeny] });

    const toGrandchild = plan(strictChild, box, reviewer, implementer);
    assert.equal(toGrandchild.mode, ROLE);
    assert.deepEqual(decoded(toGrandchild).ceilings, []);
    assert.deepEqual(decoded(toGrandchild).inherited, [grandparentDeny]);

    const grandchildRuntime = childRuntime(box, childEnv(implementer, toGrandchild));
    const grandchild = gate(box, grandchildRuntime, implementer);
    assert.match((await grandchild.call("edit", { path: "src/a.ts" }))?.reason ?? "", /rule edit "\*"/);
    assert.equal(await grandchild.call("bash", { command: "npm test" }), undefined);

    // Restrict hops hand the set down unchanged too.
    const toExplorer = plan(grandchildRuntime, box, implementer, explorer);
    assert.equal(toExplorer.mode, RESTRICT);
    assert.deepEqual(decoded(toExplorer).inherited, [grandparentDeny]);
  }),
);

// ─── Snapshot ────────────────────────────────────────────────────────────────

test(
  "snapshot: malformed, wrong version or wrong agent blocks every call",
  withBox(async (box) => {
    writeUserPolicy(box);
    const { architect, implementer } = team(box);
    const good = childEnv(implementer, plan(primaryRuntime(box), box, architect, implementer));
    const wrongVersion = { ...JSON.parse(good[POLICY_SNAPSHOT_ENV]), version: 2 };
    const noInherited = { ...JSON.parse(good[POLICY_SNAPSHOT_ENV]), inherited: undefined };
    const allowInherited = { ...JSON.parse(good[POLICY_SNAPSHOT_ENV]), inherited: [{ permission: "edit", pattern: "*", action: "allow" }] };
    const cases: Record<string, string>[] = [
      { ...good, [POLICY_SNAPSHOT_ENV]: "{not json" },
      { ...good, [POLICY_SNAPSHOT_ENV]: JSON.stringify(wrongVersion) },
      { ...good, [POLICY_SNAPSHOT_ENV]: JSON.stringify(noInherited) },
      { ...good, [POLICY_SNAPSHOT_ENV]: JSON.stringify(allowInherited) },
      { ...good, [NAME_ENV]: "explorer" },
    ];
    for (const env of cases) {
      const received = readPolicySnapshot(env);
      assert.equal(received?.status, SNAPSHOT_STATUS.invalid);
      const runtime = childRuntime(box, env);
      assert.equal(runtime.isActive(box.cwd), true);
      const child = gate(box, runtime, implementer);
      child.start();
      child.start();
      assert.equal(child.notes.length, 1);
      assert.match(child.notes[0], SNAPSHOT_BLOCK);
      for (const [tool, input] of [["read", { path: "src/a.ts" }], ["subagent", { agent: "x", task: "t" }]] as const) {
        assert.match((await child.call(tool, input))?.reason ?? "", SNAPSHOT_BLOCK);
      }
    }
    // Absent or primary process: no snapshot, files are read as before.
    assert.equal(readPolicySnapshot({ [NAME_ENV]: "implementer", [DEPTH_ENV]: "1" }), undefined);
    assert.equal(readPolicySnapshot({ [POLICY_SNAPSHOT_ENV]: good[POLICY_SNAPSHOT_ENV] }), undefined);
  }),
);

test(
  "snapshot: user agents survive the encode/read round trip",
  withBox((box) => {
    const userAgents: Record<string, PermissionConfig> = { "*": { bash: { "npm test": "allow" } }, implementer: { edit: "ask" } };
    writeUserPolicy(box, { agents: userAgents });
    const { architect, implementer } = team(box);
    const env = childEnv(implementer, plan(primaryRuntime(box), box, architect, implementer));
    const received = readPolicySnapshot(env);
    assert.equal(received?.status, SNAPSHOT_STATUS.valid);
    if (received?.status !== SNAPSHOT_STATUS.valid) return;
    assert.deepEqual(received.snapshot.files.user.policy?.agents, userAgents);
  }),
);

test(
  "snapshot: a child never reads policy files after the snapshot",
  withBox(async (box) => {
    writeUserPolicy(box);
    const { architect, implementer, explorer } = team(box);
    const env = childEnv(implementer, plan(primaryRuntime(box), box, architect, implementer));
    writeUserPolicy(box, { alwaysDeny: { tools: ["edit"] } });
    writeFileSync(join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), "{broken");

    const runtime = childRuntime(box, env);
    const child = gate(box, runtime, implementer);
    child.start();
    assert.deepEqual(child.notes, []);
    assert.equal(await child.call("edit", { path: "src/a.ts" }), undefined);
    // The grandchild is resolved from the snapshot files too.
    const toExplorer = plan(runtime, box, implementer, explorer);
    assert.equal(decoded(toExplorer).files.project.status, "missing");
    assert.deepEqual(decoded(toExplorer).self.hardRules.filter((rule) => rule.permission === "edit" && rule.pattern === "*"), []);

    // A fresh primary reads the changed files.
    const fresh = gate(box, primaryRuntime(box), implementer);
    assert.ok(await fresh.call("edit", { path: "src/a.ts" }));
  }),
);

test(
  "snapshot: a project policy alone also produces a snapshot",
  withBox((box) => {
    writeProjectPolicy(box);
    const { architect, implementer } = team(box);
    const delegation = plan(primaryRuntime(box), box, architect, implementer);
    assert.ok(delegation.extraEnv?.[POLICY_SNAPSHOT_ENV]);
    assert.equal(readPolicySnapshot(childEnv(implementer, delegation))?.status, SNAPSHOT_STATUS.valid);
  }),
);

// ─── Bash ────────────────────────────────────────────────────────────────────

test(
  "bash validator: alwaysDeny.bash matches command names case-insensitively",
  withBox(async (box) => {
    writeUserPolicy(box, { alwaysDeny: { bash: ["curl", "Npm publish"] } });
    const worker = defineAgent(box, "worker", { permission: { bash: { "*": "allow" } } });
    const primary = gate(box, primaryRuntime(box), worker);
    for (const command of ["CURL x", "/usr/bin/Curl x", "SUDO CURL x", "npm publish", "NPM publish"]) {
      assert.match((await primary.call("bash", { command }))?.reason ?? "", /alwaysDeny\.bash/, command);
    }
    assert.equal(await primary.call("bash", { command: "npm PUBLISH" }), undefined);
  }),
);

// ─── Subagent tool ───────────────────────────────────────────────────────────

type RegisteredTool = {
  name: string;
  execute: (id: string, params: Record<string, unknown>, signal: undefined, onUpdate: undefined, ctx: ToolCtx) => Promise<unknown>;
};

type ToolCtx = { cwd: string; ui?: { notify: (message: string, level: string) => void } };

function registerTool(
  agents: AgentDefinition[],
  options: { active: AgentDefinition; planDelegation?: (input: DelegationInput) => DelegationPlan; env?: Record<string, string> },
) {
  const tools: RegisteredTool[] = [];
  const captured: Array<Record<string, unknown>> = [];
  const pi = { registerTool: (tool: RegisteredTool) => tools.push(tool), getActiveTools: () => ["read", "bash", "edit"] };
  toolMod!.registerSubagentTool(pi as never, {
    agents,
    env: options.env ?? {},
    getActiveAgent: () => options.active,
    planDelegation: options.planDelegation,
    run: async (runOptions) => {
      captured.push(runOptions as unknown as Record<string, unknown>);
      return { agent: runOptions.agent.name, status: "done", output: "ok", tools: [], usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, contextTokens: 0 }, startedAt: 0, elapsedMs: 0, isError: false, exitCode: 0, stderr: "" };
    },
  });
  const tool = tools.find((t) => t.name === "subagent");
  assert.ok(tool);
  return { tool, captured };
}

runTool(
  "subagent tool: without a policy the planner hands down the upstream values",
  withBox(async (box) => {
    const { architect, implementer } = team(box);
    const grandparentRule = { permission: "bash", pattern: "rm *", action: "deny" };
    const env = { [PARENT_RULES_ENV]: JSON.stringify([grandparentRule]) };
    const planned = registerTool([architect, implementer], {
      active: architect,
      planDelegation: createDelegationPlanner({ runtime: primaryRuntime(box) }),
      env,
    });
    const upstream = registerTool([architect, implementer], { active: architect, env });
    const notes: string[] = [];
    const ctx: ToolCtx = { cwd: box.cwd, ui: { notify: (message) => notes.push(message) } };
    for (const { tool } of [planned, upstream]) await tool.execute("1", { agent: "implementer", task: "t" }, undefined, undefined, ctx);
    const [withPlanner] = planned.captured;
    const [without] = upstream.captured;
    assert.deepEqual(withPlanner.parentCeiling, without.parentCeiling);
    assert.deepEqual(withPlanner.parentCeiling, ["read", "bash"]);
    assert.deepEqual(withPlanner.parentRules, without.parentRules);
    assert.ok((withPlanner.parentRules as unknown[]).some((rule) => JSON.stringify(rule) === JSON.stringify(grandparentRule)));
    assert.equal(withPlanner.extraEnv, undefined);
    assert.deepEqual(notes, []);
  }),
);

runTool(
  "subagent tool: plan notes are shown as warnings",
  withBox(async (box) => {
    writeUserPolicy(box);
    const { architect, implementer } = team(box, "project");
    const { tool, captured } = registerTool([architect, implementer], {
      active: architect,
      planDelegation: createDelegationPlanner({ runtime: primaryRuntime(box) }),
    });
    const notes: Array<[string, string]> = [];
    const ctx: ToolCtx = { cwd: box.cwd, ui: { notify: (message, level) => notes.push([message, level]) } };
    await tool.execute("1", { agent: "implementer", task: "t" }, undefined, undefined, ctx);
    assert.equal(captured.length, 1);
    assert.equal(notes.length, 1);
    assert.match(notes[0][0], /role delegation refused.*untrusted project/);
    assert.equal(notes[0][1], "warning");
    // A context without ui does not break the call.
    await tool.execute("2", { agent: "implementer", task: "t" }, undefined, undefined, { cwd: box.cwd });
    assert.equal(captured.length, 2);
  }),
);

runTool(
  "subagent tool: call parameters cannot select the delegation mode",
  withBox(async (box) => {
    writeUserPolicy(box);
    const { architect, implementer, reviewer } = team(box);
    const { tool, captured } = registerTool([architect, implementer, reviewer], {
      active: architect,
      planDelegation: createDelegationPlanner({ runtime: primaryRuntime(box) }),
    });
    const params = { agent: "reviewer", task: "t", mode: ROLE, delegation: ROLE, delegationMode: ROLE };
    await tool.execute("1", params, undefined, undefined, { cwd: box.cwd });
    const [options] = captured;
    assert.deepEqual(options.parentCeiling, ["read", "bash"]);
    const extraEnv = options.extraEnv as Record<string, string>;
    const snapshot = JSON.parse(extraEnv[POLICY_SNAPSHOT_ENV]) as PolicySnapshot;
    assert.equal(snapshot.agent, "reviewer");
    assert.deepEqual(snapshot.ceilings.map((c) => c.agentName), ["architect"]);
    assert.equal(options.parentRules, undefined);
  }),
);
