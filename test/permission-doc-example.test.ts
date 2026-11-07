/**
 * The "Example setup" of PERMISSIONS.md is parsed and run through the real
 * engine, so every rule the doc shows is proven to take effect.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseAgentDefinition } from "../src/config/schema.ts";
import type { AgentDefinition } from "../src/types.ts";
import { createDelegationPlanner, DELEGATION_MODE } from "../src/permission/delegation.ts";
import { POLICY_FILE_NAME, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { decidePolicyCall, decideWithCeilings } from "../src/permission/policy-gate.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";

// ─── Doc extraction ──────────────────────────────────────────────────────────

const DOC_PATH = new URL("../PERMISSIONS.md", import.meta.url);
const EXAMPLE_HEADING = "## Example setup";
const FENCE = /```(json|yaml)\n([\s\S]*?)```/g;
const LANG_JSON = "json";
const LANG_YAML = "yaml";
const ALLOW = "allow";
const DENY = "deny";
const ARCHITECT = "architect";
const CHILDREN = ["implementer", "reviewer", "explorer", "researcher"];

interface ExampleDoc {
  userJson: string;
  projectJson: string;
  agents: { content: string }[];
}

function readExample(): ExampleDoc {
  const doc = readFileSync(DOC_PATH, "utf-8");
  const section = doc.slice(doc.indexOf(EXAMPLE_HEADING));
  const blocks = [...section.matchAll(FENCE)].map((match) => ({ lang: match[1], body: match[2] }));
  const json = blocks.filter((block) => block.lang === LANG_JSON);
  assert.equal(json.length, 2, "user and project policy blocks");
  return {
    userJson: json[0].body,
    projectJson: json[1].body,
    agents: blocks.filter((block) => block.lang === LANG_YAML).map((block) => ({ content: block.body })),
  };
}

// ─── Fixtures ────────────────────────────────────────────────────────────────

interface Box {
  cwd: string;
  agentDir: string;
  home: string;
  agents: Map<string, AgentDefinition>;
  runtime: PolicyRuntime;
}

function withExample(trustedProject: boolean, fn: (box: Box) => void): () => void {
  return () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-doc-")));
    try {
      const home = join(root, "home");
      const projects = join(home, "Projects");
      const cwd = join(trustedProject ? projects : root, "proj");
      const agentDir = join(home, ".pi", "agent");
      const agentsDir = join(agentDir, "agents");
      for (const dir of [join(cwd, "src"), join(cwd, PROJECT_POLICY_DIR), agentsDir]) mkdirSync(dir, { recursive: true });

      const example = readExample();
      writeFileSync(join(agentDir, POLICY_FILE_NAME), example.userJson);
      writeFileSync(join(cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), example.projectJson);
      const agents = new Map<string, AgentDefinition>();
      for (const { content } of example.agents) {
        const nameHint = /^name: (\S+)$/m.exec(content)?.[1];
        assert.ok(nameHint, "agent block has a name");
        const filePath = join(agentsDir, `${nameHint}.md`);
        writeFileSync(filePath, content);
        agents.set(nameHint, parseAgentDefinition(content, filePath, "global"));
      }
      const runtime = new PolicyRuntime({ agentDir, home });
      fn({ cwd, agentDir, home, agents, runtime });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
}

function decide(box: Box, agentName: string, toolName: string, input: Record<string, unknown>) {
  const agent = box.agents.get(agentName);
  assert.ok(agent, agentName);
  const policy = box.runtime.policyFor(agent, box.cwd);
  assert.ok(policy);
  return decidePolicyCall({ toolName, input, policy, inherited: [], cwd: box.cwd, home: box.home });
}

function expectDecision(box: Box, agentName: string, toolName: string, input: Record<string, unknown>, action: string, hard: boolean): void {
  const decision = decide(box, agentName, toolName, input);
  const label = `${agentName} ${toolName} ${JSON.stringify(input)}: ${decision.reason}`;
  assert.equal(decision.action, action, label);
  assert.equal(decision.hard, hard, label);
}

// The architect's policy as a delegation ceiling, which is what `restrict` adds to a child.
function decideRestricted(box: Box, agentName: string, toolName: string, input: Record<string, unknown>) {
  const agent = box.agents.get(agentName);
  const architect = box.agents.get(ARCHITECT);
  assert.ok(agent && architect);
  const policy = box.runtime.policyFor(agent, box.cwd);
  const ceiling = box.runtime.policyFor(architect, box.cwd);
  assert.ok(policy && ceiling);
  return decideWithCeilings({ toolName, input, policy, inherited: [], cwd: box.cwd, home: box.home }, [ceiling]);
}

// ─── Tests ───────────────────────────────────────────────────────────────────

test("doc example: the architect delegates every child in role mode", withExample(true, (box) => {
  const architect = box.agents.get(ARCHITECT);
  assert.ok(architect);
  const plan = createDelegationPlanner({ runtime: box.runtime });
  for (const name of CHILDREN) {
    const child = box.agents.get(name);
    assert.ok(child, name);
    const result = plan({
      activeAgent: architect,
      agent: child,
      cwd: box.cwd,
      childCwd: box.cwd,
      legacy: { parentCeiling: undefined, parentRules: undefined },
    });
    assert.equal(result.mode, DELEGATION_MODE.role, name);
    assert.deepEqual(result.notes, [], name);
  }
}));

test("doc example: researcher fetches but cannot write protected paths with curl", withExample(true, (box) => {
  expectDecision(box, "researcher", "bash", { command: "curl https://x" }, ALLOW, false);
  expectDecision(box, "researcher", "bash", { command: "curl -o .pi/x https://x" }, DENY, true);
}));

test("doc example: reviewer reads git history but cannot commit", withExample(true, (box) => {
  expectDecision(box, "reviewer", "bash", { command: "git show HEAD" }, ALLOW, false);
  expectDecision(box, "reviewer", "bash", { command: "git commit -m x" }, DENY, true);
}));

test("doc example: restrict would add the architect ceiling and block curl and git show", withExample(true, (box) => {
  // Each is allowed under the child's own role (tests above) and denied only by the ceiling.
  for (const [name, command] of [["researcher", "curl https://x"], ["reviewer", "git show HEAD"]]) {
    const decision = decideRestricted(box, name, "bash", { command });
    assert.equal(decision.action, DENY, `${name} ${command}: ${decision.reason}`);
    assert.ok(decision.reason.includes(`delegating agent "${ARCHITECT}"`), decision.reason);
  }
}));

test("doc example: nobody can push", withExample(true, (box) => {
  for (const name of [ARCHITECT, ...CHILDREN]) {
    expectDecision(box, name, "bash", { command: "git push origin main" }, DENY, true);
  }
}));

test("doc example: architect cannot edit, implementer edits sources", withExample(true, (box) => {
  expectDecision(box, "architect", "edit", { path: "src/a.ts" }, DENY, false);
  expectDecision(box, "implementer", "edit", { path: "src/a.ts" }, ALLOW, false);
}));

test("doc example: project pytest is allowed for the implementer only in a trusted project", () => {
  withExample(true, (box) => {
    expectDecision(box, "implementer", "bash", { command: "pytest" }, ALLOW, false);
    expectDecision(box, "reviewer", "bash", { command: "pytest" }, DENY, false);
  })();
  withExample(false, (box) => {
    expectDecision(box, "implementer", "bash", { command: "pytest" }, DENY, false);
  })();
});
