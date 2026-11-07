/**
 * Tests for the per-run policy snapshot.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { AgentDefinition } from "../src/types.ts";
import { POLICY_FILE_NAME, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";

const agent: AgentDefinition = {
  name: "worker",
  mode: "subagent",
  hidden: true,
  disable: false,
  thinking: "off",
  systemPrompt: "replace",
  maxDepth: 1,
  prompt: "You are a worker.",
  source: "project",
  filePath: "/tmp/worker.agent.md",
};

interface Box {
  cwd: string;
  agentDir: string;
  home: string;
  runtime: PolicyRuntime;
}

function withBox(fn: (box: Box) => void): void {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-runtime-")));
  try {
    const cwd = join(root, "proj");
    const home = join(root, "home");
    const agentDir = join(home, ".pi", "agent");
    for (const dir of [cwd, agentDir]) mkdirSync(dir, { recursive: true });
    fn({ cwd, agentDir, home, runtime: new PolicyRuntime({ agentDir, home }) });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function writeUser(box: Box, body: unknown): void {
  writeFileSync(join(box.agentDir, POLICY_FILE_NAME), typeof body === "string" ? body : JSON.stringify(body));
}

function writeProject(box: Box, body: unknown): void {
  mkdirSync(join(box.cwd, PROJECT_POLICY_DIR), { recursive: true });
  writeFileSync(join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), JSON.stringify(body));
}

test("runtime: inactive without policy files", () => {
  withBox((box) => {
    assert.deepEqual(box.runtime.beginRun(box.cwd), []);
    assert.equal(box.runtime.isActive(box.cwd), false);
    assert.equal(box.runtime.policyFor(agent, box.cwd), undefined);
  });
});

test("runtime: lazily loads on first use", () => {
  withBox((box) => {
    writeUser(box, { version: 1 });
    assert.equal(box.runtime.isActive(box.cwd), true);
    assert.ok(box.runtime.policyFor(agent, box.cwd));
  });
});

test("runtime: snapshot is stable until the next beginRun, which picks up edits", () => {
  withBox((box) => {
    box.runtime.beginRun(box.cwd);
    assert.equal(box.runtime.isActive(box.cwd), false);

    writeUser(box, { version: 1, trustedProjects: [box.cwd] });
    writeProject(box, { version: 1, agents: { worker: { bash: "allow" } } });
    assert.equal(box.runtime.isActive(box.cwd), false);
    assert.equal(box.runtime.policyFor(agent, box.cwd), undefined);

    box.runtime.beginRun(box.cwd);
    const first = box.runtime.policyFor(agent, box.cwd);
    assert.ok(first?.rules.some((r) => r.permission === "bash" && r.action === "allow"));
    assert.equal(box.runtime.policyFor(agent, box.cwd), first, "memoized per agent within the snapshot");

    writeProject(box, { version: 1, agents: { worker: { bash: "deny" } } });
    assert.equal(box.runtime.policyFor(agent, box.cwd), first, "mid-run edits do not apply");

    box.runtime.beginRun(box.cwd);
    const second = box.runtime.policyFor(agent, box.cwd);
    assert.notEqual(second, first);
    assert.ok(second?.rules.some((r) => r.permission === "bash" && r.action === "deny"));
  });
});

test("runtime: warnings are reported once per snapshot content", () => {
  withBox((box) => {
    writeUser(box, "{ broken");
    const first = box.runtime.beginRun(box.cwd);
    assert.equal(first.length, 1);
    assert.match(first[0] ?? "", /invalid JSON/);
    assert.deepEqual(box.runtime.beginRun(box.cwd), [], "same content: not repeated");

    writeUser(box, { version: 2 });
    assert.equal(box.runtime.beginRun(box.cwd).length, 1, "changed content: reported again");

    writeUser(box, { version: 1 });
    assert.deepEqual(box.runtime.beginRun(box.cwd), []);
  });
});

test("runtime: agent-specific warnings surface when the agent is passed", () => {
  withBox((box) => {
    writeUser(box, { version: 1 });
    writeProject(box, { version: 1, agents: { worker: { bash: "allow" } } });
    assert.deepEqual(box.runtime.beginRun(box.cwd), []);
    const warnings = box.runtime.beginRun(box.cwd, agent);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0] ?? "", /not in trustedProjects/);
    assert.deepEqual(box.runtime.beginRun(box.cwd, agent), []);
  });
});
