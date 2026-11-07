/**
 * Tests for the strict-mode policy gate: hard denies, strict category
 * defaults, path candidates, inherited ceiling, ask memo and fail-closed paths.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { AgentDefinition, PermissionConfig, PermissionRule } from "../src/types.ts";
import { POLICY_FILE_NAME, PROJECT_POLICY_DIR } from "../src/permission/loader.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";
import { registerPolicyGate } from "../src/permission/policy-gate.ts";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const baseAgent: AgentDefinition = {
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

const ALWAYS = "Allow always (this session)";

type ToolEvent = { toolName: string; input?: Record<string, unknown> };
type Handler = (event: ToolEvent | Record<string, never>, ctx: unknown) => Promise<unknown> | unknown;

interface Box {
  cwd: string;
  home: string;
  agentDir: string;
}

function withBox(fn: (box: Box) => Promise<void>): () => Promise<void> {
  return async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-gate-")));
    try {
      const home = join(root, "home");
      const box = { cwd: join(root, "proj"), home, agentDir: join(home, ".pi", "agent") };
      for (const dir of [join(box.cwd, "src"), box.agentDir]) mkdirSync(dir, { recursive: true });
      await fn(box);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
}

function writeUser(box: Box, body: unknown): void {
  writeFileSync(join(box.agentDir, POLICY_FILE_NAME), JSON.stringify(body));
}

function writeProject(box: Box, agents: Record<string, PermissionConfig>): void {
  mkdirSync(join(box.cwd, PROJECT_POLICY_DIR), { recursive: true });
  writeFileSync(join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), JSON.stringify({ version: 1, agents }));
}

function setup(
  box: Box,
  agent: AgentDefinition | undefined,
  options: { inherited?: PermissionRule[]; hasUI?: boolean; select?: string } = {},
) {
  const handlers = new Map<string, Handler>();
  const pi = {
    on: (event: string, h: Handler) => {
      handlers.set(event, h);
      return () => {};
    },
  };
  const runtime = new PolicyRuntime({ agentDir: box.agentDir, home: box.home });
  registerPolicyGate(pi as never, {
    runtime,
    resolveAgent: () => agent,
    inheritedRules: () => options.inherited ?? [],
  });
  const dialogs: string[] = [];
  const notes: string[] = [];
  const ctx = {
    cwd: box.cwd,
    hasUI: options.hasUI ?? false,
    ui: {
      select: async (title: string) => {
        dialogs.push(title);
        return options.select;
      },
      notify: (msg: string) => notes.push(msg),
    },
  };
  const toolCall = handlers.get("tool_call");
  assert.ok(toolCall && handlers.get("before_agent_start"));
  handlers.get("before_agent_start")?.({}, ctx);
  const call = async (toolName: string, input: Record<string, unknown>) =>
    (await toolCall({ toolName, input }, ctx)) as { block: true; reason: string } | undefined;
  return { call, dialogs, notes };
}

const trustedAllowAll = (box: Box) => {
  writeUser(box, { version: 1, trustedProjects: [box.cwd] });
  writeProject(box, { "*": { edit: "allow", write: "allow", bash: "allow" } });
};

// ─── Tests ───────────────────────────────────────────────────────────────────

test(
  "policy gate: no policy files leaves the call to the legacy gate",
  withBox(async (box) => {
    const { call } = setup(box, baseAgent);
    assert.equal(await call("bash", { command: "rm -rf /" }), undefined);
  }),
);

test(
  "policy gate: hard deny beats trusted allow via src/../.pi spelling",
  withBox(async (box) => {
    trustedAllowAll(box);
    const { call } = setup(box, baseAgent, { hasUI: true });
    assert.equal(await call("edit", { path: "src/a.ts" }), undefined);
    const result = await call("edit", { path: "src/../.pi/x" });
    assert.equal(result?.block, true);
    assert.match(result?.reason ?? "", /^Permission denied\.\nOperation: edit src\/\.\.\/\.pi\/x\nReason: path is protected/);
    assert.match(result?.reason ?? "", /Do not retry/);
  }),
);

test(
  "policy gate: agentDir is protected under absolute and ~/ spellings",
  withBox(async (box) => {
    trustedAllowAll(box);
    const { call } = setup(box, baseAgent);
    assert.equal((await call("write", { path: join(box.agentDir, "agents", "x.md") }))?.block, true);
    assert.equal((await call("write", { file_path: "~/.pi/agent/permissions.json" }))?.block, true);
    assert.equal((await call("write", { path: "@~/.pi/agent/x" }))?.block, true);
    assert.equal(await call("write", { path: "~/notes.md" }), undefined);
  }),
);

test(
  "policy gate: strict defaults per category",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call, dialogs } = setup(box, baseAgent, { hasUI: true, select: "Allow once" });
    const bash = await call("bash", { command: "ls" });
    assert.match(bash?.reason ?? "", /unlisted bash operations are denied by the active permission policy/);
    assert.equal((await call("edit", { path: "src/a.ts" }))?.block, true);
    assert.equal(await call("read", { path: "src/a.ts" }), undefined);
    assert.equal(dialogs.length, 0);
    assert.equal(await call("web_fetch", { url: "https://example.com" }), undefined);
    assert.equal(await call("set_agent", { name: "x" }), undefined);
    assert.equal(dialogs.length, 2, "custom tool and set_agent ask");
  }),
);

test(
  "policy gate: tools whitelist grants listed tools",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, tools: ["read", "edit"] });
    assert.equal(await call("edit", { path: "src/a.ts" }), undefined);
    assert.equal((await call("edit", { path: ".pi/x" }))?.block, true);
    assert.equal((await call("bash", { command: "ls" }))?.block, true);
  }),
);

test(
  "policy gate: relative frontmatter pattern matches an absolute path inside cwd",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, permission: { edit: { "src/**": "allow" } } });
    assert.equal(await call("edit", { path: join(box.cwd, "src", "a.ts") }), undefined);
    assert.equal((await call("edit", { path: join(box.cwd, "lib", "a.ts") }))?.block, true);
  }),
);

test(
  "policy gate: inherited deny applies over own allow",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, tools: ["bash"] }, {
      inherited: [{ permission: "bash", pattern: "rm *", action: "deny" }],
    });
    assert.equal(await call("bash", { command: "ls -la" }), undefined);
    assert.equal((await call("bash", { command: "rm -rf x" }))?.block, true);
  }),
);

test(
  "policy gate: blanket deny then relative allow is last-match-wins across candidates",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, permission: { edit: { "*": "deny", "src/**": "allow" } } });
    assert.equal(await call("edit", { path: "src/a.ts" }), undefined);
    assert.equal((await call("edit", { path: "lib/a.ts" }))?.block, true);
  }),
);

test(
  "policy gate: blanket ask then relative allow does not ask",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call, dialogs } = setup(box, { ...baseAgent, permission: { edit: { "*": "ask", "src/**": "allow" } } }, {
      hasUI: true,
      select: "Deny",
    });
    assert.equal(await call("edit", { path: "src/a.ts" }), undefined);
    assert.equal(dialogs.length, 0);
  }),
);

test(
  "policy gate: later absolute deny beats earlier allow",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, {
      ...baseAgent,
      permission: { edit: { "**": "allow", [`${box.cwd}/secret/**`]: "deny" } },
    });
    assert.equal(await call("edit", { path: "src/a.ts" }), undefined);
    const result = await call("edit", { path: "secret/key.ts" });
    assert.match(result?.reason ?? "", /Reason: rule edit "/);
  }),
);

test(
  "policy gate: inherited path deny beats own path allow",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, permission: { edit: { "src/**": "allow" } } }, {
      inherited: [{ permission: "edit", pattern: "src/secret.ts", action: "deny" }],
    });
    assert.equal(await call("edit", { path: "src/a.ts" }), undefined);
    assert.equal((await call("edit", { path: "src/secret.ts" }))?.block, true);
  }),
);

for (const tool of ["edit", "write"]) {
  test(
    `policy gate: ${tool} with a protected path key and an allowed path key is denied`,
    withBox(async (box) => {
      trustedAllowAll(box);
      const { call } = setup(box, baseAgent);
      const protectedFirst = await call(tool, { path: ".pi/permissions.json", file_path: "src/ok.ts" });
      assert.equal(protectedFirst?.block, true);
      const allowedFirst = await call(tool, { file_path: "src/ok.ts", path: ".pi/permissions.json" });
      assert.equal(allowedFirst?.block, true);
      const swapped = await call(tool, { path: "src/ok.ts", file_path: ".pi/permissions.json" });
      assert.equal(swapped?.block, true);
      assert.equal(await call(tool, { path: "src/ok.ts", file_path: "src/ok.ts" }), undefined);
    }),
  );
}

test(
  "policy gate: a decoy file_path cannot loosen a regular deny on path",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, {
      ...baseAgent,
      permission: { edit: { "*": "deny", "secret/**": "deny", "src/**": "allow" } },
    });
    const pathFirst = await call("edit", { path: "secret/a.ts", file_path: "src/ok.ts" });
    assert.equal(pathFirst?.block, true);
    assert.match(pathFirst?.reason ?? "", /Operation: edit secret\/a\.ts \(also file_path: src\/ok\.ts\)/);
    assert.equal((await call("edit", { file_path: "src/ok.ts", path: "secret/a.ts" }))?.block, true);
    assert.equal((await call("edit", { path: "src/ok.ts", file_path: "secret/a.ts" }))?.block, true);
    assert.equal(await call("edit", { path: "src/ok.ts", file_path: "src/ok.ts" }), undefined);
  }),
);

test(
  "policy gate: ask with two path keys shows both and memoizes the exact pair",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call, dialogs } = setup(box, { ...baseAgent, permission: { edit: { "*": "ask", "src/**": "allow" } } }, {
      hasUI: true,
      select: ALWAYS,
    });
    assert.equal(await call("edit", { path: "lib/a.ts", file_path: "src/ok.ts" }), undefined);
    assert.deepEqual(dialogs, ["Permission: allow edit: lib/a.ts (also file_path: src/ok.ts)?"]);
    assert.equal(await call("edit", { file_path: "src/ok.ts", path: "lib/a.ts" }), undefined);
    assert.equal(dialogs.length, 1, "same pair is covered");
    assert.equal(await call("edit", { path: "lib/a.ts", file_path: "src/other.ts" }), undefined);
    assert.equal(dialogs.length, 2, "different pair asks again");
    assert.equal(await call("edit", { path: "lib/a.ts" }), undefined);
    assert.equal(dialogs.length, 3, "single key is a different set");
  }),
);

test(
  "policy gate: grep with only file_path is decided as a path-less call",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, permission: { grep: { "*": "allow", "secret/**": "deny" } } });
    assert.equal(await call("grep", { pattern: "x", file_path: "secret/a.ts" }), undefined);
    assert.equal((await call("grep", { pattern: "x", path: "secret/a.ts" }))?.block, true);
  }),
);

test(
  "policy gate: apply_patch is a file tool under the hard check",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, permission: { edit: "allow" } });
    assert.equal(await call("apply_patch", { path: "src/a.ts" }), undefined);
    assert.equal((await call("apply_patch", { path: ".pi/x" }))?.block, true);
  }),
);

test(
  "policy gate: hard protection ignores case for missing directories",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, permission: { write: "allow" } });
    assert.equal(await call("write", { path: "src/a.ts" }), undefined);
    assert.match((await call("write", { path: ".PI/extensions/x.ts" }))?.reason ?? "", /path is protected/);
    assert.match((await call("write", { path: ".Git/config" }))?.reason ?? "", /path is protected/);
  }),
);

test(
  "policy gate: headless ask is blocked fail-closed",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, permission: { bash: "ask" } });
    assert.match((await call("bash", { command: "ls" }))?.reason ?? "", /non-interactive/);
  }),
);

test(
  "policy gate: always memo for bash is per command",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call, dialogs } = setup(box, { ...baseAgent, permission: { bash: "ask" } }, {
      hasUI: true,
      select: ALWAYS,
    });
    assert.equal(await call("bash", { command: "ls" }), undefined);
    assert.equal(await call("bash", { command: "ls" }), undefined);
    assert.equal(dialogs.length, 1);
    assert.equal(await call("bash", { command: "pwd" }), undefined);
    assert.equal(dialogs.length, 2);
  }),
);

test(
  "policy gate: hard deny never shows a dialog",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call, dialogs } = setup(box, { ...baseAgent, permission: { edit: "ask" } }, {
      hasUI: true,
      select: ALWAYS,
    });
    assert.equal((await call("edit", { path: ".git/config" }))?.block, true);
    assert.equal(dialogs.length, 0);
  }),
);

test(
  "policy gate: an exception inside the decision blocks",
  withBox(async (box) => {
    writeUser(box, { version: 1 });
    const { call } = setup(box, { ...baseAgent, tools: ["read"] });
    const input = {
      get path(): string {
        throw new Error("boom");
      },
    };
    const result = await call("read", input);
    assert.equal(result?.block, true);
    assert.match(result?.reason ?? "", /fail-closed.*boom/);
  }),
);

test(
  "policy gate: invalid policy file warns once and blocks risky tools",
  withBox(async (box) => {
    writeFileSync(join(box.agentDir, POLICY_FILE_NAME), "{ broken");
    const { call, notes } = setup(box, { ...baseAgent, tools: ["bash"] });
    assert.equal(notes.length, 1);
    assert.match((await call("bash", { command: "ls" }))?.reason ?? "", /invalid policy file/);
  }),
);

test(
  "policy gate: apply_patch without a path field is a hard deny under blanket edit allow",
  withBox(async (box) => {
    trustedAllowAll(box);
    const { call, dialogs } = setup(box, baseAgent, { hasUI: true });
    for (const field of ["patch", "input"]) {
      const result = await call("apply_patch", { [field]: "*** Begin Patch\n*** Update File: .pi/x\n*** End Patch" });
      assert.equal(result?.block, true);
      assert.match(result?.reason ?? "", /cannot verify the target path of a file-changing call/);
    }
    assert.equal(dialogs.length, 0);
  }),
);

test(
  "policy gate: write without a path field is denied under blanket allow",
  withBox(async (box) => {
    trustedAllowAll(box);
    const { call } = setup(box, baseAgent);
    const result = await call("write", { content: "x" });
    assert.equal(result?.block, true);
    assert.match(result?.reason ?? "", /cannot verify the target path/);
    assert.equal(await call("write", { path: "src/a.ts", content: "x" }), undefined);
  }),
);

test(
  "policy gate: read without a path field keeps the safe-category default",
  withBox(async (box) => {
    trustedAllowAll(box);
    const { call } = setup(box, baseAgent);
    assert.equal(await call("read", {}), undefined);
  }),
);
