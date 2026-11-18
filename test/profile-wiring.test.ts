/**
 * Profile wiring: virtual models registered by the real factory resolve a
 * physical model at request time, follow the active profile live, and bind
 * only agents whose frontmatter has no model.
 *
 * PI_CODING_AGENT_DIR points getAgentDir() at a tmp dir, never ~/.pi/agent;
 * HOME and USERPROFILE point at a tmp dir so home discovery never reads the
 * real home. A parent pi process exports PI_OPEN_AGENTS_* vars, so every test
 * that needs one sets it explicitly and restores it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Profile } from "../src/profile/schema.ts";
import { PROFILE_PROVIDER } from "../src/profile/schema.ts";
import {
  PROFILE_LAYER_ENV,
  PROFILES_COMMAND,
  PROFILE_STATUS_KEY,
  SUBAGENT_TOOL_NAME,
} from "../src/profile/runtime.ts";

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
const DEPTH_ENV = "PI_OPEN_AGENTS_DEPTH";

// ─── Workspace ───────────────────────────────────────────────────────────────

interface Workspace {
  root: string;
  cwd: string;
  agentDir: string;
  writeAgent(name: string, options?: { model?: string }): void;
  writeProfile(name: string, profile: Profile): void;
  writeLayer(layer: unknown): void;
  removeLayer(): void;
  writeState(name: string, pretty?: boolean): void;
  dispose(): void;
}

function makeWorkspace(): Workspace {
  const root = mkdtempSync(join(tmpdir(), "poa-profile-"));
  const cwd = join(root, "project");
  mkdirSync(join(cwd, ".pi", "agents"), { recursive: true });
  const agentDir = join(root, "agent-home");
  mkdirSync(join(agentDir, "agents"), { recursive: true });
  const home = join(root, "user-home");
  mkdirSync(home, { recursive: true });

  const overrides: Record<string, string> = { [AGENT_DIR_ENV]: agentDir };
  for (const name of HOME_ENVS) overrides[name] = home;
  const previous = new Map(Object.keys(overrides).map((name) => [name, process.env[name]]));
  Object.assign(process.env, overrides);

  const profilesDir = join(agentDir, "profiles");
  const layerPath = join(cwd, ".pi", "profile.json");
  const statePath = join(agentDir, "profile-state.json");

  return {
    root,
    cwd,
    agentDir,
    writeAgent(name, options = {}) {
      const model = options.model === undefined ? "" : `model: ${options.model}\n`;
      writeFileSync(
        join(cwd, ".pi", "agents", `${name}.agent.md`),
        `---\nname: ${name}\nmode: primary\ndescription: profile test\n${model}---\nBody.\n`,
      );
    },
    writeProfile(name, profile) {
      mkdirSync(profilesDir, { recursive: true });
      writeFileSync(join(profilesDir, `${name}.json`), `${JSON.stringify(profile, null, 2)}\n`);
    },
    writeLayer(layer) {
      writeFileSync(layerPath, `${JSON.stringify(layer, null, 2)}\n`);
    },
    removeLayer() {
      rmSync(layerPath, { force: true });
    },
    writeState(name, pretty = false) {
      const body = pretty ? JSON.stringify({ active: name }, null, 2) : JSON.stringify({ active: name });
      writeFileSync(statePath, `${body}\n`);
    },
    dispose() {
      rmSync(root, { recursive: true, force: true });
      for (const [name, value] of previous) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    },
  };
}

// ─── Harness ─────────────────────────────────────────────────────────────────

interface FakeModel {
  provider: string;
  id: string;
  name?: string;
  api?: string;
}

interface VirtualModel {
  provider: string;
  id: string;
  name: string;
  thinkingLevels: readonly string[];
  route(request: unknown, ctx: unknown): unknown;
}

type Handler = (event: never, ctx: never) => unknown;

interface HarnessOptions {
  cwd: string;
  entries?: unknown[];
  trusted?: boolean;
  hasUI?: boolean;
  initialModel?: FakeModel;
  physical?: FakeModel[];
  flags?: Record<string, string>;
  selectResult?: string;
  setModelResult?: boolean;
}

function makeHarness(options: HarnessOptions) {
  assert.ok(piOpenAgents, "factory available");

  const handlers = new Map<string, Handler[]>();
  const virtualModels = new Map<string, VirtualModel>();
  const virtualObjects = new Map<string, FakeModel>();
  const commands = new Map<
    string,
    {
      description?: string;
      getArgumentCompletions?: (prefix: string) => Array<{ value: string; label: string }> | null;
      handler: (args: string, ctx: never) => Promise<void>;
    }
  >();
  const notifications: Array<{ message: string; level?: string }> = [];
  const statuses = new Map<string, string | undefined>();
  const setModels: FakeModel[] = [];
  const flags = new Map(Object.entries(options.flags ?? {}));
  const physical = options.physical ?? [];
  const entries = options.entries ?? [];
  const builtinTools = ["read", "bash", "edit", "write", "grep", "find", "ls"];

  let currentModel = options.initialModel;
  let thinkingLevel = "off";
  let selected = options.selectResult;

  const pi = {
    on(event: string, handler: Handler) {
      handlers.set(event, [...(handlers.get(event) ?? []), handler]);
      return () => {};
    },
    registerFlag() {},
    registerCommand(
      name: string,
      definition: {
        description?: string;
        getArgumentCompletions?: (prefix: string) => Array<{ value: string; label: string }> | null;
        handler: (args: string, ctx: never) => Promise<void>;
      },
    ) {
      commands.set(name, definition);
    },
    registerTool() {},
    registerShortcut() {},
    registerVirtualModel(definition: VirtualModel) {
      virtualModels.set(definition.id, definition);
      virtualObjects.set(definition.id, {
        provider: definition.provider,
        id: definition.id,
        name: definition.name,
        api: "pi-virtual",
      });
    },
    unregisterVirtualModel(_provider: string, id: string) {
      virtualModels.delete(id);
      virtualObjects.delete(id);
    },
    getFlag(name: string) {
      return flags.get(name);
    },
    getAllTools() {
      return builtinTools.map((name) => ({ name, sourceInfo: { source: "builtin" } }));
    },
    getActiveTools() {
      return builtinTools.slice();
    },
    setActiveTools() {},
    getThinkingLevel() {
      return thinkingLevel;
    },
    setThinkingLevel(level: string) {
      thinkingLevel = level;
    },
    async setModel(model: FakeModel) {
      setModels.push(model);
      if (options.setModelResult === false) return false;
      currentModel = model;
      return true;
    },
    appendEntry() {},
  };

  const ctx = {
    cwd: options.cwd,
    get model() {
      return currentModel;
    },
    mode: "tui",
    hasUI: options.hasUI ?? true,
    ui: {
      notify(message: string, level?: string) {
        notifications.push({ message, level });
      },
      async select() {
        return selected;
      },
      theme: {
        bold: (text: string) => text,
        fg: (_color: string, text: string) => text,
      },
      setWidget() {},
      setStatus(key: string, text: string | undefined) {
        statuses.set(key, text);
      },
    },
    isProjectTrusted: () => options.trusted ?? false,
    modelRegistry: {
      find(provider: string, id: string) {
        if (provider === PROFILE_PROVIDER) return virtualObjects.get(id);
        return physical.find((model) => model.provider === provider && model.id === id);
      },
      getAvailable() {
        return [...virtualObjects.values(), ...physical];
      },
    },
    sessionManager: {
      getEntries: () => entries,
      getSessionFile: () => undefined,
      getLeafId: () => undefined,
    },
  };

  piOpenAgents(pi as never);

  async function start(reason = "startup") {
    for (const handler of [...(handlers.get("session_start") ?? [])]) {
      await handler({ type: "session_start", reason } as never, ctx as never);
    }
  }

  async function callTool(toolName: string, input: Record<string, unknown>) {
    for (const handler of handlers.get("tool_call") ?? []) {
      const result = (await handler(
        { type: "tool_call", toolCallId: "call-1", toolName, input } as never,
        ctx as never,
      )) as { block?: boolean; reason?: string } | undefined;
      if (result) return result;
    }
    return undefined;
  }

  async function route(modelId: string, request: Record<string, unknown>) {
    const definition = virtualModels.get(modelId);
    assert.ok(definition, `virtual model ${modelId} is registered`);
    return (await definition.route(
      {
        model: virtualObjects.get(modelId),
        thinkingLevel: "off",
        messages: [],
        ...request,
      } as never,
      ctx as never,
    )) as { model: FakeModel; thinkingLevel: string };
  }

  async function command(args: string) {
    const definition = commands.get(PROFILES_COMMAND);
    assert.ok(definition, "profile command is registered");
    await definition.handler(args, ctx as never);
  }

  return {
    pi,
    ctx,
    handlers,
    virtualModels,
    virtualObjects,
    commands,
    notifications,
    statuses,
    setModels,
    start,
    callTool,
    route,
    command,
    getThinkingLevel: () => thinkingLevel,
  };
}

function model(provider: string, id: string): FakeModel {
  return { provider, id, name: id };
}

const ATTRIBUTION = "anthropic/claude-a";
const HOME_ATTRIBUTION = "anthropic/claude-home";
const PART_SEPARATOR = " · ";

function twoProfiles(): { work: Profile; home: Profile } {
  return {
    work: { alpha: { model: ATTRIBUTION, thinking: "high", escalationModel: "anthropic/claude-big" } },
    home: { beta: { model: HOME_ATTRIBUTION } },
  };
}

// ─── Inert mode ──────────────────────────────────────────────────────────────

run("profile wiring: no profile file registers nothing", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeAgent("alpha");
    const h = makeHarness({ cwd: ws.cwd, flags: { agent: "alpha" } });
    await h.start();

    assert.equal(h.virtualModels.size, 0);
    assert.ok(!h.commands.has(PROFILES_COMMAND));
    assert.equal(h.setModels.length, 0, "agent model is untouched");
    assert.equal(process.env[PROFILE_LAYER_ENV], undefined);
    assert.ok(!h.statuses.has(PROFILE_STATUS_KEY), "no profile status is written");
  } finally {
    ws.dispose();
  }
});

run("profile wiring: an unreadable profiles path leaves the extension inert", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeAgent("alpha");
    // A file where the profiles directory belongs: readdir fails with ENOTDIR.
    writeFileSync(join(ws.agentDir, "profiles"), "");

    const h = makeHarness({ cwd: ws.cwd, flags: { agent: "alpha" } });
    await h.start();

    assert.equal(h.virtualModels.size, 0);
    assert.ok(!h.commands.has(PROFILES_COMMAND));
    assert.equal(h.setModels.length, 0, "agent model is untouched");
    assert.equal(process.env[PROFILE_LAYER_ENV], undefined);
  } finally {
    ws.dispose();
  }
});

// ─── Active mode ─────────────────────────────────────────────────────────────

run("profile wiring: registers the union of keys and binds only agents without a model", async () => {
  const ws = makeWorkspace();
  try {
    const profiles = twoProfiles();
    ws.writeProfile("work", profiles.work);
    ws.writeProfile("home", profiles.home);
    ws.writeState("work");
    ws.writeAgent("alpha");
    ws.writeAgent("pinned", { model: "anthropic/claude-pinned" });

    const physical = [model("anthropic", "claude-a"), model("anthropic", "claude-pinned")];
    const alphaRun = makeHarness({ cwd: ws.cwd, flags: { agent: "alpha" }, physical });
    await alphaRun.start();

    assert.deepEqual([...alphaRun.virtualModels.keys()].sort(), ["alpha", "alpha-escalation", "beta"]);
    assert.ok(
      alphaRun.setModels.some((m) => m.provider === PROFILE_PROVIDER && m.id === "alpha"),
      "an agent without model is applied through the normal path as profile/alpha",
    );

    const pinnedRun = makeHarness({ cwd: ws.cwd, flags: { agent: "pinned" }, physical });
    await pinnedRun.start();
    assert.ok(pinnedRun.setModels.some((m) => m.provider === "anthropic" && m.id === "claude-pinned"));
    assert.ok(!pinnedRun.setModels.some((m) => m.provider === PROFILE_PROVIDER));
  } finally {
    ws.dispose();
  }
});

run("profile wiring: a profile switch resolves on the next request without a reload", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeProfile("home", { alpha: { model: HOME_ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const h = makeHarness({
      cwd: ws.cwd,
      physical: [model("anthropic", "claude-a"), model("anthropic", "claude-home")],
    });
    await h.start();

    assert.equal((await h.route("alpha", { reason: "user" })).model.id, "claude-a");
    // Pretty JSON changes the size, so the store's version cache cannot hide the rewrite.
    ws.writeState("home", true);
    assert.equal((await h.route("alpha", { reason: "user" })).model.id, "claude-home");
  } finally {
    ws.dispose();
  }
});

run("profile wiring: continuation keeps the previous model; retry resolves fresh", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeProfile("home", { alpha: { model: HOME_ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const physicalA = model("anthropic", "claude-a");
    const h = makeHarness({
      cwd: ws.cwd,
      physical: [physicalA, model("anthropic", "claude-home")],
    });
    await h.start();
    ws.writeState("home", true);

    const continued = await h.route("alpha", {
      reason: "continuation",
      previous: { model: physicalA, thinkingLevel: "high" },
    });
    assert.equal(continued.model, physicalA);
    assert.equal(continued.thinkingLevel, "high");

    const retried = await h.route("alpha", {
      reason: "retry",
      previous: { model: physicalA, thinkingLevel: "high" },
    });
    assert.equal(retried.model.id, "claude-home");

    const continuedWithoutPrevious = await h.route("alpha", { reason: "continuation" });
    assert.equal(continuedWithoutPrevious.model.id, "claude-home");
  } finally {
    ws.dispose();
  }
});

run("profile wiring: an escalation route resolves to the entry's escalationModel", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", {
      alpha: { model: ATTRIBUTION, thinking: "high", escalationModel: "anthropic/claude-big" },
    });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const h = makeHarness({
      cwd: ws.cwd,
      physical: [model("anthropic", "claude-a"), model("anthropic", "claude-big")],
    });
    await h.start();

    const escalated = await h.route("alpha-escalation", { reason: "user" });
    assert.equal(escalated.model.id, "claude-big");
    assert.equal(escalated.thinkingLevel, "high");
  } finally {
    ws.dispose();
  }
});

run("profile wiring: route errors name the missing piece", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: "anthropic/missing" } });
    ws.writeProfile("home", { beta: { model: HOME_ATTRIBUTION } });
    ws.writeAgent("alpha");

    const h = makeHarness({ cwd: ws.cwd, physical: [] });
    await h.start();

    await assert.rejects(
      async () => h.route("alpha", { reason: "user" }),
      /no active profile; run \/profile <name>/,
    );

    ws.writeState("work");
    await assert.rejects(
      async () => h.route("beta", { reason: "user" }),
      /profile work does not define beta/,
    );
    await assert.rejects(
      async () => h.route("alpha", { reason: "user" }),
      /profile work: model anthropic\/missing \(alpha\) is not available/,
    );
  } finally {
    ws.dispose();
  }
});

// ─── Subagent model guard ────────────────────────────────────────────────────

run("profile wiring: the subagent tool only accepts registered profile models", async () => {
  const ws = makeWorkspace();
  try {
    const profiles = twoProfiles();
    ws.writeProfile("work", profiles.work);
    ws.writeProfile("home", profiles.home);
    ws.writeState("work");
    ws.writeAgent("alpha");

    const h = makeHarness({ cwd: ws.cwd, physical: [model("anthropic", "claude-a")] });
    await h.start();

    const blocked = await h.callTool(SUBAGENT_TOOL_NAME, { model: "anthropic/claude-a" });
    assert.equal(blocked?.block, true);
    assert.match(blocked?.reason ?? "", /is not allowed; omit it or use one of: .*profile\/alpha/);

    assert.equal(await h.callTool(SUBAGENT_TOOL_NAME, { model: "profile/alpha" }), undefined);
    assert.equal(await h.callTool(SUBAGENT_TOOL_NAME, { model: "profile/alpha-escalation" }), undefined);
    assert.equal(await h.callTool(SUBAGENT_TOOL_NAME, {}), undefined);
  } finally {
    ws.dispose();
  }
});

// ─── Session restore ─────────────────────────────────────────────────────────

run("profile wiring: resume selects the bound agent's virtual model", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const entries = [{ type: "custom", customType: "open-agents-state", data: { name: "alpha" } }];
    const h = makeHarness({
      cwd: ws.cwd,
      entries,
      initialModel: model("anthropic", "claude-last"),
      physical: [model("anthropic", "claude-a"), model("anthropic", "claude-last")],
    });
    await h.start("resume");

    const selected = h.setModels.at(-1);
    assert.deepEqual(
      selected === undefined ? undefined : { provider: selected.provider, id: selected.id },
      { provider: PROFILE_PROVIDER, id: "alpha" },
    );
  } finally {
    ws.dispose();
  }
});

run("profile wiring: fork and reload also re-select the bound agent's virtual model", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const entries = [{ type: "custom", customType: "open-agents-state", data: { name: "alpha" } }];
    for (const reason of ["fork", "reload"]) {
      const h = makeHarness({
        cwd: ws.cwd,
        entries,
        initialModel: model("anthropic", "claude-last"),
        physical: [model("anthropic", "claude-a"), model("anthropic", "claude-last")],
      });
      await h.start(reason);

      const selected = h.setModels.at(-1);
      assert.deepEqual(
        selected === undefined ? undefined : { provider: selected.provider, id: selected.id },
        { provider: PROFILE_PROVIDER, id: "alpha" },
        `${reason} selects the virtual model`,
      );
    }
  } finally {
    ws.dispose();
  }
});

run("profile wiring: a rejected model selection warns and does not throw", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const h = makeHarness({
      cwd: ws.cwd,
      entries: [{ type: "custom", customType: "open-agents-state", data: { name: "alpha" } }],
      initialModel: model("anthropic", "claude-last"),
      physical: [model("anthropic", "claude-a"), model("anthropic", "claude-last")],
      setModelResult: false,
    });
    await h.start("resume");

    assert.ok(
      h.notifications.some(
        (n) => n.level === "warning" && n.message === "Profile: cannot select profile/alpha",
      ),
    );
    assert.equal(h.ctx.model?.id, "claude-last", "the physical model stays selected");
  } finally {
    ws.dispose();
  }
});

// ─── Project layer ───────────────────────────────────────────────────────────

run("profile wiring: a trusted project layer overrides routes and reaches children", async () => {
  const ws = makeWorkspace();
  try {
    const profiles = twoProfiles();
    ws.writeProfile("work", profiles.work);
    ws.writeProfile("home", profiles.home);
    ws.writeState("work");
    ws.writeAgent("alpha");

    const layer = { profile: "home", agents: { alpha: { model: "anthropic/claude-project", thinking: "low" } } };
    ws.writeLayer(layer);

    const h = makeHarness({
      cwd: ws.cwd,
      trusted: true,
      physical: [
        model("anthropic", "claude-a"),
        model("anthropic", "claude-project"),
        model("anthropic", "claude-home"),
      ],
    });
    await h.start();

    const alpha = await h.route("alpha", { reason: "user" });
    assert.equal(alpha.model.id, "claude-project");
    assert.equal(alpha.thinkingLevel, "low");
    assert.equal((await h.route("beta", { reason: "user" })).model.id, "claude-home");
    assert.equal(process.env[PROFILE_LAYER_ENV], JSON.stringify(layer));
    assert.match(h.statuses.get(PROFILE_STATUS_KEY) ?? "", /\[home · project\]/);
  } finally {
    ws.dispose();
  }
});

run("profile wiring: a project override without a model for an unknown agent is ignored", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");
    const layer = { agents: { ghost: { thinking: "high" } } };
    ws.writeLayer(layer);

    const h = makeHarness({ cwd: ws.cwd, trusted: true, physical: [model("anthropic", "claude-a")] });
    await h.start();

    assert.ok(
      h.notifications.some(
        (n) =>
          n.level === "warning" &&
          n.message ===
            ".pi/profile.json: no model for ghost in profile work; these overrides are ignored",
      ),
    );
    assert.equal((await h.route("alpha", { reason: "user" })).model.id, "claude-a");
    assert.equal(process.env[PROFILE_LAYER_ENV], JSON.stringify(layer), "the layer stays active");
  } finally {
    ws.dispose();
  }
});

run("profile wiring: an untrusted project layer is ignored with a warning", async () => {
  const ws = makeWorkspace();
  try {
    const profiles = twoProfiles();
    ws.writeProfile("work", profiles.work);
    ws.writeProfile("home", profiles.home);
    ws.writeState("work");
    ws.writeAgent("alpha");
    ws.writeLayer({ agents: { alpha: { model: "anthropic/claude-project" } } });

    const h = makeHarness({
      cwd: ws.cwd,
      trusted: false,
      physical: [model("anthropic", "claude-a"), model("anthropic", "claude-project")],
    });
    await h.start();

    assert.ok(
      h.notifications.some(
        (n) => n.level === "warning" && n.message === "Ignoring .pi/profile.json: the project is not trusted",
      ),
    );
    assert.equal(process.env[PROFILE_LAYER_ENV], undefined);
    assert.equal((await h.route("alpha", { reason: "user" })).model.id, "claude-a");
  } finally {
    ws.dispose();
  }
});

run("profile wiring: a stale layer env var is deleted when no layer is active", async () => {
  const ws = makeWorkspace();
  const previous = process.env[PROFILE_LAYER_ENV];
  process.env[PROFILE_LAYER_ENV] = JSON.stringify({ agents: {} });
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const h = makeHarness({ cwd: ws.cwd, physical: [model("anthropic", "claude-a")] });
    await h.start();
    assert.equal(process.env[PROFILE_LAYER_ENV], undefined);
  } finally {
    if (previous === undefined) delete process.env[PROFILE_LAYER_ENV];
    else process.env[PROFILE_LAYER_ENV] = previous;
    ws.dispose();
  }
});

// ─── Subagent process ────────────────────────────────────────────────────────

run("profile wiring: a subagent reads its layer from env, never the project file", async () => {
  const ws = makeWorkspace();
  const previousDepth = process.env[DEPTH_ENV];
  const previousLayer = process.env[PROFILE_LAYER_ENV];
  const envLayer = { agents: { alpha: { model: "anthropic/claude-env" } } };
  process.env[DEPTH_ENV] = "1";
  process.env[PROFILE_LAYER_ENV] = JSON.stringify(envLayer);
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeProfile("home", { alpha: { model: HOME_ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");
    ws.writeLayer({ profile: "home", agents: { alpha: { model: "anthropic/claude-project" } } });

    const h = makeHarness({
      cwd: ws.cwd,
      trusted: true,
      physical: [
        model("anthropic", "claude-a"),
        model("anthropic", "claude-env"),
        model("anthropic", "claude-project"),
      ],
    });
    await h.start();

    assert.ok(!h.commands.has(PROFILES_COMMAND));
    assert.equal((await h.route("alpha", { reason: "user" })).model.id, "claude-env");
    assert.equal(process.env[PROFILE_LAYER_ENV], JSON.stringify(envLayer));
  } finally {
    if (previousDepth === undefined) delete process.env[DEPTH_ENV];
    else process.env[DEPTH_ENV] = previousDepth;
    if (previousLayer === undefined) delete process.env[PROFILE_LAYER_ENV];
    else process.env[PROFILE_LAYER_ENV] = previousLayer;
    ws.dispose();
  }
});

// ─── /profile command ────────────────────────────────────────────────────────

run("profile wiring: /profile writes the state file and summarizes the result", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION }, pinned: { model: "anthropic/claude-from-profile" } });
    ws.writeProfile("home", { alpha: { model: HOME_ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");
    ws.writeAgent("pinned", { model: "anthropic/claude-pinned" });

    const h = makeHarness({
      cwd: ws.cwd,
      physical: [model("anthropic", "claude-a"), model("anthropic", "claude-pinned")],
    });
    await h.start();
    h.notifications.length = 0;

    await h.command("home");
    assert.deepEqual(JSON.parse(readFileSync(join(ws.agentDir, "profile-state.json"), "utf-8")), {
      active: "home",
    });
    assert.ok(
      h.notifications.some(
        (n) => n.level === "info" && n.message.includes("Profile home") && n.message.includes("alpha: anthropic/claude-home"),
      ),
    );

    h.notifications.length = 0;
    await h.command("nope");
    assert.ok(
      h.notifications.some(
        (n) => n.level === "error" && n.message === "Unknown profile: nope. Available: home, work",
      ),
    );

    h.notifications.length = 0;
    assert.ok(h.virtualModels.has("pinned"));
    await h.command("work");
    const summary = h.notifications.find((n) => n.level === "info")?.message ?? "";
    assert.match(summary, /Pinned by frontmatter \(not following the profile\):/);
    assert.ok(
      summary.includes(`pinned: anthropic/claude-pinned (${join(ws.cwd, ".pi", "agents", "pinned.agent.md")})`),
    );

    const completions = h.commands.get(PROFILES_COMMAND)?.getArgumentCompletions?.("h");
    assert.deepEqual(completions, [{ value: "home", label: "home" }]);
  } finally {
    ws.dispose();
  }
});

run("profile wiring: /profile summarizes the profile the project layer selects", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeProfile("home", {
      alpha: { model: HOME_ATTRIBUTION },
      beta: { model: "anthropic/claude-b" },
    });
    ws.writeState("work");
    ws.writeAgent("alpha");
    ws.writeLayer({ profile: "home", agents: {} });

    const h = makeHarness({
      cwd: ws.cwd,
      trusted: true,
      physical: [model("anthropic", "claude-a"), model("anthropic", "claude-home")],
    });
    await h.start();
    h.notifications.length = 0;

    await h.command("work");
    const summary = h.notifications.find((n) => n.level === "info")?.message ?? "";
    assert.match(summary, /^Profile home/);
    assert.ok(summary.includes("beta: anthropic/claude-b"), "the layer's profile is listed");
    assert.ok(!summary.includes("anthropic/claude-a"), "the global selection is not listed");
    assert.ok(
      summary.includes(
        ".pi/profile.json selects home in this project; the global selection (work) applies elsewhere.",
      ),
    );
    // The global selection still moves elsewhere.
    assert.deepEqual(JSON.parse(readFileSync(join(ws.agentDir, "profile-state.json"), "utf-8")), {
      active: "work",
    });
  } finally {
    ws.dispose();
  }
});

run("profile wiring: /profile without an argument and a cancelled picker", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeProfile("home", { alpha: { model: HOME_ATTRIBUTION } });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const cancelled = makeHarness({
      cwd: ws.cwd,
      selectResult: undefined,
      physical: [model("anthropic", "claude-a")],
    });
    await cancelled.start();
    cancelled.notifications.length = 0;
    await cancelled.command("");
    assert.equal(cancelled.notifications.length, 0);
    assert.deepEqual(
      JSON.parse(readFileSync(join(ws.agentDir, "profile-state.json"), "utf-8")),
      { active: "work" },
    );

    const picked = makeHarness({
      cwd: ws.cwd,
      selectResult: "home",
      physical: [model("anthropic", "claude-a"), model("anthropic", "claude-home")],
    });
    await picked.start();
    picked.notifications.length = 0;
    await picked.command("");
    assert.deepEqual(
      JSON.parse(readFileSync(join(ws.agentDir, "profile-state.json"), "utf-8")),
      { active: "home" },
    );
  } finally {
    ws.dispose();
  }
});

run("profile wiring: /profile completions survive an unreadable profiles path", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION } });
    ws.writeAgent("alpha");

    const h = makeHarness({ cwd: ws.cwd, physical: [model("anthropic", "claude-a")] });
    await h.start();
    const definition = h.commands.get(PROFILES_COMMAND);
    assert.ok(definition, "profile command is registered");
    assert.deepEqual(definition.getArgumentCompletions?.("w"), [{ value: "work", label: "work" }]);

    // A file where the profiles directory belongs: readdir fails with ENOTDIR.
    rmSync(join(ws.agentDir, "profiles"), { recursive: true, force: true });
    writeFileSync(join(ws.agentDir, "profiles"), "");
    assert.equal(definition.getArgumentCompletions?.(""), null);
  } finally {
    ws.dispose();
  }
});

// ─── Status and thinking ─────────────────────────────────────────────────────

run("profile wiring: the footer shows the profile and the routed model", async () => {
  const ws = makeWorkspace();
  try {
    ws.writeProfile("work", { alpha: { model: ATTRIBUTION, thinking: "high" } });
    ws.writeState("work");
    ws.writeAgent("alpha");

    const h = makeHarness({
      cwd: ws.cwd,
      flags: { agent: "alpha" },
      physical: [model("anthropic", "claude-a")],
    });
    await h.start();

    assert.equal(h.statuses.get(PROFILE_STATUS_KEY), `[work${PART_SEPARATOR}anthropic/claude-a]`);
    assert.equal(h.getThinkingLevel(), "high");
  } finally {
    ws.dispose();
  }
});
