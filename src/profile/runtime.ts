/**
 * Agent profile runtime: virtual models that resolve to a physical model at
 * request time, so a profile switch applies to every running pi process on
 * its next request without a reload.
 *
 * Inert until at least one profile file exists: no virtual model, handler or
 * command is registered, so a legacy external `profile/*` extension keeps
 * working.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import type {
  ExtensionAPI,
  ExtensionCommandContext,
  ExtensionContext,
  ModelRoute,
  ModelRouteReason,
  ModelRouteRequest,
} from "@earendil-works/pi-coding-agent";

import { PROJECT_POLICY_DIR } from "../permission/loader.ts";
import type { AgentDefinition } from "../types.ts";
import { THINKING_LEVELS } from "../types.ts";
import { applyLayer, incompleteOverrides, lookupRoute, routeKeys, subagentModelViolation, virtualModelRef } from "./resolve.ts";
import type { Profile, ProjectLayer } from "./schema.ts";
import {
  PROFILE_PROVIDER,
  PROJECT_PROFILE_FILE,
  parseProjectLayer,
  splitModelRef,
} from "./schema.ts";
import { ProfileStore } from "./store.ts";
import { buildProfileSummary, type PinnedAgent } from "./summary.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

export const PROFILE_LAYER_ENV = "PI_OPEN_AGENTS_PROFILE_LAYER";
export const PROFILES_COMMAND = "profile";
export const PROFILE_STATUS_KEY = "open-agents-profile";
export const SUBAGENT_TOOL_NAME = "subagent";

const NOT_FOUND = "ENOENT";
const NO_ACTIVE_PROFILE = "no active profile; run /profile <name>";
const PROJECT_MARKER = "project";
const PROJECT_PROFILE_LABEL = `${PROJECT_POLICY_DIR}/${PROJECT_PROFILE_FILE}`;
const PART_SEPARATOR = " · ";
const STATUS_OPEN = "[";
const STATUS_CLOSE = "]";
const WHITESPACE = /\s/;

const LEVEL = {
  info: "info",
  warning: "warning",
  error: "error",
} as const satisfies Record<"info" | "warning" | "error", "info" | "warning" | "error">;

const THEME_COLOR = {
  dim: "dim",
  accent: "accent",
} as const;

const ROUTE_REASON = {
  user: "user",
  continuation: "continuation",
  retry: "retry",
  direct: "direct",
} as const satisfies Record<ModelRouteReason, ModelRouteReason>;

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ProfileRuntimeOptions {
  agentDir: string;
  env: NodeJS.ProcessEnv;
  isSubagent: boolean;
  getActiveAgent: () => AgentDefinition | undefined;
  getAgents: () => AgentDefinition[];
}

export interface ProfileRuntime {
  startSession(ctx: ExtensionContext, agents: AgentDefinition[]): void;
}

interface ActiveProfile {
  name: string;
  profile: Profile;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function errorCode(error: unknown): string | undefined {
  return error instanceof Error ? (error as NodeJS.ErrnoException).code : undefined;
}

function isVirtualFor(model: { provider: string; id: string } | undefined, key: string): boolean {
  return model?.provider === PROFILE_PROVIDER && model.id === key;
}

function parseLayerFromEnv(env: NodeJS.ProcessEnv): ProjectLayer | undefined {
  const raw = env[PROFILE_LAYER_ENV];
  if (raw === undefined || raw.trim() === "") return undefined;
  try {
    return parseProjectLayer(raw);
  } catch {
    return undefined;
  }
}

function listProfiles(store: ProfileStore): string[] {
  try {
    return store.list();
  } catch {
    // An unreadable profiles path (ENOTDIR, EACCES) must never break the session.
    return [];
  }
}

// ─── Registration ────────────────────────────────────────────────────────────

export function registerProfiles(pi: ExtensionAPI, options: ProfileRuntimeOptions): ProfileRuntime {
  const store = new ProfileStore({ agentDir: options.agentDir });
  if (listProfiles(store).length === 0) {
    return { startSession: () => {} };
  }

  const registered = new Set<string>();
  const bound = new Set<string>();
  // A subagent keeps the layer it was spawned with; it never reads a project file.
  let layer: ProjectLayer | undefined = options.isSubagent ? parseLayerFromEnv(options.env) : undefined;

  function resolveActive(): ActiveProfile {
    const name = layer?.profile ?? store.activeName();
    if (name === undefined) throw new Error(NO_ACTIVE_PROFILE);
    return { name, profile: applyLayer(store.read(name), layer) };
  }

  function scanProfiles(): void {
    for (const name of listProfiles(store)) {
      try {
        ensureRegistered(routeKeys(applyLayer(store.read(name), layer)));
      } catch {
        // An invalid profile is reported when a request uses it, not at load.
      }
    }
  }

  function ensureRegistered(keys: Iterable<string>): void {
    for (const key of keys) {
      if (registered.has(key)) continue;
      registered.add(key);
      pi.registerVirtualModel({
        provider: PROFILE_PROVIDER,
        id: key,
        name: `Profile ${key}`,
        thinkingLevels: THINKING_LEVELS,
        route: (request, ctx) => route(key, request, ctx),
      });
    }
  }

  function route(
    key: string,
    request: ModelRouteRequest,
    ctx: ExtensionContext,
  ): ModelRoute {
    // A run in flight finishes on its model: that keeps the prompt cache and
    // thinking signatures valid, and a switch applies from the next user message.
    if (request.reason === ROUTE_REASON.continuation && request.previous !== undefined) {
      return {
        model: request.previous.model,
        thinkingLevel: request.previous.thinkingLevel ?? request.thinkingLevel,
      };
    }

    const active = resolveActive();
    const entry = lookupRoute(active.profile, key);
    if (entry === undefined) throw new Error(`profile ${active.name} does not define ${key}`);
    const ref = splitModelRef(entry.model);
    const model = ref === undefined ? undefined : ctx.modelRegistry.find(ref.provider, ref.id);
    if (model === undefined) {
      throw new Error(`profile ${active.name}: model ${entry.model} (${key}) is not available`);
    }
    return { model, thinkingLevel: entry.thinking ?? request.thinkingLevel };
  }

  function loadProjectLayer(ctx: ExtensionContext): ProjectLayer | undefined {
    const filePath = path.join(ctx.cwd, PROJECT_POLICY_DIR, PROJECT_PROFILE_FILE);
    let text: string;
    try {
      text = readFileSync(filePath, "utf-8");
    } catch (error) {
      if (errorCode(error) !== NOT_FOUND) {
        ctx.ui.notify(`Ignoring ${PROJECT_PROFILE_LABEL}: ${errorMessage(error)}`, LEVEL.warning);
      }
      return undefined;
    }
    if (!ctx.isProjectTrusted()) {
      ctx.ui.notify(`Ignoring ${PROJECT_PROFILE_LABEL}: the project is not trusted`, LEVEL.warning);
      return undefined;
    }
    try {
      const parsed = parseProjectLayer(text);
      // A layer naming a profile that cannot be read is invalid, not active.
      if (parsed.profile !== undefined) store.read(parsed.profile);
      warnIncompleteOverrides(ctx, parsed);
      return parsed;
    } catch (error) {
      ctx.ui.notify(`Ignoring ${PROJECT_PROFILE_LABEL}: ${errorMessage(error)}`, LEVEL.warning);
      return undefined;
    }
  }

  function warnIncompleteOverrides(ctx: ExtensionContext, candidate: ProjectLayer): void {
    const baseName = candidate.profile ?? store.activeName();
    if (baseName === undefined) return;
    let base: Profile;
    try {
      base = store.read(baseName);
    } catch {
      return;
    }
    const skipped = incompleteOverrides(base, candidate);
    if (skipped.length === 0) return;
    ctx.ui.notify(
      `${PROJECT_PROFILE_LABEL}: no model for ${skipped.join(", ")} in profile ${baseName}; these overrides are ignored`,
      LEVEL.warning,
    );
  }

  function publishLayer(): void {
    if (layer === undefined) {
      delete options.env[PROFILE_LAYER_ENV];
      return;
    }
    options.env[PROFILE_LAYER_ENV] = JSON.stringify(layer);
  }

  function bindAgents(agents: AgentDefinition[]): void {
    bound.clear();
    for (const agent of agents) {
      if (agent.model !== undefined || !registered.has(agent.name)) continue;
      agent.model = virtualModelRef(agent.name);
      bound.add(agent.name);
    }
  }

  function syncThinking(ctx: ExtensionContext, profile: Profile): void {
    const agent = options.getActiveAgent();
    if (agent === undefined || !bound.has(agent.name) || !isVirtualFor(ctx.model, agent.name)) return;
    const entry = lookupRoute(profile, agent.name);
    if (entry?.thinking === undefined || entry.thinking === pi.getThinkingLevel()) return;
    pi.setThinkingLevel(entry.thinking);
  }

  function statusText(ctx: ExtensionContext, active: ActiveProfile): string {
    const parts = [active.name];
    if (layer !== undefined) parts.push(PROJECT_MARKER);
    const agent = options.getActiveAgent();
    if (agent !== undefined && bound.has(agent.name) && isVirtualFor(ctx.model, agent.name)) {
      const entry = lookupRoute(active.profile, agent.name);
      if (entry !== undefined) parts.push(entry.model);
    }
    const style = (color: (typeof THEME_COLOR)[keyof typeof THEME_COLOR], text: string) =>
      ctx.ui.theme.fg(color, text);
    return [
      style(THEME_COLOR.dim, STATUS_OPEN),
      style(THEME_COLOR.accent, parts.join(PART_SEPARATOR)),
      style(THEME_COLOR.dim, STATUS_CLOSE),
    ].join("");
  }

  function refresh(ctx: ExtensionContext): void {
    if (!ctx.hasUI) return;
    let active: ActiveProfile;
    try {
      active = resolveActive();
    } catch {
      ctx.ui.setStatus(PROFILE_STATUS_KEY, undefined);
      return;
    }
    syncThinking(ctx, active.profile);
    ctx.ui.setStatus(PROFILE_STATUS_KEY, statusText(ctx, active));
  }

  function notifyResolutionFailure(ctx: ExtensionContext): void {
    if (bound.size === 0) return;
    try {
      resolveActive();
    } catch (error) {
      ctx.ui.notify(errorMessage(error), LEVEL.warning);
    }
  }

  async function restoreModel(ctx: ExtensionContext): Promise<void> {
    const agent = options.getActiveAgent();
    if (agent === undefined || !bound.has(agent.name) || isVirtualFor(ctx.model, agent.name)) return;
    const model = ctx.modelRegistry.find(PROFILE_PROVIDER, agent.name);
    if (model === undefined || !(await pi.setModel(model))) {
      ctx.ui.notify(`Profile: cannot select ${virtualModelRef(agent.name)}`, LEVEL.warning);
    }
  }

  function pinnedAgents(profile: Profile): PinnedAgent[] {
    const pinned: PinnedAgent[] = [];
    for (const agent of options.getAgents()) {
      if (agent.model === undefined || bound.has(agent.name) || !Object.hasOwn(profile, agent.name)) continue;
      pinned.push({ name: agent.name, model: agent.model, filePath: agent.filePath });
    }
    return pinned;
  }

  async function switchProfile(args: string, ctx: ExtensionCommandContext): Promise<void> {
    const names = store.list();
    const activeName = store.activeName();
    const requested = args.trim();
    const chosen =
      requested === "" ? await ctx.ui.select(`Profile (active: ${activeName ?? "none"})`, names) : requested;
    if (chosen === undefined) return;

    if (!names.includes(chosen)) {
      ctx.ui.notify(`Unknown profile: ${chosen}. Available: ${names.join(", ")}`, LEVEL.error);
      return;
    }
    if (chosen !== activeName) {
      try {
        store.setActive(chosen);
      } catch (error) {
        ctx.ui.notify(errorMessage(error), LEVEL.error);
        return;
      }
    }

    let profile: Profile;
    // The summary shows the resolution in effect here, so a layer that selects
    // its own profile wins over the profile this command just selected.
    const effectiveName = layer?.profile ?? chosen;
    try {
      profile = applyLayer(store.read(effectiveName), layer);
    } catch (error) {
      ctx.ui.notify(errorMessage(error), LEVEL.error);
      return;
    }
    const summary = buildProfileSummary({
      name: effectiveName,
      projectOverride: layer !== undefined,
      profile,
      pinned: pinnedAgents(profile),
      layerProfile: layer?.profile,
      globalProfile: store.activeName(),
    });
    ctx.ui.notify(summary, LEVEL.info);
    refresh(ctx);
  }

  // ─── Handlers ──────────────────────────────────────────────────────────────

  pi.on("tool_call", (event) => {
    if (event.toolName !== SUBAGENT_TOOL_NAME) return undefined;
    const input = (event as { input?: Record<string, unknown> }).input ?? {};
    const reason = subagentModelViolation(input.model, [...registered]);
    if (reason === undefined) return undefined;
    return { block: true, reason };
  });

  if (!options.isSubagent) {
    pi.on("session_start", async (_event, ctx) => {
      await restoreModel(ctx);
      notifyResolutionFailure(ctx);
      refresh(ctx);
    });

    pi.on("before_agent_start", (_event, ctx) => {
      refresh(ctx);
      return undefined;
    });

    pi.registerCommand(PROFILES_COMMAND, {
      description: "Switch the active agent profile",
      getArgumentCompletions: (prefix) => {
        if (WHITESPACE.test(prefix)) return null;
        const items = listProfiles(store)
          .filter((name) => name.startsWith(prefix))
          .map((name) => ({ value: name, label: name }));
        return items.length > 0 ? items : null;
      },
      handler: async (args, ctx) => {
        try {
          await switchProfile(args ?? "", ctx);
        } catch (error) {
          ctx.ui.notify(`Profile command failed: ${errorMessage(error)}`, LEVEL.error);
        }
      },
    });
  }

  scanProfiles();

  return {
    startSession(ctx: ExtensionContext, agents: AgentDefinition[]): void {
      if (!options.isSubagent) {
        layer = loadProjectLayer(ctx);
        publishLayer();
      }
      scanProfiles();
      bindAgents(agents);
    },
  };
}
