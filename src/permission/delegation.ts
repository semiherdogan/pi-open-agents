/**
 * Delegation modes for strict mode.
 *
 * The delegating agent's frontmatter may set `delegation: { <child>: role }`.
 * `restrict` (default) keeps the child under the parent's policy: the parent's
 * own policy becomes one more ceiling. `role` lets a trusted child run with its
 * own role policy; ceilings imposed further up the chain still apply. Nothing
 * the model passes in a subagent call can select the mode.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { parseFrontmatter } from "../config/frontmatter.ts";
import type { AgentDefinition } from "../types.ts";
import { encodePolicySnapshot, POLICY_SNAPSHOT_ENV, POLICY_SNAPSHOT_VERSION, serializePolicy } from "./policy-snapshot.ts";
import type { PolicyRuntime } from "./policy-runtime.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

export type DelegationMode = "restrict" | "role";

export const DELEGATION_MODE = {
  restrict: "restrict",
  role: "role",
} as const satisfies Record<DelegationMode, DelegationMode>;

const DELEGATION_KEY = "delegation";
const GLOBAL_SOURCE: AgentDefinition["source"] = "global";
const DELEGATION_MODES: readonly string[] = Object.values(DELEGATION_MODE);

// ─── Types ───────────────────────────────────────────────────────────────────

export type InheritedRule = { permission: string; pattern: string; action: "deny" | "ask" };

/** The upstream #8 values: tool ceiling and restrictive rules handed to the child. */
export interface LegacyDelegation {
  parentCeiling: string[] | undefined;
  parentRules: InheritedRule[] | undefined;
}

export interface DelegationInput {
  /** The delegating agent (in a child process: the child's own definition). */
  activeAgent: AgentDefinition | undefined;
  agent: AgentDefinition;
  cwd: string;
  childCwd: string;
  legacy: LegacyDelegation;
}

export interface DelegationPlan extends LegacyDelegation {
  mode: DelegationMode;
  extraEnv?: Record<string, string>;
  /** Why role was refused, invalid config, and similar diagnostics. */
  notes: string[];
}

export interface DelegationConfig {
  modes: Record<string, DelegationMode>;
  warnings: string[];
}

// ─── Frontmatter ─────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The upstream schema drops unknown keys, so `delegation` is read from the definition file itself. */
export function parseDelegationConfig(content: string, filePath: string): DelegationConfig {
  const raw = parseFrontmatter(content).data[DELEGATION_KEY];
  const modes: Record<string, DelegationMode> = {};
  const warnings: string[] = [];
  if (raw === undefined) return { modes, warnings };
  if (!isRecord(raw)) {
    warnings.push(`${filePath}: ${DELEGATION_KEY} must map agent names to ${DELEGATION_MODES.join(" or ")}; using ${DELEGATION_MODE.restrict}`);
    return { modes, warnings };
  }
  for (const [name, value] of Object.entries(raw)) {
    if (typeof value === "string" && DELEGATION_MODES.includes(value)) {
      modes[name] = value as DelegationMode;
      continue;
    }
    warnings.push(
      `${filePath}: ${DELEGATION_KEY}.${name} must be ${DELEGATION_MODES.join(" or ")}, got ${JSON.stringify(value)}; using ${DELEGATION_MODE.restrict}`,
    );
    modes[name] = DELEGATION_MODE.restrict;
  }
  return { modes, warnings };
}

export function readDelegationConfig(
  agent: AgentDefinition,
  readFile: (filePath: string) => string = (filePath) => readFileSync(filePath, "utf-8"),
): DelegationConfig {
  try {
    return parseDelegationConfig(readFile(agent.filePath), agent.filePath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { modes: {}, warnings: [`${agent.filePath}: cannot read ${DELEGATION_KEY} (${message}); using ${DELEGATION_MODE.restrict}`] };
  }
}

// ─── Planning ────────────────────────────────────────────────────────────────

function isTrusted(agent: AgentDefinition, projectTrusted: boolean): boolean {
  return agent.source === GLOBAL_SOURCE || projectTrusted;
}

export interface DelegationModeInput {
  activeAgent: AgentDefinition | undefined;
  agent: AgentDefinition;
  /** The delegating agent's frontmatter entry for `agent`, if any. */
  configured: DelegationMode | undefined;
  projectTrusted: boolean;
  childProjectTrusted: boolean;
}

export interface DelegationModeDecision {
  mode: DelegationMode;
  /** Why a configured role was refused. */
  refusal?: string;
}

function roleRefusal(input: DelegationModeInput): string | undefined {
  const { activeAgent, agent, projectTrusted, childProjectTrusted } = input;
  if (!activeAgent) return `no delegating agent definition`;
  if (!activeAgent.allowedAgents?.includes(agent.name)) {
    return `"${agent.name}" is not listed in allowedAgents of "${activeAgent.name}"`;
  }
  if (!isTrusted(activeAgent, projectTrusted)) return `"${activeAgent.name}" is a project agent in an untrusted project`;
  if (!isTrusted(agent, projectTrusted && childProjectTrusted)) return `"${agent.name}" is a project agent in an untrusted project`;
  return undefined;
}

/** The mode a child runs in; shared by the planner and the prompt summary so both agree. */
export function decideDelegationMode(input: DelegationModeInput): DelegationModeDecision {
  const mode = input.configured ?? DELEGATION_MODE.restrict;
  if (mode !== DELEGATION_MODE.role) return { mode };
  const refusal = roleRefusal(input);
  return refusal === undefined ? { mode } : { mode: DELEGATION_MODE.restrict, refusal };
}

/** Modes of `agents` delegated by `activeAgent` in `cwd` with the child's default cwd, as the planner decides them. */
export function delegationModesFor(
  runtime: PolicyRuntime,
  activeAgent: AgentDefinition | undefined,
  agents: AgentDefinition[],
  cwd: string,
  readFile?: (filePath: string) => string,
): Map<string, DelegationMode> {
  const modes = new Map<string, DelegationMode>();
  if (agents.length === 0) return modes;
  const state = runtime.delegationState(activeAgent, cwd);
  if (!state) throw new Error(`cannot resolve the permission policy of the delegating agent`);
  const childDir = path.resolve(process.cwd(), cwd);
  const child = runtime.childProject(state.files, cwd, childDir);
  const config = activeAgent ? readDelegationConfig(activeAgent, readFile) : undefined;
  for (const agent of agents) {
    const childSelf = runtime.resolveFrom(child.files, agent, childDir, child.root);
    if (!childSelf) throw new Error(`cannot resolve the permission policy for "${agent.name}"`);
    const { mode } = decideDelegationMode({
      activeAgent,
      agent,
      configured: config?.modes[agent.name],
      projectTrusted: state.self?.trusted ?? false,
      childProjectTrusted: childSelf.trusted,
    });
    modes.set(agent.name, mode);
  }
  return modes;
}

export interface DelegationPlannerOptions {
  runtime: PolicyRuntime;
  readFile?: (filePath: string) => string;
}

/** Without an active policy the plan is exactly the legacy (#8) values. */
export function createDelegationPlanner(options: DelegationPlannerOptions): (input: DelegationInput) => DelegationPlan {
  const { runtime } = options;
  return (input) => {
    const { activeAgent, agent, cwd, childCwd, legacy } = input;
    if (!runtime.isActive(cwd)) return { mode: DELEGATION_MODE.restrict, ...legacy, notes: [] };

    const state = runtime.delegationState(activeAgent, cwd);
    // The executor spawns with the raw cwd, which the OS resolves against process.cwd(), not ctx.cwd.
    const childDir = path.resolve(process.cwd(), childCwd);
    // The child is judged by its project's file and trust: the parent's at or below cwd, else the nearest one above childDir.
    const child = state && runtime.childProject(state.files, cwd, childDir);
    const childFiles = child?.files;
    const childSelf = child && runtime.resolveFrom(child.files, agent, childDir, child.root);
    // Unreachable while a policy is active; refuse rather than spawn an unconstrained child.
    if (!state || !childFiles || !childSelf) throw new Error(`cannot resolve the permission policy for "${agent.name}"`);

    const config = activeAgent ? readDelegationConfig(activeAgent, options.readFile) : { modes: {}, warnings: [] };
    const notes = [...config.warnings];
    // Project definitions come from the session cwd; a project child must also run in a trusted cwd.
    const { mode, refusal } = decideDelegationMode({
      activeAgent,
      agent,
      configured: config.modes[agent.name],
      projectTrusted: state.self?.trusted ?? false,
      childProjectTrusted: childSelf.trusted,
    });
    if (refusal !== undefined) notes.push(`role delegation refused, using ${DELEGATION_MODE.restrict}: ${refusal}`);

    const role = mode === DELEGATION_MODE.role;
    // An exempt (agentless) parent has no policy, so it adds no ceiling.
    const ceilings = role || !state.self ? state.ceilings : [...state.ceilings, serializePolicy(state.self)];
    const snapshot = encodePolicySnapshot({
      version: POLICY_SNAPSHOT_VERSION,
      agent: agent.name,
      self: serializePolicy(childSelf),
      ceilings,
      inherited: state.inherited,
      files: childFiles,
    });
    return {
      mode,
      parentCeiling: role ? undefined : legacy.parentCeiling,
      // Ceilings in the snapshot replace the legacy inherited rules.
      parentRules: undefined,
      extraEnv: { [POLICY_SNAPSHOT_ENV]: snapshot },
      notes,
    };
  };
}
