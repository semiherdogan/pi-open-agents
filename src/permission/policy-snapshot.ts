/**
 * Policy snapshot handed from a strict-mode parent to its child process.
 *
 * The child decides every call against `self` and each ceiling and never re-reads
 * its own policy files; `files` are the files `self` was resolved from, used to
 * resolve the child's own delegates. Only a delegate in a different project gets
 * that project's file read at delegation time; the user file always comes from
 * `files`. `inherited` carries deny/ask
 * rules from a legacy ancestor down every hop. Anything malformed fails closed.
 */

import type { PermissionAction, PermissionRule } from "../types.ts";
import { isSubagentProcess } from "../subagent/env.ts";
import {
  parseProjectPolicy,
  parseUserPolicy,
  POLICY_FILE_STATUS,
  POLICY_VERSION,
  type PolicyFile,
  type ProjectPolicy,
  type UserPolicy,
} from "./loader.ts";
import type { EffectivePolicy } from "./resolver.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

export const POLICY_SNAPSHOT_ENV = "PI_OPEN_AGENTS_POLICY";
export const POLICY_SNAPSHOT_VERSION = 1;
const AGENT_NAME_ENV = "PI_OPEN_AGENTS_NAME";
const PERMISSION_ACTIONS: readonly PermissionAction[] = ["allow", "ask", "deny"];
const INHERITED_ACTIONS: readonly PermissionAction[] = ["ask", "deny"];
const FILE_STATUSES: readonly string[] = Object.values(POLICY_FILE_STATUS);

export const SNAPSHOT_STATUS = {
  valid: "valid",
  invalid: "invalid",
} as const;

// ─── Types ───────────────────────────────────────────────────────────────────

export type SerializedPolicy = Omit<EffectivePolicy, "sources" | "warnings">;

export interface PolicySnapshotFiles {
  user: PolicyFile<UserPolicy>;
  project: PolicyFile<ProjectPolicy>;
}

export interface PolicySnapshot {
  version: typeof POLICY_SNAPSHOT_VERSION;
  agent: string;
  self: SerializedPolicy;
  ceilings: SerializedPolicy[];
  /** Deny/ask rules from a legacy ancestor (PI_OPEN_AGENTS_PARENT_RULES); appended after `self` rules. */
  inherited: PermissionRule[];
  files: PolicySnapshotFiles;
}

export type ReceivedSnapshot =
  | { status: typeof SNAPSHOT_STATUS.valid; snapshot: PolicySnapshot }
  | { status: typeof SNAPSHOT_STATUS.invalid; reason: string };

type Env = Record<string, string | undefined>;

// ─── Conversion ──────────────────────────────────────────────────────────────

export function serializePolicy(policy: EffectivePolicy): SerializedPolicy {
  const { agentName, trusted, rules, hardRules, denyGitWrite, bashDeny, agentDirs } = policy;
  return { agentName, trusted, rules, hardRules, denyGitWrite, bashDeny, agentDirs };
}

export function hydratePolicy(policy: SerializedPolicy, files: PolicySnapshotFiles): EffectivePolicy {
  return { ...policy, sources: files, warnings: [] };
}

export function encodePolicySnapshot(snapshot: PolicySnapshot): string {
  return JSON.stringify(snapshot);
}

// ─── Validation ──────────────────────────────────────────────────────────────

class SnapshotError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function expect(condition: boolean, message: string): void {
  if (!condition) throw new SnapshotError(message);
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isRule(value: unknown): value is PermissionRule {
  return (
    isRecord(value) &&
    typeof value.permission === "string" &&
    typeof value.pattern === "string" &&
    PERMISSION_ACTIONS.includes(value.action as PermissionAction)
  );
}

function checkPolicy(value: unknown, context: string): SerializedPolicy {
  expect(isRecord(value), `${context} must be an object`);
  const policy = value as Record<string, unknown>;
  expect(policy.agentName === undefined || typeof policy.agentName === "string", `${context}.agentName must be a string`);
  expect(typeof policy.trusted === "boolean", `${context}.trusted must be a boolean`);
  expect(typeof policy.denyGitWrite === "boolean", `${context}.denyGitWrite must be a boolean`);
  expect(Array.isArray(policy.rules) && policy.rules.every(isRule), `${context}.rules must be permission rules`);
  expect(Array.isArray(policy.hardRules) && policy.hardRules.every(isRule), `${context}.hardRules must be permission rules`);
  expect(isStringList(policy.bashDeny), `${context}.bashDeny must be strings`);
  expect(isStringList(policy.agentDirs), `${context}.agentDirs must be strings`);
  return serializePolicy(policy as unknown as EffectivePolicy);
}

// Loaded file content is re-validated with the same parsers the file loader uses.
function checkFile<T>(value: unknown, context: string, parse: (raw: unknown) => T): PolicyFile<T> {
  expect(isRecord(value), `${context} must be an object`);
  const file = value as Record<string, unknown>;
  expect(typeof file.path === "string", `${context}.path must be a string`);
  expect(FILE_STATUSES.includes(file.status as string), `${context}.status is invalid`);
  const checked: PolicyFile<T> = { path: file.path as string, status: file.status as PolicyFile<T>["status"] };
  if (typeof file.error === "string") checked.error = file.error;
  if (file.status === POLICY_FILE_STATUS.loaded) {
    expect(isRecord(file.policy), `${context}.policy must be an object`);
    try {
      checked.policy = parse({ ...(file.policy as Record<string, unknown>), version: POLICY_VERSION });
    } catch (error) {
      throw new SnapshotError(`${context}.policy: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return checked;
}

function checkSnapshot(raw: unknown, expectedAgent: string | undefined): PolicySnapshot {
  expect(isRecord(raw), "snapshot must be an object");
  const value = raw as Record<string, unknown>;
  expect(
    value.version === POLICY_SNAPSHOT_VERSION,
    `version must be ${POLICY_SNAPSHOT_VERSION}, got ${JSON.stringify(value.version)}`,
  );
  expect(
    typeof value.agent === "string" && value.agent === expectedAgent,
    `snapshot is for agent ${JSON.stringify(value.agent)}, this process runs ${JSON.stringify(expectedAgent)}`,
  );
  expect(Array.isArray(value.ceilings), "ceilings must be an array");
  expect(
    Array.isArray(value.inherited) &&
      value.inherited.every((rule) => isRule(rule) && INHERITED_ACTIONS.includes(rule.action)),
    "inherited must be deny/ask permission rules",
  );
  expect(isRecord(value.files), "files must be an object");
  const files = value.files as Record<string, unknown>;
  return {
    version: POLICY_SNAPSHOT_VERSION,
    agent: value.agent as string,
    self: checkPolicy(value.self, "self"),
    ceilings: (value.ceilings as unknown[]).map((ceiling, index) => checkPolicy(ceiling, `ceilings[${index}]`)),
    inherited: (value.inherited as PermissionRule[]).map(({ permission, pattern, action }) => ({ permission, pattern, action })),
    files: {
      user: checkFile(files.user, "files.user", parseUserPolicy),
      project: checkFile(files.project, "files.project", parseProjectPolicy),
    },
  };
}

/** The snapshot this child process received; undefined in a primary or without one (older parent). */
export function readPolicySnapshot(env: Env): ReceivedSnapshot | undefined {
  if (!isSubagentProcess(env)) return undefined;
  const raw = env[POLICY_SNAPSHOT_ENV];
  if (raw === undefined) return undefined;
  try {
    return { status: SNAPSHOT_STATUS.valid, snapshot: checkSnapshot(JSON.parse(raw), env[AGENT_NAME_ENV]) };
  } catch (error) {
    const message = error instanceof SnapshotError ? error.message : `invalid JSON: ${(error as Error).message}`;
    return { status: SNAPSHOT_STATUS.invalid, reason: `invalid ${POLICY_SNAPSHOT_ENV} (${message}); every tool call is blocked` };
  }
}
