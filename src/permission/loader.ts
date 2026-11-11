/**
 * Permission policy file loader.
 *
 * Loads and strictly validates the user policy (<agentDir>/permissions.json)
 * and the project policy (<cwd>/.pi/permissions.json). Unlike frontmatter
 * parsing, anything unexpected is an error: a policy that is silently
 * half-applied is worse than one that is rejected.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { PERMISSION_ACTIONS } from "../types.ts";
import type { PermissionAction, PermissionConfig } from "../types.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

export const POLICY_FILE_NAME = "permissions.json";
export const PROJECT_POLICY_DIR = ".pi";
export const POLICY_VERSION = 1;
// Agent key (user and project files) applying to every agent and to no-agent sessions.
export const ALL_AGENTS_KEY = "*";
const NOT_FOUND = "ENOENT";
const HOME_PREFIX = "~/";

export type PolicyFileStatus = "missing" | "loaded" | "invalid";

export const POLICY_FILE_STATUS = {
  missing: "missing",
  loaded: "loaded",
  invalid: "invalid",
} as const satisfies Record<PolicyFileStatus, PolicyFileStatus>;

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AlwaysDeny {
  gitWrite: boolean;
  paths: string[];
  tools: string[];
  bash: string[];
}

export interface UserPolicy {
  alwaysDeny: AlwaysDeny;
  trustedProjects: string[];
  agents: Record<string, PermissionConfig>;
}

export interface ProjectPolicy {
  agents: Record<string, PermissionConfig>;
}

export interface PolicyFile<T> {
  path: string;
  status: PolicyFileStatus;
  policy?: T;
  error?: string;
}

export class PolicyParseError extends Error {
  override name = "PolicyParseError";
}

// ─── Paths ───────────────────────────────────────────────────────────────────

export function userPolicyPath(agentDir: string): string {
  return path.join(agentDir, POLICY_FILE_NAME);
}

export function projectPolicyPath(cwd: string): string {
  return path.join(cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME);
}

// ─── Validation helpers ──────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function expectObject(value: unknown, context: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new PolicyParseError(`${context} must be an object, got ${describe(value)}`);
  }
  return value;
}

function checkKeys(obj: Record<string, unknown>, allowed: readonly string[], context: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      const where = context ? `${context}.${key}` : key;
      throw new PolicyParseError(
        `unknown key "${where}"; allowed keys: ${allowed.join(", ")}`,
      );
    }
  }
}

function checkVersion(obj: Record<string, unknown>): void {
  if (obj.version !== POLICY_VERSION) {
    throw new PolicyParseError(
      `version must be ${POLICY_VERSION}, got ${obj.version === undefined ? "nothing" : JSON.stringify(obj.version)}`,
    );
  }
}

function parseStringList(value: unknown, context: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new PolicyParseError(`${context} must be an array of strings, got ${describe(value)}`);
  }
  return value.map((item, index) => {
    if (typeof item !== "string" || item.trim() === "") {
      throw new PolicyParseError(`${context}[${index}] must be a non-empty string`);
    }
    return item.trim();
  });
}

function isPermissionAction(value: unknown): value is PermissionAction {
  return typeof value === "string" && (PERMISSION_ACTIONS as readonly string[]).includes(value);
}

function expectAction(value: unknown, context: string): PermissionAction {
  if (!isPermissionAction(value)) {
    throw new PolicyParseError(
      `${context} must be one of ${PERMISSION_ACTIONS.join(", ")}, got ${JSON.stringify(value)}`,
    );
  }
  return value;
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

const USER_KEYS = ["version", "alwaysDeny", "trustedProjects", "agents"] as const;
const ALWAYS_DENY_KEYS = ["gitWrite", "paths", "tools", "bash"] as const;
const PROJECT_KEYS = ["version", "agents"] as const;

function parseAlwaysDeny(raw: unknown): AlwaysDeny {
  if (raw === undefined) return { gitWrite: true, paths: [], tools: [], bash: [] };
  const obj = expectObject(raw, "alwaysDeny");
  checkKeys(obj, ALWAYS_DENY_KEYS, "alwaysDeny");
  if (obj.gitWrite !== undefined && typeof obj.gitWrite !== "boolean") {
    throw new PolicyParseError(`alwaysDeny.gitWrite must be a boolean, got ${describe(obj.gitWrite)}`);
  }
  return {
    gitWrite: obj.gitWrite ?? true,
    paths: parseStringList(obj.paths, "alwaysDeny.paths"),
    tools: parseStringList(obj.tools, "alwaysDeny.tools"),
    bash: parseStringList(obj.bash, "alwaysDeny.bash"),
  };
}

export function parseUserPolicy(raw: unknown): UserPolicy {
  const obj = expectObject(raw, "policy");
  checkKeys(obj, USER_KEYS, "");
  checkVersion(obj);

  const trustedProjects = parseStringList(obj.trustedProjects, "trustedProjects");
  trustedProjects.forEach((entry, index) => {
    if (!path.isAbsolute(entry) && !entry.startsWith(HOME_PREFIX)) {
      throw new PolicyParseError(
        `trustedProjects[${index}] must be an absolute path or start with "${HOME_PREFIX}", got ${JSON.stringify(entry)}`,
      );
    }
  });

  return { alwaysDeny: parseAlwaysDeny(obj.alwaysDeny), trustedProjects, agents: parseAgents(obj.agents) };
}

export function parsePolicyPermissionConfig(raw: unknown, context: string): PermissionConfig {
  const obj = expectObject(raw, context);
  const config: PermissionConfig = {};

  for (const [permission, value] of Object.entries(obj)) {
    const valueContext = `${context}.${permission}`;
    if (isRecord(value)) {
      const patterns: Record<string, PermissionAction> = {};
      for (const [pattern, action] of Object.entries(value)) {
        patterns[pattern] = expectAction(action, `${valueContext}[${JSON.stringify(pattern)}]`);
      }
      config[permission] = patterns;
    } else {
      config[permission] = expectAction(value, valueContext);
    }
  }

  return config;
}

function parseAgents(raw: unknown): Record<string, PermissionConfig> {
  const agents: Record<string, PermissionConfig> = {};
  if (raw === undefined) return agents;
  for (const [name, config] of Object.entries(expectObject(raw, "agents"))) {
    agents[name] = parsePolicyPermissionConfig(config, `agents.${name}`);
  }
  return agents;
}

export function parseProjectPolicy(raw: unknown): ProjectPolicy {
  const obj = expectObject(raw, "policy");
  checkKeys(obj, PROJECT_KEYS, "");
  checkVersion(obj);

  return { agents: parseAgents(obj.agents) };
}

// ─── Loading ─────────────────────────────────────────────────────────────────

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function loadPolicyFile<T>(filePath: string, parse: (raw: unknown) => T): PolicyFile<T> {
  let text: string;
  try {
    text = readFileSync(filePath, "utf-8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === NOT_FOUND) {
      return { path: filePath, status: POLICY_FILE_STATUS.missing };
    }
    return { path: filePath, status: POLICY_FILE_STATUS.invalid, error: errorMessage(error) };
  }

  try {
    const policy = parse(JSON.parse(text));
    return { path: filePath, status: POLICY_FILE_STATUS.loaded, policy };
  } catch (error) {
    const message = error instanceof SyntaxError ? `invalid JSON: ${error.message}` : errorMessage(error);
    return { path: filePath, status: POLICY_FILE_STATUS.invalid, error: message };
  }
}

export function loadUserPolicy(agentDir: string): PolicyFile<UserPolicy> {
  return loadPolicyFile(userPolicyPath(agentDir), parseUserPolicy);
}

export function loadProjectPolicy(cwd: string): PolicyFile<ProjectPolicy> {
  return loadPolicyFile(projectPolicyPath(cwd), parseProjectPolicy);
}
