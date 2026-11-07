/**
 * Strict-mode permission gate, active only when a policy file exists.
 *
 * Unlike the legacy gate (opt-in per category, unmatched = allow), every call
 * is decided: hard denies first, then rules, then a per-category default.
 * Each path key is decided on its own: the matched rule with the highest index
 * across that key's spellings wins (last-match-wins, inherited rules appended
 * last stay on top), then the keys combine most restrictive first, so a decoy
 * key can never loosen the decision for the key the tool actually uses.
 * Shell calls are judged per command by bash-validator.ts (argv token-prefix
 * rules, git and protected-path hard denies) instead of a whole-string glob.
 * Registered after the legacy gate, which stands down while a policy is active.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import type { AgentDefinition, PermissionAction, PermissionRule } from "../types.ts";
import { validateShellCommand } from "./bash-validator.ts";
import { matchPermissionKey, toolToPermission } from "./evaluator.ts";
import { extractToolArg } from "./gate.ts";
import { POLICY_FILE_STATUS } from "./loader.ts";
import { matchPattern } from "./matcher.ts";
import { pathCandidates } from "./paths.ts";
import type { PolicyRuntime } from "./policy-runtime.ts";
import type { EffectivePolicy } from "./resolver.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

const ACTION = {
  allow: "allow",
  ask: "ask",
  deny: "deny",
} as const satisfies Record<PermissionAction, PermissionAction>;

/** Unmatched calls are allowed. */
export const SAFE_CATEGORIES: readonly string[] = ["read", "grep", "find", "ls", "subagent", "search_agents"];
/** Unmatched calls are denied. Any other category asks. */
export const RISKY_CATEGORIES: readonly string[] = ["bash", "powershell", "shell", "edit", "write"];
/** Categories whose command is decided by the bash validator. */
const SHELL_CATEGORIES: readonly string[] = ["bash", "shell", "powershell"];
/** Tools whose argument is always a path. */
export const FILE_TOOLS: readonly string[] = ["read", "edit", "write", "ls", "apply_patch"];
/** Every key a file tool may read its path from; all present ones are judged, `path` first. */
const PATH_KEYS: readonly string[] = ["path", "file_path"];
/** pi's grep and find read only `path`. */
const OPTIONAL_PATH_KEYS: readonly string[] = ["path"];
/** Categories that change files; a call without a path field cannot be verified. */
const FILE_CHANGING_CATEGORIES: readonly string[] = ["edit", "write"];
const UNVERIFIABLE_PATH_REASON = "cannot verify the target path of a file-changing call";
/** Tools whose argument is a path only when a path key is present. */
const OPTIONAL_PATH_TOOLS: readonly string[] = ["grep", "find"];
const WILDCARD = "*";
const NO_ARG = "";
const KEY_SEPARATOR = "\u0000";
/** Higher is more restrictive; per-key decisions combine to the maximum. */
const RESTRICTIVENESS: Record<PermissionAction, number> = {
  [ACTION.allow]: 0,
  [ACTION.ask]: 1,
  [ACTION.deny]: 2,
};
const PREVIEW_MAX = 80;

const CHOICE_ONCE = "Allow once";
const CHOICE_ALWAYS = "Allow always (this session)";
const CHOICE_DENY = "Deny";
const CHOICES = [CHOICE_ONCE, CHOICE_ALWAYS, CHOICE_DENY];

// ─── Decision ────────────────────────────────────────────────────────────────

export interface PolicyDecisionInput {
  toolName: string;
  input: Record<string, unknown>;
  policy: EffectivePolicy;
  inherited: PermissionRule[];
  cwd: string;
  home?: string;
  realpath?: (p: string) => string;
}

export interface PolicyDecision {
  action: PermissionAction;
  category: string;
  /** Non-overridable deny: never asks, never memoized */
  hard: boolean;
  reason: string;
  matched?: PermissionRule;
  /** Every spelling the call was evaluated against (all keys) */
  candidates: string[];
  /** Path keys present on the call, `path` first; empty when the call has no path */
  targets: PathTarget[];
}

/** One path key of a call with every spelling a rule may target; candidates[0] is the lexical absolute path. */
export interface PathTarget {
  key: string;
  value: string;
  candidates: string[];
}

function str(input: Record<string, unknown>, key: string): string | undefined {
  return typeof input[key] === "string" ? (input[key] as string) : undefined;
}

function pathKeysFor(toolName: string): readonly string[] {
  if (FILE_TOOLS.includes(toolName)) return PATH_KEYS;
  if (OPTIONAL_PATH_TOOLS.includes(toolName)) return OPTIONAL_PATH_KEYS;
  return [];
}

// pi's tools execute on `path` but keep extra keys, so judging only one key would let a decoy pass.
function pathTargets(options: PolicyDecisionInput): PathTarget[] {
  const targets: PathTarget[] = [];
  for (const key of pathKeysFor(options.toolName)) {
    const value = str(options.input, key);
    if (value === undefined) continue;
    const candidates = pathCandidates(value, options.cwd, { home: options.home, realpath: options.realpath });
    targets.push({ key, value, candidates });
  }
  return targets;
}

/** Candidate groups decided separately: one per path key, or a single group for path-less calls. */
function candidateGroups(options: PolicyDecisionInput, targets: PathTarget[]): string[][] {
  if (targets.length > 0) return targets.map((target) => target.candidates);
  if (FILE_TOOLS.includes(options.toolName)) return [[NO_ARG]];
  return [[extractToolArg(options.toolName, options.input) ?? NO_ARG]];
}

// Case-insensitive filesystems cannot canonicalize the case of a missing component,
// so hard denies ignore case everywhere (only ever stricter).
export function matchesHard(pattern: string, candidate: string): boolean {
  return matchPattern(pattern.toLowerCase(), candidate.toLowerCase());
}

function defaultAction(category: string): PermissionAction {
  if (SAFE_CATEGORIES.includes(category)) return ACTION.allow;
  if (RISKY_CATEGORIES.includes(category)) return ACTION.deny;
  return ACTION.ask;
}

function hardReason(rule: PermissionRule, category: string, policy: EffectivePolicy): string {
  if (rule.pattern !== WILDCARD) {
    return `path is protected (alwaysDeny.paths or built-in protection "${rule.pattern}")`;
  }
  const { user, project } = policy.sources;
  const deniedTools = (user.policy?.alwaysDeny.tools ?? []).map(toolToPermission);
  if (deniedTools.some((tool) => matchPermissionKey(tool, category))) {
    return `"${category}" is listed in alwaysDeny.tools of ${user.path}`;
  }
  const invalid = [user, project].filter((file) => file.status === POLICY_FILE_STATUS.invalid);
  return `invalid policy file ${invalid.map((file) => file.path).join(", ")}; ${category} is blocked until it is fixed`;
}

function defaultReason(category: string, action: PermissionAction): string {
  if (action === ACTION.deny) return `unlisted ${category} operations are denied by the active permission policy`;
  if (action === ACTION.ask) return `unlisted ${category} operations require confirmation under the active permission policy`;
  return `unlisted ${category} operations are allowed by the active permission policy`;
}

export function decidePolicyCall(options: PolicyDecisionInput): PolicyDecision {
  const { toolName, policy, inherited } = options;
  const category = toolToPermission(toolName);
  const targets = pathTargets(options);
  const groups = candidateGroups(options, targets);
  const candidates = [...new Set(groups.flat())];

  // apply_patch-style tools carry paths inside patch text, which rules cannot see.
  if (FILE_TOOLS.includes(toolName) && FILE_CHANGING_CATEGORIES.includes(category) && targets.length === 0) {
    return { action: ACTION.deny, category, hard: true, reason: UNVERIFIABLE_PATH_REASON, candidates, targets };
  }

  for (const rule of policy.hardRules) {
    if (!matchPermissionKey(rule.permission, category)) continue;
    if (!candidates.some((candidate) => matchesHard(rule.pattern, candidate))) continue;
    return {
      action: ACTION.deny,
      category,
      hard: true,
      reason: hardReason(rule, category, policy),
      matched: rule,
      candidates,
      targets,
    };
  }

  if (SHELL_CATEGORIES.includes(category)) {
    const shell = validateShellCommand({
      command: extractToolArg(toolName, options.input) ?? NO_ARG,
      category,
      policy,
      inherited,
      cwd: options.cwd,
      home: options.home,
      realpath: options.realpath,
    });
    return { action: shell.action, category, hard: shell.hard, reason: shell.reason, candidates, targets };
  }

  const rules = [...policy.rules, ...inherited];
  // Ties keep the earlier group, so `path` explains the decision when keys agree.
  const strictest = groups
    .map((group) => decideGroup(rules, category, group))
    .reduce((kept, next) => (RESTRICTIVENESS[next.action] > RESTRICTIVENESS[kept.action] ? next : kept));
  return { ...strictest, candidates, targets };
}

// The highest-index rule matching any spelling equals the max of per-spelling last matches.
function decideGroup(rules: PermissionRule[], category: string, group: string[]): PolicyDecision {
  for (let index = rules.length - 1; index >= 0; index--) {
    const rule = rules[index];
    if (!matchPermissionKey(rule.permission, category)) continue;
    if (!group.some((candidate) => matchPattern(rule.pattern, candidate))) continue;
    return {
      action: rule.action,
      category,
      hard: false,
      reason: `rule ${rule.permission} "${rule.pattern}"`,
      matched: rule,
      candidates: group,
      targets: [],
    };
  }
  const action = defaultAction(category);
  return { action, category, hard: false, reason: defaultReason(category, action), candidates: group, targets: [] };
}

// ─── Gate Registration ───────────────────────────────────────────────────────

function preview(value: string, max = PREVIEW_MAX): string {
  const flat = value.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

// Shows every distinct path value, `path` first, so the user sees any decoy key too.
function describeTargets(targets: PathTarget[]): string {
  const [first, ...rest] = targets;
  const shown = new Set<string>([first.value]);
  const extras: string[] = [];
  for (const target of rest) {
    if (shown.has(target.value)) continue;
    shown.add(target.value);
    extras.push(`${target.key}: ${preview(target.value)}`);
  }
  return extras.length > 0 ? `${preview(first.value)} (also ${extras.join(", ")})` : preview(first.value);
}

function memoKeyFor(decision: PolicyDecision): string {
  // An "always" for one command or path set must not unlock the whole risky category.
  if (!RISKY_CATEGORIES.includes(decision.category)) return decision.category;
  const subjects = decision.targets.length > 0
    ? decision.targets.map((target) => target.candidates[0]).sort()
    : [decision.candidates[0]];
  return [decision.category, ...subjects].join(KEY_SEPARATOR);
}

/** `shown` is already previewed. */
function blocked(toolName: string, shown: string | undefined, reason: string): { block: true; reason: string } {
  const operation = shown ? `${toolName} ${shown}` : toolName;
  return {
    block: true,
    reason:
      `Permission denied.\nOperation: ${operation}\nReason: ${reason}\n` +
      `Do not retry this operation or attempt it through another tool.`,
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export interface PolicyGateOptions {
  runtime: PolicyRuntime;
  resolveAgent: () => AgentDefinition | undefined;
  /** Parent's rules, appended after the policy rules (authority ceiling). */
  inheritedRules: () => PermissionRule[];
  /** Session-scoped "always allow" memo. Injectable for tests. */
  alwaysAllow?: Map<string, boolean>;
}

export function registerPolicyGate(pi: ExtensionAPI, options: PolicyGateOptions): void {
  const { runtime } = options;
  const alwaysAllow = options.alwaysAllow ?? new Map<string, boolean>();

  pi.on("before_agent_start", (_event, ctx: ExtensionContext) => {
    for (const warning of runtime.beginRun(ctx.cwd, options.resolveAgent())) {
      ctx.ui.notify(warning, "warning");
    }
    return undefined;
  });

  pi.on("tool_call", async (event, ctx: ExtensionContext) => {
    const toolName = event.toolName;
    let shown: string | undefined;
    try {
      const policy = runtime.policyFor(options.resolveAgent(), ctx.cwd);
      if (!policy) return undefined;

      const input = (event as { input?: Record<string, unknown> }).input ?? {};
      const arg = extractToolArg(toolName, input);
      shown = arg === undefined ? undefined : preview(arg);
      const decision = decidePolicyCall({
        toolName,
        input,
        policy,
        inherited: options.inheritedRules(),
        cwd: ctx.cwd,
        home: runtime.home,
        realpath: runtime.realpath,
      });

      if (decision.targets.length > 0) shown = describeTargets(decision.targets);

      if (decision.action === ACTION.allow) return undefined;
      if (decision.action === ACTION.deny) return blocked(toolName, shown, decision.reason);

      const memoKey = memoKeyFor(decision);
      if (alwaysAllow.get(memoKey)) return undefined;

      if (!ctx.hasUI) {
        return blocked(
          toolName,
          shown,
          `${decision.reason}; confirmation is required but this process is non-interactive (subagent), ` +
            `so the call was blocked (fail-closed)`,
        );
      }

      const target = shown ? `: ${shown}` : "";
      const choice = await ctx.ui.select(`Permission: allow ${toolName}${target}?`, CHOICES);
      if (choice === CHOICE_ALWAYS) {
        alwaysAllow.set(memoKey, true);
        return undefined;
      }
      if (choice === CHOICE_ONCE) return undefined;
      return blocked(toolName, shown, choice === undefined ? "no answer was given" : "the user denied it");
    } catch (error) {
      return blocked(toolName, shown, `permission check failed (fail-closed): ${errorMessage(error)}`);
    }
  });
}
