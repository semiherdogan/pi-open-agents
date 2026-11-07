/**
 * Permission awareness: a short "Runtime Permissions" section appended to the
 * system prompt in strict mode. Every verdict is asked of the same engine the
 * policy gate enforces with (decideWithCeilings), so the prompt cannot promise
 * what the gate denies. The text is deterministic for a given policy, which
 * keeps prompt caching intact.
 */

import { statSync } from "node:fs";

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import { spawnableAgents } from "../discovery/loader.ts";
import { allowedAgentNames, isPastMaxDepth, type RecursionEnv } from "../subagent/env.ts";
import type { AgentDefinition, PermissionAction, PermissionRule } from "../types.ts";
import { DELEGATION_MODE, delegationModesFor, type DelegationMode } from "./delegation.ts";
import { matchPermissionKey } from "./evaluator.ts";
import { matchPattern } from "./matcher.ts";
import { decideWithCeilings } from "./policy-gate.ts";
import type { PolicyRuntime } from "./policy-runtime.ts";
import { BUILTIN_PROTECTED_PATHS, type EffectivePolicy } from "./resolver.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

const ACTION = {
  allow: "allow",
  ask: "ask",
  deny: "deny",
} as const satisfies Record<PermissionAction, PermissionAction>;

export const SUMMARY_HEADER = "## Runtime Permissions";
export const SUMMARY_UNAVAILABLE = `${SUMMARY_HEADER}\nPermission summary unavailable; enforcement is unchanged.`;
const SECTION_SEPARATOR = "\n\n";
const NO_AGENT = "(no agent)";

/** A representative project file the FILES verdicts are decided for (relative to cwd). */
export const PROBE_FILE = "src/example.ts";
/** Stands in for a `*` or `**` run when a pattern is turned into a probe. */
export const PROBE_WORD = "example";
/** Stands in for a `?`, which matches exactly one character. */
export const PROBE_CHAR = "x";
const FILE_TOOLS = ["read", "edit", "write"] as const;
type FileTool = (typeof FILE_TOOLS)[number];
const BASH_TOOL = "bash";
const SHELL_TOOLS: readonly string[] = [BASH_TOOL, "shell", "powershell"];
const SUBAGENT_TOOL = "subagent";
/** Tools with their own summary line; "Other tools" covers the rest. */
const COVERED_TOOLS: readonly string[] = [...FILE_TOOLS, ...SHELL_TOOLS, SUBAGENT_TOOL];
const WILDCARD = "*";
const STAR_RUN = /\*+/g;
const SINGLE_CHAR = /\?/g;
const TOKEN_SPLIT = /\s+/;
const ANY_DESCENDANT = "/**";
const RULE_KEY_SEPARATOR = "\u0000";
const PATH_LIST_MAX = 8;
const COMMAND_LIST_MAX = 16;
const DELEGATE_LIST_MAX = 8;
const TOOL_LIST_MAX = 12;

// Policy text is untrusted prompt input: one line per item, no code-span breakouts, bounded length.
const UNSAFE_CHARS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu;
const UNSAFE_REPLACEMENT = " ";
const BACKTICK = /`/g;
const BACKTICK_REPLACEMENT = "'";
const ITEM_MAX = 80;
const PATH_MAX = 240;
/** Cache-key stand-in when the delegating agent file cannot be stat'ed. */
const AGENT_FILE_MISSING = "missing";
const TRUNCATION_MARKER = "\u2026";

const VERDICT: Record<PermissionAction, string> = {
  [ACTION.allow]: "allowed",
  [ACTION.ask]: "asks for approval",
  [ACTION.deny]: "denied",
};
const HEADLESS_ASK = "denied (no approval in subagents)";
const GENERIC_OTHER_TOOLS = "Other tools: grep, find, ls allowed";

const MODE_TEXT: Record<DelegationMode, string> = {
  [DELEGATION_MODE.role]: "role (own permissions)",
  [DELEGATION_MODE.restrict]: "restrict (limited to your permissions)",
};

const GIT_LINE =
  "Git: read-only git (status, diff, log, show, ...) only if listed under Bash; staging, committing, pushing, " +
  "resetting, checkout/switch/restore, stash, rebase, merge, branch/tag changes and config changes are forbidden.";
const BEHAVIOR_LINES = [
  "Do not attempt forbidden operations. Do not retry a denied operation through another tool, a wrapper, a script, or another agent.",
  "Plan with the permissions above; when a task needs more, tell the user what is needed and why.",
];

// ─── Summary ─────────────────────────────────────────────────────────────────

export interface DelegateEntry {
  name: string;
  mode: DelegationMode;
}

export interface PermissionSummaryInput {
  policy: EffectivePolicy;
  ceilings: EffectivePolicy[];
  inherited: PermissionRule[];
  cwd: string;
  home?: string;
  realpath?: (p: string) => string;
  /** No UI to answer an ask (subagent child): asks fail closed. */
  headless: boolean;
  /** Agents the subagent tool would accept, with the planner's mode. */
  delegates: DelegateEntry[];
  /** Active tool names; without them the "Other tools" line falls back to the category defaults. */
  tools?: string[];
}

function decide(input: PermissionSummaryInput, toolName: string, args: Record<string, unknown>): PermissionAction {
  return decideWithCeilings(
    {
      toolName,
      input: args,
      policy: input.policy,
      inherited: input.inherited,
      cwd: input.cwd,
      home: input.home,
      realpath: input.realpath,
    },
    input.ceilings,
  ).action;
}

function verdict(action: PermissionAction, headless: boolean): string {
  return action === ACTION.ask && headless ? HEADLESS_ASK : VERDICT[action];
}

// Headless asks fail closed, so they are denials in effect.
function effective(action: PermissionAction, headless: boolean): PermissionAction {
  return action === ACTION.ask && headless ? ACTION.deny : action;
}

export function sanitize(value: string): string {
  return sanitizeTo(value, ITEM_MAX);
}

// Separate from sanitize: callers pass it to Array.map, which would feed the index in as the cap.
function sanitizeTo(value: string, max: number): string {
  const chars = [...value.replace(UNSAFE_CHARS, UNSAFE_REPLACEMENT).replace(BACKTICK, BACKTICK_REPLACEMENT)];
  return chars.length > max ? chars.slice(0, max - 1).join("") + TRUNCATION_MARKER : chars.join("");
}

function capped(items: string[], max: number): string {
  const shown = items.slice(0, max).join(", ");
  return items.length > max ? `${shown}, and ${items.length - max} more` : shown;
}

function code(value: string): string {
  return `\`${sanitize(value)}\``;
}

function pathCode(value: string): string {
  return `\`${sanitizeTo(value, PATH_MAX)}\``;
}

function ruleKey(rule: PermissionRule): string {
  return [rule.permission, rule.pattern, rule.action].join(RULE_KEY_SEPARATOR);
}

// Hard rules are covered by the protected section; they are not the agent's own rules.
function ownRules(policy: EffectivePolicy): PermissionRule[] {
  const hard = new Set(policy.hardRules.map(ruleKey));
  return policy.rules.filter((rule) => !hard.has(ruleKey(rule)));
}

function tokens(value: string): string[] {
  return value.trim().split(TOKEN_SPLIT).filter((token) => token !== "");
}

function probeText(pattern: string): string {
  return pattern.replace(STAR_RUN, PROBE_WORD).replace(SINGLE_CHAR, PROBE_CHAR);
}

/** A command the pattern's token prefix matches: literal tokens kept, glob characters replaced by placeholders. */
export function probeCommand(pattern: string): string {
  return tokens(pattern).map(probeText).join(" ");
}

/** A path the pattern matches; relative patterns stay relative, so the gate resolves them against cwd like the tools do. */
export function probePath(pattern: string): string {
  return probeText(pattern.trim());
}

// Same token-prefix shape as the bash validator's rule match.
function prefixCovers(prefix: string, command: string): boolean {
  const pattern = tokens(prefix);
  const words = tokens(command);
  if (pattern.length === 0 || words.length < pattern.length) return false;
  return pattern.every((token, i) => token === WILDCARD || matchPattern(token, words[i]));
}

function bashRules(rules: PermissionRule[]): PermissionRule[] {
  return rules.filter((rule) => matchPermissionKey(rule.permission, BASH_TOOL));
}

function isBlanket(pattern: string): boolean {
  return pattern.trim() === WILDCARD;
}

// Every rule source the gate consults: own, inherited, and each ceiling's own rules.
function gateRules(input: PermissionSummaryInput): PermissionRule[] {
  return [...ownRules(input.policy), ...input.inherited, ...input.ceilings.flatMap(ownRules)];
}

export interface BashFacts {
  /** Own patterns whose probe the engine allows. */
  allowed: string[];
  /** Patterns from any source the engine asks for, outside every allowed prefix. */
  asks: string[];
  /** A blanket `*` allow survives every ceiling. */
  blanket: boolean;
  /** Patterns from any source the engine denies although the blanket allow would let them through. */
  denied: string[];
  /** Patterns from any source whose probe falls under an allowed prefix and the engine denies. */
  exceptionsDenied: string[];
  /** Same for asks; headless asks count as denied. */
  exceptionsAsk: string[];
}

export function bashFacts(input: PermissionSummaryInput): BashFacts {
  const facts: BashFacts = { allowed: [], asks: [], blanket: false, denied: [], exceptionsDenied: [], exceptionsAsk: [] };
  const seen = new Set<string>();
  for (const rule of bashRules(ownRules(input.policy))) {
    const pattern = rule.pattern.trim();
    if (rule.action !== ACTION.allow || seen.has(pattern)) continue;
    seen.add(pattern);
    if (decide(input, BASH_TOOL, { command: probeCommand(pattern) }) !== ACTION.allow) continue;
    if (isBlanket(pattern)) facts.blanket = true;
    else facts.allowed.push(pattern);
  }
  addRestrictions(input, facts);
  return facts;
}

// A deny/ask from any source is listed wherever the generic bash verdict would hide it.
function addRestrictions(input: PermissionSummaryInput, facts: BashFacts): void {
  const seen = new Set<string>();
  for (const rule of bashRules(gateRules(input))) {
    if (rule.action === ACTION.allow) continue;
    const pattern = rule.pattern.trim();
    if (isBlanket(pattern) || seen.has(pattern)) continue;
    seen.add(pattern);
    const probe = probeCommand(pattern);
    const covered = facts.allowed.some((prefix) => prefixCovers(prefix, probe));
    const generic = covered || facts.blanket ? ACTION.allow : ACTION.deny;
    const action = effective(decide(input, BASH_TOOL, { command: probe }), input.headless);
    if (action === generic || action === ACTION.allow) continue;
    if (covered) (action === ACTION.deny ? facts.exceptionsDenied : facts.exceptionsAsk).push(pattern);
    else (action === ACTION.deny ? facts.denied : facts.asks).push(pattern);
  }
}

export function fileVerdicts(input: PermissionSummaryInput): Record<FileTool, PermissionAction> {
  const [read, edit, write] = FILE_TOOLS.map((tool) => decide(input, tool, { path: PROBE_FILE }));
  return { read, edit, write };
}

/** Path patterns from any source whose engine verdict differs from the generic Files verdict. */
function pathRules(input: PermissionSummaryInput, files: Record<FileTool, PermissionAction>): string[] {
  const lines: string[] = [];
  const seen = new Set<string>();
  for (const rule of gateRules(input)) {
    const pattern = rule.pattern.trim();
    if (isBlanket(pattern)) continue;
    for (const category of FILE_TOOLS) {
      const key = [category, pattern].join(RULE_KEY_SEPARATOR);
      if (seen.has(key) || !matchPermissionKey(rule.permission, category)) continue;
      seen.add(key);
      const action = decide(input, category, { path: probePath(pattern) });
      if (effective(action, input.headless) === effective(files[category], input.headless)) continue;
      lines.push(`${category} ${code(pattern)}: ${verdict(action, input.headless)}`);
    }
  }
  return lines;
}

function unionOf(policies: EffectivePolicy[], pick: (policy: EffectivePolicy) => string[]): string[] {
  return [...new Set(policies.flatMap(pick))];
}

function builtinProtectedNames(): string[] {
  return [...new Set(BUILTIN_PROTECTED_PATHS.map((p) => (p.endsWith(ANY_DESCENDANT) ? p.slice(0, -ANY_DESCENDANT.length) : p)))];
}

function bashLines(input: PermissionSummaryInput): string[] {
  const facts = bashFacts(input);
  const lines: string[] = [];
  if (facts.allowed.length > 0) lines.push(`Bash allowed command prefixes: ${capped(facts.allowed.map(code), COMMAND_LIST_MAX)}`);
  if (facts.asks.length > 0 && !input.headless) {
    lines.push(`Bash commands that ask for approval: ${capped(facts.asks.map(code), COMMAND_LIST_MAX)}`);
  }
  if (facts.exceptionsDenied.length > 0) {
    lines.push(`Bash exceptions (denied): ${capped(facts.exceptionsDenied.map(code), COMMAND_LIST_MAX)}`);
  }
  if (facts.exceptionsAsk.length > 0) {
    lines.push(`Bash exceptions (asks): ${capped(facts.exceptionsAsk.map(code), COMMAND_LIST_MAX)}`);
  }
  if (facts.blanket) {
    lines.push("Bash: any command not listed below as forbidden.");
    if (facts.denied.length > 0) lines.push(`Denied commands: ${capped(facts.denied.map(code), COMMAND_LIST_MAX)}`);
  } else {
    lines.push("Bash: any other command: denied.");
  }
  return lines;
}

function protectedLines(all: EffectivePolicy[]): string[] {
  const userPaths = unionOf(all, (p) => p.sources.user.policy?.alwaysDeny.paths ?? []);
  const agentDirs = unionOf(all, (p) => p.agentDirs.slice(0, 1));
  const targets = [
    `${builtinProtectedNames().join(", ")} (any project)`,
    `the pi agent directory (${agentDirs.map((dir) => sanitizeTo(dir, PATH_MAX)).join(", ")})`,
    ...userPaths.map(pathCode),
  ];
  const lines = [`Never write to: ${targets.join(", ")}.`];
  const bash = unionOf(all, (p) => p.bashDeny);
  if (bash.length > 0) lines.push(`Forbidden commands: ${bash.map(code).join(", ")}`);
  const tools = unionOf(all, (p) => p.sources.user.policy?.alwaysDeny.tools ?? []);
  if (tools.length > 0) lines.push(`Forbidden tools: ${tools.map(sanitize).join(", ")}`);
  return lines;
}

function otherToolsLines(input: PermissionSummaryInput): string[] {
  const { tools, headless } = input;
  if (tools === undefined) {
    return [`${GENERIC_OTHER_TOOLS}; any other tool ${headless ? VERDICT[ACTION.deny] : VERDICT[ACTION.ask]}.`];
  }
  const groups: Record<PermissionAction, string[]> = { [ACTION.allow]: [], [ACTION.ask]: [], [ACTION.deny]: [] };
  const names = [...new Set(tools)].filter((name) => !COVERED_TOOLS.includes(name)).sort();
  for (const name of names) groups[effective(decide(input, name, {}), headless)].push(sanitize(name));
  const parts = (Object.keys(groups) as PermissionAction[])
    .filter((action) => groups[action].length > 0)
    .map((action) => `${VERDICT[action]}: ${capped(groups[action], TOOL_LIST_MAX)}`);
  return parts.length > 0 ? [`Other tools: ${parts.join("; ")}.`] : [];
}

function delegationLines(input: PermissionSummaryInput): string[] {
  if (input.delegates.length === 0) return [];
  const action = decide(input, SUBAGENT_TOOL, {});
  if (action === ACTION.deny || (action === ACTION.ask && input.headless)) return [];
  const suffix = action === ACTION.ask ? " (each call asks for approval)" : "";
  const sorted = [...input.delegates].sort((a, b) => a.name.localeCompare(b.name));
  const entries = sorted.map((d) => `${sanitize(d.name)}: ${MODE_TEXT[d.mode]}`);
  return [`Delegation via the subagent tool${suffix}: ${capped(entries, DELEGATE_LIST_MAX)}`];
}

/** Pure and deterministic: the same policy always gives the same text. */
export function buildPermissionSummary(input: PermissionSummaryInput): string {
  const { policy, headless } = input;
  const all = [policy, ...input.ceilings];
  const files = fileVerdicts(input);
  const paths = pathRules(input, files);
  const lines = [
    SUMMARY_HEADER,
    `Agent: ${policy.agentName === undefined ? NO_AGENT : sanitize(policy.agentName)}`,
    `Files (a project file such as ${PROBE_FILE}): read ${verdict(files.read, headless)}; ` +
      `edit ${verdict(files.edit, headless)}; write ${verdict(files.write, headless)}.`,
    ...(paths.length > 0 ? [`Path rules: ${capped(paths, PATH_LIST_MAX)}`] : []),
    ...bashLines(input),
    ...(all.some((p) => p.denyGitWrite) ? [GIT_LINE] : []),
    ...protectedLines(all),
    ...delegationLines(input),
    ...otherToolsLines(input),
    ...BEHAVIOR_LINES,
  ];
  return lines.join("\n");
}

// ─── Registration ────────────────────────────────────────────────────────────

export interface PermissionAwarenessOptions {
  runtime: PolicyRuntime;
  resolveAgent: () => AgentDefinition | undefined;
  /** Same source the policy gate uses when no snapshot was received. */
  inheritedRules: () => PermissionRule[];
  agents: AgentDefinition[];
  env?: RecursionEnv;
  readFile?: (filePath: string) => string;
}

// Mirrors registerSubagentTool's filters: max depth, the env whitelist, then the active agent's allowedAgents.
export function delegateCandidates(options: PermissionAwarenessOptions, active: AgentDefinition | undefined, tools: string[]): AgentDefinition[] {
  const env = options.env ?? process.env;
  if (isPastMaxDepth(env) || !tools.includes(SUBAGENT_TOOL)) return [];
  const allowed = allowedAgentNames(env);
  const own = active?.allowedAgents && active.allowedAgents.length > 0 ? active.allowedAgents : undefined;
  return spawnableAgents(options.agents).filter((a) => (!allowed || allowed.has(a.name)) && (!own || own.includes(a.name)));
}

interface SummaryMemo {
  signature: string | undefined;
  entries: Map<string, string>;
}

// The planner reads the delegating agent's file fresh, so an edit must not hit a stale summary.
function agentFileStamp(active: AgentDefinition | undefined): [number, number] | string {
  if (!active) return AGENT_FILE_MISSING;
  try {
    const stat = statSync(active.filePath);
    return [stat.mtimeMs, stat.size];
  } catch {
    return AGENT_FILE_MISSING;
  }
}

function summaryFor(pi: ExtensionAPI, options: PermissionAwarenessOptions, ctx: ExtensionContext, memo: SummaryMemo): string | undefined {
  const { runtime } = options;
  const active = options.resolveAgent();
  const policy = runtime.policyFor(active, ctx.cwd);
  if (!policy) return undefined;
  const tools = pi.getActiveTools();
  const candidates = delegateCandidates(options, active, tools);
  const headless = !ctx.hasUI;
  // Only the current policy's summaries are worth keeping.
  if (memo.signature !== runtime.signature) {
    memo.signature = runtime.signature;
    memo.entries.clear();
  }
  const key = JSON.stringify([policy.agentName, ctx.cwd, headless, candidates.map((agent) => agent.name), tools, agentFileStamp(active)]);
  const cached = memo.entries.get(key);
  if (cached !== undefined) return cached;
  // Reads agent files and resolves policies: only on a cache miss.
  const modes = delegationModesFor(runtime, active, candidates, ctx.cwd, options.readFile);
  const delegates = candidates.map((agent) => ({ name: agent.name, mode: modes.get(agent.name) ?? DELEGATION_MODE.restrict }));
  const summary = buildPermissionSummary({
    policy,
    ceilings: runtime.ceilings(),
    inherited: runtime.fromSnapshot ? runtime.inherited() : options.inheritedRules(),
    cwd: ctx.cwd,
    home: runtime.home,
    realpath: runtime.realpath,
    headless,
    delegates,
    tools,
  });
  memo.entries.set(key, summary);
  return summary;
}

/**
 * Must be registered after upstream's before_agent_start (which may replace the
 * whole prompt) and after the policy gate's beginRun: pi chains the handlers in
 * registration order, so the section is appended last and reflects this run's snapshot.
 */
export function registerPermissionAwareness(pi: ExtensionAPI, options: PermissionAwarenessOptions): void {
  const memo: SummaryMemo = { signature: undefined, entries: new Map() };
  pi.on("before_agent_start", (event, ctx: ExtensionContext) => {
    let summary: string | undefined;
    try {
      summary = summaryFor(pi, options, ctx, memo);
    } catch (error) {
      summary = SUMMARY_UNAVAILABLE;
      const message = error instanceof Error ? error.message : String(error);
      if (ctx.hasUI) ctx.ui.notify(`Permission summary unavailable: ${message}`, "warning");
    }
    if (summary === undefined) return undefined;
    return { systemPrompt: event.systemPrompt + SECTION_SEPARATOR + summary };
  });
}
