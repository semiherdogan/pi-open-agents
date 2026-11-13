/**
 * Read-only `/permissions` command: shows the effective policy, where it comes
 * from, and how a hypothetical call would be decided. Every verdict comes from
 * the same functions the gates enforce with; nothing here writes policy files
 * or executes the explained call.
 */

import { homedir } from "node:os";
import path from "node:path";

import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";

import type { RecursionEnv } from "../subagent/env.ts";
import type { AgentDefinition, PermissionAction, PermissionRule } from "../types.ts";
import { buildPermissionSummary, delegateCandidates, type PermissionAwarenessOptions } from "./awareness.ts";
import { DELEGATION_MODE, delegationModesFor } from "./delegation.ts";
import { decideToolCall } from "./gate.ts";
import { POLICY_FILE_STATUS, projectPolicyPath, userPolicyPath, type PolicyFile } from "./loader.ts";
import { parsePermissionRules } from "./parser.ts";
import { decideWithCeilings, FILE_TOOLS } from "./policy-gate.ts";
import type { PolicyRuntime } from "./policy-runtime.ts";
import { canonicalPath, isInside, type EffectivePolicy } from "./resolver.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

export const PERMISSIONS_COMMAND = "permissions";

export const SUBCOMMAND = {
  source: "source",
  reload: "reload",
  explain: "explain",
  help: "help",
} as const;

type NotifyLevel = "info" | "warning" | "error";
const LEVEL = {
  info: "info",
  warning: "warning",
  error: "error",
} as const satisfies Record<NotifyLevel, NotifyLevel>;

const ACTION = {
  allow: "allow",
  ask: "ask",
  deny: "deny",
} as const satisfies Record<PermissionAction, PermissionAction>;

const NO_AGENT = "(no agent)";
const YES = "yes";
const NO = "no";
const HOME_PREFIX = "~/";
const FIRST_WORD = /^(\S+)\s*([\s\S]*)$/;

const COMMAND_ARG_KEY = "command";
const PATH_ARG_KEY = "path";
// extractToolArg reads `path` first for tools it does not know.
const GENERIC_ARG_KEY = "path";
// apply_patch carries paths inside patch text; a path key would make explain verify a path the real gate cannot.
const APPLY_PATCH_TOOL = "apply_patch";
const PATCH_ARG_KEY = "input";
const COMMAND_TOOLS: readonly string[] = ["bash", "shell", "powershell"];
const PATH_TOOLS: readonly string[] = [...FILE_TOOLS, "grep", "find"];

const USAGE = [
  "Usage:",
  "/permissions: effective permissions of the active agent",
  "/permissions <agent>: effective permissions of <agent> as a primary agent",
  "/permissions source: policy files, trust and where the active agent comes from",
  "/permissions reload: re-read the policy files now",
  "/permissions explain <tool> <argument...>: how a call would be decided (never executed)",
  "/permissions help: this text",
].join("\n");
const SNAPSHOT_NOTE = "Running subagents keep their policy snapshot; the change applies from the next run.";
const BUSY_RELOAD = "An agent run is in progress; reload after it finishes so the running agent keeps its policy.";
const NOT_EXECUTED = "Nothing was executed.";
const HEADLESS_NOTE = " (headless: deny, subagents cannot ask)";
const EXEMPT_NOTE = "No agent is active: the permission policy does not apply to this session.";
const EXEMPT_HINT = `Select an agent to enforce it, or run /${PERMISSIONS_COMMAND} <agent> to see what an agent may do.`;
const EXEMPT_REASON = "no agent is active; the permission policy does not apply";
const STRICT_MODE = {
  on: "on",
  off: "off (legacy frontmatter gate)",
  exempt: "not applied (no active agent)",
} as const;

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PermissionCommandOptions {
  runtime: PolicyRuntime;
  resolveAgent: () => AgentDefinition | undefined;
  getAgents: () => AgentDefinition[];
  /** Same source the gates use when no snapshot was received. */
  inheritedRules: () => PermissionRule[];
  env?: RecursionEnv;
}

interface Report {
  text: string;
  level: NotifyLevel;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function agentLabel(agent: AgentDefinition | undefined): string {
  return agent?.name ?? NO_AGENT;
}

function fileStatus(label: string, file: PolicyFile<unknown>): string {
  const error = file.status === POLICY_FILE_STATUS.invalid ? ` (${file.error})` : "";
  return `${label}: ${file.path}: ${file.status}${error}`;
}

function anyInvalid(files: PolicyFile<unknown>[]): boolean {
  return files.some((file) => file.status === POLICY_FILE_STATUS.invalid);
}

function strictOffText(runtime: PolicyRuntime, cwd: string): string {
  return [
    "Strict permission mode is off: no policy file exists.",
    `Looked for: ${userPolicyPath(runtime.agentDir)} and ${projectPolicyPath(cwd)}.`,
    "The legacy frontmatter gate applies (agent `permission` rules; unmatched calls proceed).",
  ].join("\n");
}

function inheritedFor(options: PermissionCommandOptions): PermissionRule[] {
  return options.runtime.fromSnapshot ? options.runtime.inherited() : options.inheritedRules();
}

function argumentKey(toolName: string): string {
  if (toolName === APPLY_PATCH_TOOL) return PATCH_ARG_KEY;
  if (COMMAND_TOOLS.includes(toolName)) return COMMAND_ARG_KEY;
  if (PATH_TOOLS.includes(toolName)) return PATH_ARG_KEY;
  return GENERIC_ARG_KEY;
}

function expandHome(entry: string, home: string): string {
  return entry.startsWith(HOME_PREFIX) ? path.join(home, entry.slice(HOME_PREFIX.length)) : entry;
}

// Mirrors the resolver's trust check to name the entry that made the project trusted.
function trustedEntry(runtime: PolicyRuntime, entries: string[], projectRoot: string): string | undefined {
  const real = runtime.realpath ?? canonicalPath;
  const home = real(runtime.home ?? homedir());
  const root = real(projectRoot);
  return entries.find((entry) => isInside(real(expandHome(entry, home)), root));
}

// ─── Subcommands ─────────────────────────────────────────────────────────────

function summary(pi: ExtensionAPI, options: PermissionCommandOptions, ctx: ExtensionCommandContext, named?: AgentDefinition): Report {
  const { runtime } = options;
  if (!runtime.isActive(ctx.cwd)) return { text: strictOffText(runtime, ctx.cwd), level: LEVEL.info };
  if (!named && runtime.isExempt(options.resolveAgent())) return { text: `${EXEMPT_NOTE}\n${EXEMPT_HINT}`, level: LEVEL.info };

  const files = runtime.files(ctx.cwd);
  const awareness: PermissionAwarenessOptions = {
    runtime,
    resolveAgent: options.resolveAgent,
    inheritedRules: options.inheritedRules,
    agents: options.getAgents(),
    env: options.env,
  };
  let policy: EffectivePolicy | undefined;
  let ceilings: EffectivePolicy[] = [];
  let inherited: PermissionRule[] = [];
  let tools: string[] | undefined;
  let candidates: AgentDefinition[] = [];
  const agent = named ?? options.resolveAgent();
  if (named) {
    // As a primary: resolved from this run's files, no ceilings or inherited rules.
    policy = runtime.resolveFrom(files, named, ctx.cwd);
    const namedTools = (named.tools ?? pi.getActiveTools()).map((tool) => tool.toLowerCase());
    // A child's delegation state is the parent's snapshot, which says nothing about another agent.
    if (!runtime.fromSnapshot) candidates = delegateCandidates(awareness, named, namedTools);
  } else {
    policy = runtime.policyFor(agent, ctx.cwd);
    ceilings = runtime.ceilings();
    inherited = inheritedFor(options);
    tools = pi.getActiveTools();
    candidates = delegateCandidates(awareness, agent, tools);
  }
  if (!policy) return { text: strictOffText(runtime, ctx.cwd), level: LEVEL.info };

  const modes = delegationModesFor(runtime, agent, candidates, ctx.cwd);
  const text = buildPermissionSummary({
    policy,
    ceilings,
    inherited,
    cwd: ctx.cwd,
    home: runtime.home,
    realpath: runtime.realpath,
    headless: !ctx.hasUI,
    delegates: candidates.map((candidate) => ({ name: candidate.name, mode: modes.get(candidate.name) ?? DELEGATION_MODE.restrict })),
    tools,
  });
  const origin = runtime.fromSnapshot ? "parent snapshot of " : "";
  const source =
    `Source: ${origin}user ${files.user.path} (${files.user.status}), project ${files.project.path} (${files.project.status}); ` +
    `details: /${PERMISSIONS_COMMAND} ${SUBCOMMAND.source}`;
  const level = anyInvalid([files.user, files.project]) ? LEVEL.warning : LEVEL.info;
  return { text: `${text}\n${source}`, level };
}

function source(options: PermissionCommandOptions, ctx: ExtensionCommandContext): Report {
  const { runtime } = options;
  const active = options.resolveAgent();
  const files = runtime.files(ctx.cwd);
  const strict = runtime.isActive(ctx.cwd);
  const exempt = strict && runtime.isExempt(active);
  let mode: string = STRICT_MODE.off;
  if (exempt) mode = STRICT_MODE.exempt;
  else if (strict) mode = STRICT_MODE.on;
  const lines = [
    `Strict mode: ${mode}`,
    fileStatus("User policy", files.user),
    fileStatus("Project policy", files.project),
  ];

  const policy = strict ? runtime.policyFor(active, ctx.cwd) : undefined;
  if (policy) {
    const projectRoot = path.dirname(path.dirname(files.project.path));
    const entry = policy.trusted ? trustedEntry(runtime, files.user.policy?.trustedProjects ?? [], projectRoot) : undefined;
    lines.push(`Trusted: ${policy.trusted ? YES : NO}${entry ? ` (trustedProjects entry ${entry})` : ""}`);
  } else if (!exempt) {
    lines.push(`Trusted: ${NO} (strict mode off)`);
  }

  lines.push(active ? `Agent: ${active.name} (${active.source}, ${active.filePath})` : `Agent: ${NO_AGENT}`);
  if (runtime.fromSnapshot) {
    lines.push(
      `Policy received from parent snapshot: ${runtime.ceilings().length} ceiling(s), ${runtime.inherited().length} inherited rule(s)`,
    );
  }
  const level = anyInvalid([files.user, files.project]) ? LEVEL.error : LEVEL.info;
  return { text: lines.join("\n"), level };
}

function reload(options: PermissionCommandOptions, ctx: ExtensionCommandContext): Report {
  const { runtime } = options;
  if (!ctx.isIdle()) return { text: BUSY_RELOAD, level: LEVEL.warning };
  const active = options.resolveAgent();
  const fresh = runtime.beginRun(ctx.cwd, active);
  const files = runtime.files(ctx.cwd);
  const lines = runtime.fromSnapshot
    ? ["This process runs on its parent's policy snapshot; its policy files are not re-read."]
    : ["Reloaded the permission policy files."];
  lines.push(fileStatus("User policy", files.user), fileStatus("Project policy", files.project));
  if (!runtime.isActive(ctx.cwd)) lines.push("Strict mode is off; the legacy frontmatter gate applies.");
  else if (runtime.isExempt(active)) lines.push(EXEMPT_NOTE);
  const warnings = [...new Set([...fresh, ...(runtime.policyFor(active, ctx.cwd)?.warnings ?? [])])];
  for (const warning of warnings) lines.push(`Warning: ${warning}`);
  lines.push(SNAPSHOT_NOTE);
  let level: NotifyLevel = LEVEL.info;
  if (warnings.length > 0) level = LEVEL.warning;
  if (anyInvalid([files.user, files.project])) level = LEVEL.error;
  return { text: lines.join("\n"), level };
}

function actionLine(action: PermissionAction): string {
  return `Action: ${action}${action === ACTION.ask ? HEADLESS_NOTE : ""}`;
}

function explain(options: PermissionCommandOptions, ctx: ExtensionCommandContext, rest: string): Report {
  const match = FIRST_WORD.exec(rest);
  const toolName = match?.[1];
  const argument = match?.[2].trim() ?? "";
  if (!toolName || argument === "") {
    return { text: `Missing tool or argument.\n${USAGE}`, level: LEVEL.error };
  }
  const { runtime } = options;
  const active = options.resolveAgent();
  const input = { [argumentKey(toolName)]: argument };
  const header = `Explain: ${toolName} ${argument} (agent ${agentLabel(active)})`;

  if (!runtime.isActive(ctx.cwd)) {
    const rules = [...(active?.permission ? parsePermissionRules(active.permission) : []), ...options.inheritedRules()];
    const decision = decideToolCall(toolName, input, rules);
    let reason = `no rule matched; unmatched ${decision.category} calls proceed`;
    if (!decision.gated) reason = `no rules for category ${decision.category}; the call is not gated`;
    else if (decision.matched) reason = `rule ${decision.matched.permission} "${decision.matched.pattern}"`;
    const lines = [
      header,
      "Legacy mode (no policy file): decided by the agent's frontmatter permission rules.",
      actionLine(decision.action),
      `Hard: ${NO}`,
      `Reason: ${reason}`,
      ...(decision.matched ? [`Matched rule: ${decision.matched.permission} "${decision.matched.pattern}" -> ${decision.matched.action}`] : []),
      NOT_EXECUTED,
    ];
    return { text: lines.join("\n"), level: LEVEL.info };
  }

  if (runtime.isExempt(active)) {
    const lines = [header, EXEMPT_NOTE, actionLine(ACTION.allow), `Hard: ${NO}`, `Reason: ${EXEMPT_REASON}`, NOT_EXECUTED];
    return { text: lines.join("\n"), level: LEVEL.info };
  }

  const policy = runtime.policyFor(active, ctx.cwd);
  if (!policy) return { text: strictOffText(runtime, ctx.cwd), level: LEVEL.info };
  const decision = decideWithCeilings(
    {
      toolName,
      input,
      policy,
      inherited: inheritedFor(options),
      cwd: ctx.cwd,
      home: runtime.home,
      realpath: runtime.realpath,
    },
    runtime.ceilings(),
  );
  const lines = [
    header,
    actionLine(decision.action),
    `Hard: ${decision.hard ? YES : NO}`,
    `Reason: ${decision.reason}`,
    ...(decision.matched ? [`Matched rule: ${decision.matched.permission} "${decision.matched.pattern}" -> ${decision.matched.action}`] : []),
    NOT_EXECUTED,
  ];
  return { text: lines.join("\n"), level: LEVEL.info };
}

function namedAgent(pi: ExtensionAPI, options: PermissionCommandOptions, ctx: ExtensionCommandContext, name: string): Report {
  const agents = options.getAgents();
  const agent = agents.find((candidate) => candidate.name === name);
  if (agent) return summary(pi, options, ctx, agent);
  const known = agents.map((candidate) => candidate.name).join(", ") || "(none defined)";
  return { text: `Unknown agent "${name}". Known agents: ${known}`, level: LEVEL.error };
}

function dispatch(pi: ExtensionAPI, options: PermissionCommandOptions, ctx: ExtensionCommandContext, args: string): Report {
  const match = FIRST_WORD.exec(args.trim());
  if (!match) return summary(pi, options, ctx);
  const [, sub, rest] = match;
  switch (sub) {
    case SUBCOMMAND.help:
      return { text: USAGE, level: LEVEL.info };
    case SUBCOMMAND.source:
      return source(options, ctx);
    case SUBCOMMAND.reload:
      return reload(options, ctx);
    case SUBCOMMAND.explain:
      return explain(options, ctx, rest);
    default:
      if (rest.trim() === "") return namedAgent(pi, options, ctx, sub);
      return { text: `Unknown subcommand "${sub}".\n${USAGE}`, level: LEVEL.warning };
  }
}

// ─── Registration ────────────────────────────────────────────────────────────

export function registerPermissionCommands(pi: ExtensionAPI, options: PermissionCommandOptions): void {
  pi.registerCommand(PERMISSIONS_COMMAND, {
    description: "Show the effective permission policy (read-only)",
    getArgumentCompletions: (prefix) => {
      if (/\s/.test(prefix)) return null;
      const names = [...Object.values(SUBCOMMAND), ...options.getAgents().map((agent) => agent.name)];
      const items = names.filter((name) => name.startsWith(prefix)).map((name) => ({ value: name, label: name }));
      return items.length > 0 ? items : null;
    },
    handler: async (args, ctx) => {
      let report: Report;
      try {
        report = dispatch(pi, options, ctx, args ?? "");
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        report = { text: `Permission report failed: ${message}`, level: LEVEL.error };
      }
      ctx.ui.notify(report.text, report.level);
    },
  });
}
