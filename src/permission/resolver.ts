/**
 * Permission policy resolver.
 *
 * Combines agent frontmatter rules, project rules and user hard denies into
 * one effective policy. Returns undefined when no policy file exists, which
 * keeps the legacy (frontmatter-only) behavior untouched.
 */

import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import type { AgentDefinition, PermissionAction, PermissionRule } from "../types.ts";
import { toolToPermission } from "./evaluator.ts";
import { parsePermissionRules } from "./parser.ts";
import {
  ALL_AGENTS_KEY,
  POLICY_FILE_STATUS,
  type PolicyFile,
  type ProjectPolicy,
  type UserPolicy,
} from "./loader.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

const DENY: PermissionAction = "deny";
const ALLOW: PermissionAction = "allow";
const WILDCARD = "*";
const HOME_PREFIX = "~/";
const ANY_DESCENDANT = "/**";
const PATH_SEPARATOR = "/";
const GLOB_CHARS = /[*?]/;
const PARENT_DIR = "..";
const WRITE_CATEGORIES = ["edit", "write"] as const;
// User alwaysDeny.paths also block these, so credentials cannot be read and sent out.
export const READ_CATEGORIES = ["read", "grep", "find", "ls"] as const;
// Blocked when a policy file exists but cannot be validated (fail-closed).
const RISKY_CATEGORIES = ["bash", "shell", "powershell", "edit", "write"] as const;
// Agent definitions, policy files, project extensions/settings and git metadata:
// writing any of them is a privilege escalation path.
export const BUILTIN_PROTECTED_PATHS = [".git", ".git/**", ".pi/**", ".opencode/**", ".agents/**"] as const;
// The same locations in any directory, so no project's config can be authored from outside it.
// Not anchored: they have no literal prefix and must stay out of the bash ancestor check.
export const ANYWHERE_PROTECTED_PATHS = ["**/.git", "**/.git/**", "**/.pi/**", "**/.opencode/**", "**/.agents/**"] as const;

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ResolvePolicyOptions {
  agent: AgentDefinition | undefined;
  cwd: string;
  /** Also protected: `${realpath(agentDir)}/**` */
  agentDir: string;
  user: PolicyFile<UserPolicy>;
  project: PolicyFile<ProjectPolicy>;
  /** Default os.homedir(); injectable for tests */
  home?: string;
  /** Default: realpathSync.native on the longest existing ancestor, missing tail re-appended */
  realpath?: (p: string) => string;
  /** Directory trust is computed for; default cwd */
  trustRoot?: string;
  /** More directories relative protected patterns are anchored to, besides cwd */
  anchorRoots?: string[];
}

export interface EffectivePolicy {
  agentName: string | undefined;
  trusted: boolean;
  /** Frontmatter, then project `*`, then project agent rules, then hard rules last (last-match-wins). */
  rules: PermissionRule[];
  /** Denies nothing may override (project rules, "always allow" answers). Consumed by the gate in M2. */
  hardRules: PermissionRule[];
  /** User alwaysDeny.gitWrite, default true (also when the user file is missing) */
  denyGitWrite: boolean;
  /** User alwaysDeny.bash, raw for the bash validator; NOT turned into glob rules */
  bashDeny: string[];
  /** Lexical and canonical agent dir; the bash validator scans inline scripts for them. */
  agentDirs: string[];
  sources: { user: PolicyFile<UserPolicy>; project: PolicyFile<ProjectPolicy> };
  warnings: string[];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

export function isPolicyActive(
  user: PolicyFile<UserPolicy>,
  project: PolicyFile<ProjectPolicy>,
): boolean {
  return user.status !== POLICY_FILE_STATUS.missing || project.status !== POLICY_FILE_STATUS.missing;
}

// Missing paths still need their existing ancestors resolved (e.g. /tmp -> /private/tmp).
export function canonicalPath(p: string): string {
  try {
    return realpathSync.native(p);
  } catch {
    const parent = path.dirname(p);
    if (parent === p) return path.resolve(p);
    return path.join(canonicalPath(parent), path.basename(p));
  }
}

// Canonicalizes only the literal prefix; the glob remainder is kept verbatim.
function canonicalizePattern(pattern: string, real: (p: string) => string): string {
  const segments = pattern.split(PATH_SEPARATOR);
  const globIndex = segments.findIndex((segment) => GLOB_CHARS.test(segment));
  const literalCount = globIndex === -1 ? segments.length : globIndex;
  const literal = segments.slice(0, literalCount).join(PATH_SEPARATOR) || PATH_SEPARATOR;
  const canonical = real(literal);
  if (globIndex === -1) return canonical;
  return path.join(canonical, segments.slice(globIndex).join(PATH_SEPARATOR));
}

function expandHome(entry: string, home: string): string {
  return entry.startsWith(HOME_PREFIX) ? path.join(home, entry.slice(HOME_PREFIX.length)) : entry;
}

export function isInside(root: string, target: string): boolean {
  const rel = path.relative(root, target);
  return (
    rel === "" ||
    (rel !== PARENT_DIR && !rel.startsWith(PARENT_DIR + path.sep) && !path.isAbsolute(rel))
  );
}

function denyRule(permission: string): PermissionRule {
  return { permission, pattern: WILDCARD, action: DENY };
}

// A `tools` whitelist without a `permission` block grants exactly the listed tools.
// Lowercased like the executor's whitelist filter.
function ownAgentRules(agent: AgentDefinition | undefined): PermissionRule[] {
  if (agent?.permission) return parsePermissionRules(agent.permission);
  return (agent?.tools ?? []).map((tool) => ({
    permission: toolToPermission(tool.toLowerCase()),
    pattern: WILDCARD,
    action: ALLOW,
  }));
}

// ─── Resolution ──────────────────────────────────────────────────────────────

export function resolvePolicy(options: ResolvePolicyOptions): EffectivePolicy | undefined {
  const { agent, cwd, agentDir, user, project } = options;
  if (!isPolicyActive(user, project)) return undefined;

  const real = options.realpath ?? canonicalPath;
  const home = real(options.home ?? homedir());
  const realCwd = real(cwd);
  const userPolicy = user.policy;
  const warnings: string[] = [];
  const hardRules: PermissionRule[] = [];

  for (const file of [user, project]) {
    if (file.status !== POLICY_FILE_STATUS.invalid) continue;
    warnings.push(`${file.path}: ${file.error}; bash, shell, powershell, edit and write are blocked until it is fixed`);
    for (const category of RISKY_CATEGORIES) hardRules.push(denyRule(category));
  }

  // M2 checks both path.resolve(cwd, arg) (lexical) and the realpath'd argument against these rules.
  // A nested symlink inside a protected dir targeted directly by its real path is not covered
  // (OS-level isolation territory).
  const roots = [cwd, ...(options.anchorRoots ?? [])];
  const lexicalHome = path.resolve(options.home ?? homedir());
  const anchoredPatterns = (patterns: readonly string[]): Set<string> => {
    const out = new Set<string>();
    for (const pattern of patterns) {
      const anchorTo = (root: string, homeRoot: string): string => {
        const expanded = expandHome(pattern, homeRoot);
        return path.isAbsolute(expanded) ? expanded : path.join(root, expanded);
      };
      for (const root of roots) {
        const anchored = anchorTo(real(root), home);
        out.add(anchorTo(path.resolve(root), lexicalHome));
        out.add(anchored);
        out.add(canonicalizePattern(anchored, real));
      }
    }
    return out;
  };
  const builtinPatterns = anchoredPatterns([
    ...BUILTIN_PROTECTED_PATHS,
    `${path.resolve(agentDir)}${ANY_DESCENDANT}`,
    `${real(agentDir)}${ANY_DESCENDANT}`,
  ]);
  const userPatterns = anchoredPatterns(userPolicy?.alwaysDeny.paths ?? []);
  const writePatterns = new Set<string>([...ANYWHERE_PROTECTED_PATHS, ...builtinPatterns, ...userPatterns]);
  for (const hardPattern of writePatterns) {
    for (const category of WRITE_CATEGORIES) {
      hardRules.push({ permission: category, pattern: hardPattern, action: DENY });
    }
  }
  // Built-in locations stay readable; only the user's own entries are read-protected,
  // including the directory itself so grep, find and ls cannot be rooted at it.
  const readPatterns = new Set<string>();
  for (const pattern of userPatterns) {
    readPatterns.add(pattern);
    if (pattern.endsWith(ANY_DESCENDANT)) readPatterns.add(pattern.slice(0, -ANY_DESCENDANT.length));
  }
  for (const hardPattern of readPatterns) {
    for (const category of READ_CATEGORIES) {
      hardRules.push({ permission: category, pattern: hardPattern, action: DENY });
    }
  }

  for (const tool of userPolicy?.alwaysDeny.tools ?? []) {
    hardRules.push(denyRule(toolToPermission(tool)));
  }

  const realTrustRoot = options.trustRoot === undefined ? realCwd : real(options.trustRoot);
  const trusted = (userPolicy?.trustedProjects ?? []).some((entry) =>
    isInside(real(expandHome(entry, home)), realTrustRoot),
  );

  const agents = project.policy?.agents ?? {};
  const agentName = agent?.name;
  let projectRules = [
    ...(Object.hasOwn(agents, ALL_AGENTS_KEY) ? parsePermissionRules(agents[ALL_AGENTS_KEY]) : []),
    ...(agentName !== undefined && Object.hasOwn(agents, agentName)
      ? parsePermissionRules(agents[agentName])
      : []),
  ];
  if (!trusted) {
    const kept = projectRules.filter((rule) => rule.action === DENY);
    const dropped = projectRules.length - kept.length;
    if (dropped > 0) {
      warnings.push(
        `project is not in trustedProjects; ignored ${dropped} non-deny (allow/ask) rule(s) from ${project.path}`,
      );
    }
    projectRules = kept;
  }

  const ownRules = ownAgentRules(agent);

  return {
    agentName,
    trusted,
    rules: [...ownRules, ...projectRules, ...hardRules],
    hardRules,
    denyGitWrite: userPolicy?.alwaysDeny.gitWrite ?? true,
    bashDeny: userPolicy?.alwaysDeny.bash ?? [],
    agentDirs: [...new Set([path.resolve(agentDir), real(agentDir)])],
    sources: { user, project },
    warnings,
  };
}
