/**
 * Guard for agent markdown `include:` directives.
 *
 * An include inlines a file into the agent's prompt when agents load, without
 * a tool call, so the policy gate never sees it. In strict mode this refuses
 * includes of read-protected paths and keeps a project agent's includes inside
 * its project.
 */

import path from "node:path";

import type { AgentDefinition } from "../types.ts";
import { matchPermissionKey } from "./evaluator.ts";
import { POLICY_FILE_STATUS } from "./loader.ts";
import { pathCandidates } from "./paths.ts";
import { matchesHard } from "./policy-gate.ts";
import type { PolicyRuntime } from "./policy-runtime.ts";
import { canonicalPath, isInside } from "./resolver.ts";

// An include is a read of the file by the agent that names it.
const READ_CATEGORY = "read";
const PROJECT_SOURCE: AgentDefinition["source"] = "project";

/** Returns why the include is refused, or undefined when the file may be read. */
export type IncludeGuard = (resolved: string, agent: AgentDefinition) => string | undefined;

function refusal(runtime: PolicyRuntime, cwd: string, resolved: string, agent: AgentDefinition): string | undefined {
  // Without a policy file upstream behavior applies unchanged.
  if (!runtime.isActive(cwd)) return undefined;

  const real = runtime.realpath ?? canonicalPath;
  // Canonical on both sides, so a symlink inside the project cannot point out of it.
  if (agent.source === PROJECT_SOURCE && !isInside(real(cwd), real(resolved))) {
    return "outside the project (a project agent may only include files inside it)";
  }

  const files = runtime.files(cwd);
  const invalid = [files.user, files.project].filter((file) => file.status === POLICY_FILE_STATUS.invalid);
  // The read-protected paths are unknown while a policy file cannot be validated.
  if (invalid.length > 0) return `invalid policy file ${invalid.map((file) => file.path).join(", ")}`;

  // `<root>/.pi/permissions.json` -> `<root>`: relative alwaysDeny.paths entries are anchored there too, as in the gate.
  const projectRoot = path.dirname(path.dirname(files.project.path));
  const policy = runtime.resolveFrom(files, agent, cwd, projectRoot);
  if (!policy) return undefined;
  // Hard denies only: the include is written by the agent file's author, so the agent's own tool rules do not apply to it.
  // Ceilings carry the parent's anchoring in a subagent child.
  const hardRules = [policy, ...runtime.ceilings()].flatMap((each) => each.hardRules);
  const candidates = pathCandidates(resolved, cwd, { home: runtime.home, realpath: runtime.realpath });
  const rule = hardRules.find(
    (hard) => matchPermissionKey(hard.permission, READ_CATEGORY) && candidates.some((candidate) => matchesHard(hard.pattern, candidate)),
  );
  return rule ? `read-protected by the permission policy ("${rule.pattern}")` : undefined;
}

export function createIncludeGuard(runtime: PolicyRuntime, cwd: string): IncludeGuard {
  return (resolved, agent) => {
    try {
      return refusal(runtime, cwd, resolved, agent);
    } catch (error) {
      // An unreadable parent snapshot throws: fail closed like the gate.
      return error instanceof Error ? error.message : String(error);
    }
  };
}
