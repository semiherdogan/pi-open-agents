/**
 * Per-run policy snapshot.
 *
 * Policy files are read once per agent run: edits apply from the next run, and
 * a running child never widens its permissions mid-run.
 */

import type { AgentDefinition } from "../types.ts";
import {
  loadProjectPolicy,
  loadUserPolicy,
  type PolicyFile,
  type ProjectPolicy,
  type UserPolicy,
} from "./loader.ts";
import { isPolicyActive, resolvePolicy, type EffectivePolicy } from "./resolver.ts";

export interface PolicyRuntimeOptions {
  agentDir: string;
  home?: string;
  realpath?: (p: string) => string;
}

interface Snapshot {
  cwd: string;
  user: PolicyFile<UserPolicy>;
  project: PolicyFile<ProjectPolicy>;
  signature: string;
}

export class PolicyRuntime {
  readonly agentDir: string;
  readonly home: string | undefined;
  readonly realpath: ((p: string) => string) | undefined;
  private snapshot: Snapshot | undefined;
  private readonly memo = new Map<string | undefined, EffectivePolicy | undefined>();
  private reportedSignature: string | undefined;
  private readonly reported = new Set<string>();

  constructor(options: PolicyRuntimeOptions) {
    this.agentDir = options.agentDir;
    this.home = options.home;
    this.realpath = options.realpath;
  }

  /**
   * Load a fresh snapshot. Returns warnings not yet reported for this file
   * content; `agent` (optional) adds that agent's resolution warnings.
   */
  beginRun(cwd: string, agent?: AgentDefinition): string[] {
    const { signature } = this.load(cwd);
    if (signature !== this.reportedSignature) {
      this.reportedSignature = signature;
      this.reported.clear();
    }

    const fresh: string[] = [];
    for (const warning of this.policyFor(agent, cwd)?.warnings ?? []) {
      if (this.reported.has(warning)) continue;
      this.reported.add(warning);
      fresh.push(warning);
    }
    return fresh;
  }

  policyFor(agent: AgentDefinition | undefined, cwd: string): EffectivePolicy | undefined {
    const snapshot = this.ensureSnapshot(cwd);
    const key = agent?.name;
    if (this.memo.has(key)) return this.memo.get(key);
    const policy = resolvePolicy({
      agent,
      cwd: snapshot.cwd,
      agentDir: this.agentDir,
      user: snapshot.user,
      project: snapshot.project,
      home: this.home,
      realpath: this.realpath,
    });
    this.memo.set(key, policy);
    return policy;
  }

  isActive(cwd: string): boolean {
    const snapshot = this.ensureSnapshot(cwd);
    return isPolicyActive(snapshot.user, snapshot.project);
  }

  // A lazy load must not consume warnings: only beginRun reports them.
  private ensureSnapshot(cwd: string): Snapshot {
    return this.snapshot?.cwd === cwd ? this.snapshot : this.load(cwd);
  }

  private load(cwd: string): Snapshot {
    const user = loadUserPolicy(this.agentDir);
    const project = loadProjectPolicy(cwd);
    const snapshot = { cwd, user, project, signature: JSON.stringify([cwd, user, project]) };
    this.snapshot = snapshot;
    this.memo.clear();
    return snapshot;
  }
}
