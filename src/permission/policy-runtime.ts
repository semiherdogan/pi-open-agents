/**
 * Per-run policy snapshot.
 *
 * Policy files are read once per agent run: edits apply from the next run, and
 * a running child never widens its permissions mid-run.
 */

import { existsSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

import type { AgentDefinition, PermissionRule } from "../types.ts";
import {
  loadProjectPolicy,
  loadUserPolicy,
  POLICY_FILE_STATUS,
  projectPolicyPath,
  type PolicyFile,
  type ProjectPolicy,
  type UserPolicy,
} from "./loader.ts";
import { canonicalPath, isInside, isPolicyActive, resolvePolicy, type EffectivePolicy } from "./resolver.ts";
import {
  hydratePolicy,
  SNAPSHOT_STATUS,
  type PolicySnapshot,
  type PolicySnapshotFiles,
  type ReceivedSnapshot,
  type SerializedPolicy,
} from "./policy-snapshot.ts";

export interface PolicyRuntimeOptions {
  agentDir: string;
  home?: string;
  realpath?: (p: string) => string;
  /** Snapshot received from the delegating parent; when set, its own policy files are never read (see childProject). */
  received?: ReceivedSnapshot;
  /** Legacy parent rules (PI_OPEN_AGENTS_PARENT_RULES) of a process without a snapshot. */
  inherited?: PermissionRule[];
}

/** What this process hands down: its own policy, the ceilings above it and the files they came from. */
export interface DelegationState {
  self: EffectivePolicy;
  ceilings: SerializedPolicy[];
  inherited: PermissionRule[];
  files: PolicySnapshotFiles;
}

/** Policy files a child is resolved from and the project root they belong to. */
export interface ChildProject {
  files: PolicySnapshotFiles;
  root: string;
}

// A received snapshot never changes during the process.
const RECEIVED_SIGNATURE = "received";

// `<root>/.pi/permissions.json` -> `<root>`
function projectRootOf(file: PolicyFile<ProjectPolicy>): string {
  return path.dirname(path.dirname(file.path));
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
  // Last successfully loaded version per policy path: deleting a policy file must not lift its denies mid-session.
  private readonly lastLoaded = new Map<string, PolicyFile<unknown>>();
  private readonly retained = new Set<string>();
  private readonly retainedReported = new Set<string>();
  private readonly received: ReceivedSnapshot | undefined;
  private receivedSelf: EffectivePolicy | undefined;
  private receivedCeilings: EffectivePolicy[] = [];
  private receivedReported = false;
  private readonly inheritedRules: PermissionRule[];

  constructor(options: PolicyRuntimeOptions) {
    this.agentDir = options.agentDir;
    this.home = options.home;
    this.realpath = options.realpath;
    this.received = options.received;
    this.inheritedRules = options.inherited ?? [];
    if (this.received?.status === SNAPSHOT_STATUS.valid) {
      const { self, ceilings, files } = this.received.snapshot;
      this.receivedSelf = hydratePolicy(self, files);
      this.receivedCeilings = ceilings.map((ceiling) => hydratePolicy(ceiling, files));
    }
  }

  /** True when decisions come from a parent's snapshot (legacy inherited rules no longer apply). */
  get fromSnapshot(): boolean {
    return this.received !== undefined;
  }

  /** Identity of the policy inputs: changes only when a received snapshot or a loaded file's content changes. */
  get signature(): string | undefined {
    if (this.received !== undefined) return RECEIVED_SIGNATURE;
    return this.snapshot?.signature;
  }

  /** Policies above this process; every call must also pass each of them. */
  ceilings(): EffectivePolicy[] {
    this.receivedSnapshot();
    return this.receivedCeilings;
  }

  delegationState(agent: AgentDefinition | undefined, cwd: string): DelegationState | undefined {
    const received = this.receivedSnapshot();
    if (received) {
      return { self: this.receivedSelf!, ceilings: received.ceilings, inherited: received.inherited, files: received.files };
    }
    const self = this.policyFor(agent, cwd);
    if (!self) return undefined;
    const { user, project } = this.ensureSnapshot(cwd);
    return { self, ceilings: [], inherited: this.inheritedRules, files: { user, project } };
  }

  /** Policy files decisions come from: the parent's snapshot files, else this run's loaded files. */
  files(cwd: string): PolicySnapshotFiles {
    const received = this.receivedSnapshot();
    if (received) return received.files;
    const { user, project } = this.ensureSnapshot(cwd);
    return { user, project };
  }

  /** Legacy ancestor rules this process must keep applying after its own rules. */
  inherited(): PermissionRule[] {
    return this.receivedSnapshot()?.inherited ?? this.inheritedRules;
  }

  /**
   * Project of a child in absolute `childDir`, delegated from a process in `cwd`.
   * At or below `cwd` it is the parent's project: `files` is reused, never re-read,
   * so an edit during the run cannot widen the child. Elsewhere it is the nearest
   * ancestor of `childDir` with a project file, read now even in a process with a
   * snapshot (as a primary would); the user file always comes from `files`.
   */
  childProject(files: PolicySnapshotFiles, cwd: string, childDir: string): ChildProject {
    const real = this.realpath ?? canonicalPath;
    if (isInside(path.resolve(cwd), childDir) || isInside(real(cwd), real(childDir))) {
      return { files, root: projectRootOf(files.project) };
    }
    const root = this.nearestProjectRoot(childDir) ?? childDir;
    if (files.project.path === projectPolicyPath(root)) return { files, root };
    return { files: { user: files.user, project: loadProjectPolicy(root) }, root };
  }

  // Stops below the home dir and the filesystem root: neither is a project.
  private nearestProjectRoot(dir: string): string | undefined {
    const home = path.resolve(this.home ?? homedir());
    for (let current = dir; current !== home && current !== path.dirname(current); current = path.dirname(current)) {
      if (existsSync(projectPolicyPath(current))) return current;
    }
    return undefined;
  }

  /**
   * Another agent's policy for `cwd` in `projectRoot`, resolved from `files` without
   * reloading them. Trust is the project root's; protected paths cover both dirs.
   */
  resolveFrom(files: PolicySnapshotFiles, agent: AgentDefinition, cwd: string, projectRoot: string = cwd): EffectivePolicy | undefined {
    return resolvePolicy({
      agent,
      cwd,
      agentDir: this.agentDir,
      user: files.user,
      project: files.project,
      home: this.home,
      realpath: this.realpath,
      trustRoot: projectRoot,
      anchorRoots: [projectRoot],
    });
  }

  // Throws for an invalid snapshot so every caller fails closed.
  private receivedSnapshot(): PolicySnapshot | undefined {
    if (this.received === undefined) return undefined;
    if (this.received.status === SNAPSHOT_STATUS.invalid) throw new Error(this.received.reason);
    return this.received.snapshot;
  }

  /**
   * Load a fresh snapshot. Returns warnings not yet reported for this file
   * content; `agent` (optional) adds that agent's resolution warnings.
   */
  beginRun(cwd: string, agent?: AgentDefinition): string[] {
    if (this.received !== undefined) {
      if (this.received.status === SNAPSHOT_STATUS.valid || this.receivedReported) return [];
      this.receivedReported = true;
      return [this.received.reason];
    }
    const { signature } = this.load(cwd);
    if (signature !== this.reportedSignature) {
      this.reportedSignature = signature;
      this.reported.clear();
    }

    const fresh: string[] = [];
    for (const filePath of this.retained) {
      if (this.retainedReported.has(filePath)) continue;
      this.retainedReported.add(filePath);
      fresh.push(`${filePath} disappeared; keeping the last loaded policy until pi restarts`);
    }
    for (const warning of this.policyFor(agent, cwd)?.warnings ?? []) {
      if (this.reported.has(warning)) continue;
      this.reported.add(warning);
      fresh.push(warning);
    }
    return fresh;
  }

  policyFor(agent: AgentDefinition | undefined, cwd: string): EffectivePolicy | undefined {
    if (this.receivedSnapshot()) return this.receivedSelf;
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
    if (this.received !== undefined) return true;
    const snapshot = this.ensureSnapshot(cwd);
    return isPolicyActive(snapshot.user, snapshot.project);
  }

  // A lazy load must not consume warnings: only beginRun reports them.
  private ensureSnapshot(cwd: string): Snapshot {
    return this.snapshot?.cwd === cwd ? this.snapshot : this.load(cwd);
  }

  private load(cwd: string): Snapshot {
    const user = this.retain(loadUserPolicy(this.agentDir));
    const project = this.retain(loadProjectPolicy(cwd));
    const snapshot = { cwd, user, project, signature: JSON.stringify([cwd, user, project]) };
    this.snapshot = snapshot;
    this.memo.clear();
    return snapshot;
  }

  private retain<T>(file: PolicyFile<T>): PolicyFile<T> {
    if (file.status !== POLICY_FILE_STATUS.missing) {
      this.retained.delete(file.path);
      this.retainedReported.delete(file.path);
      if (file.status === POLICY_FILE_STATUS.loaded) this.lastLoaded.set(file.path, file);
      return file;
    }
    const last = this.lastLoaded.get(file.path) as PolicyFile<T> | undefined;
    if (last === undefined) return file;
    this.retained.add(file.path);
    return last;
  }
}
