/**
 * Tests for permission policy loading (strict validation) and resolution
 * (precedence, trust, hard denies, fail-closed on invalid files).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { AgentDefinition } from "../src/types.ts";
import { evaluate } from "../src/permission/evaluator.ts";
import {
  POLICY_FILE_NAME,
  POLICY_FILE_STATUS,
  PROJECT_POLICY_DIR,
  loadProjectPolicy,
  loadUserPolicy,
  type PolicyFile,
  type ProjectPolicy,
  type UserPolicy,
} from "../src/permission/loader.ts";
import { decidePolicyCall } from "../src/permission/policy-gate.ts";
import { resolvePolicy } from "../src/permission/resolver.ts";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const baseAgent: AgentDefinition = {
  name: "worker",
  mode: "subagent",
  hidden: true,
  disable: false,
  thinking: "off",
  systemPrompt: "replace",
  maxDepth: 1,
  prompt: "You are a worker.",
  source: "project",
  filePath: "/tmp/worker.agent.md",
};

interface Sandbox {
  root: string;
  cwd: string;
  agentDir: string;
  home: string;
}

function withSandbox(fn: (box: Sandbox) => void): void {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-policy-")));
  try {
    const box = { root, cwd: join(root, "proj"), agentDir: join(root, "agent"), home: join(root, "home") };
    for (const dir of [box.cwd, box.agentDir, box.home]) mkdirSync(dir, { recursive: true });
    fn(box);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function writeUser(box: Sandbox, body: unknown): void {
  writeFileSync(join(box.agentDir, POLICY_FILE_NAME), typeof body === "string" ? body : JSON.stringify(body));
}

function writeProject(box: Sandbox, body: unknown): void {
  mkdirSync(join(box.cwd, PROJECT_POLICY_DIR), { recursive: true });
  writeFileSync(
    join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME),
    typeof body === "string" ? body : JSON.stringify(body),
  );
}

function userFile(policy: Partial<UserPolicy> = {}): PolicyFile<UserPolicy> {
  return {
    path: "/u/permissions.json",
    status: POLICY_FILE_STATUS.loaded,
    policy: {
      alwaysDeny: { gitWrite: true, paths: [], tools: [], bash: [], ...policy.alwaysDeny },
      trustedProjects: policy.trustedProjects ?? [],
    },
  };
}

const missingUser: PolicyFile<UserPolicy> = { path: "/u/permissions.json", status: POLICY_FILE_STATUS.missing };
const missingProject: PolicyFile<ProjectPolicy> = { path: "/p/permissions.json", status: POLICY_FILE_STATUS.missing };

function projectFile(agents: ProjectPolicy["agents"]): PolicyFile<ProjectPolicy> {
  return { path: "/p/.pi/permissions.json", status: POLICY_FILE_STATUS.loaded, policy: { agents } };
}

// ─── Loader ──────────────────────────────────────────────────────────────────

test("loader: both files missing", () => {
  withSandbox((box) => {
    assert.equal(loadUserPolicy(box.agentDir).status, POLICY_FILE_STATUS.missing);
    assert.equal(loadProjectPolicy(box.cwd).status, POLICY_FILE_STATUS.missing);
  });
});

test("loader: valid user file applies defaults", () => {
  withSandbox((box) => {
    writeUser(box, { version: 1 });
    const file = loadUserPolicy(box.agentDir);
    assert.equal(file.status, POLICY_FILE_STATUS.loaded);
    assert.deepEqual(file.policy, {
      alwaysDeny: { gitWrite: true, paths: [], tools: [], bash: [] },
      trustedProjects: [],
    });
  });
});

test("loader: valid user file trims lists and honors gitWrite false", () => {
  withSandbox((box) => {
    writeUser(box, {
      version: 1,
      alwaysDeny: { gitWrite: false, paths: [" ~/secrets/** "], bash: ["rm -rf *"] },
      trustedProjects: ["~/work", "/abs/path"],
    });
    const file = loadUserPolicy(box.agentDir);
    assert.equal(file.status, POLICY_FILE_STATUS.loaded);
    assert.equal(file.policy?.alwaysDeny.gitWrite, false);
    assert.deepEqual(file.policy?.alwaysDeny.paths, ["~/secrets/**"]);
  });
});

test("loader: invalid JSON", () => {
  withSandbox((box) => {
    writeUser(box, "{ nope");
    const file = loadUserPolicy(box.agentDir);
    assert.equal(file.status, POLICY_FILE_STATUS.invalid);
    assert.match(file.error ?? "", /invalid JSON/);
  });
});

test("loader: unknown keys are rejected and named", () => {
  withSandbox((box) => {
    writeUser(box, { version: 1, extra: true });
    const top = loadUserPolicy(box.agentDir);
    assert.equal(top.status, POLICY_FILE_STATUS.invalid);
    assert.match(top.error ?? "", /extra/);
    assert.match(top.error ?? "", /alwaysDeny/);

    writeUser(box, { version: 1, alwaysDeny: { gitwrite: false } });
    const nested = loadUserPolicy(box.agentDir);
    assert.equal(nested.status, POLICY_FILE_STATUS.invalid);
    assert.match(nested.error ?? "", /gitwrite/);
  });
});

test("loader: wrong or missing version is invalid", () => {
  withSandbox((box) => {
    writeUser(box, { version: 2 });
    assert.equal(loadUserPolicy(box.agentDir).status, POLICY_FILE_STATUS.invalid);
    writeProject(box, { agents: {} });
    assert.equal(loadProjectPolicy(box.cwd).status, POLICY_FILE_STATUS.invalid);
  });
});

test("loader: project agent action errors carry a context path", () => {
  withSandbox((box) => {
    const cases: Array<[unknown, RegExp]> = [
      [{ implementer: { bash: "maybe" } }, /agents\.implementer\.bash/],
      [{ implementer: { bash: { pytest: "maybe" } } }, /agents\.implementer\.bash\["pytest"\]/],
      [{ implementer: { edit: { "*.env": 5 } } }, /agents\.implementer\.edit\["\*\.env"\]/],
      [{ implementer: { bash: ["allow"] } }, /agents\.implementer\.bash/],
    ];
    for (const [agents, pattern] of cases) {
      writeProject(box, { version: 1, agents });
      const file = loadProjectPolicy(box.cwd);
      assert.equal(file.status, POLICY_FILE_STATUS.invalid);
      assert.match(file.error ?? "", pattern);
    }
  });
});

test("loader: valid project file", () => {
  withSandbox((box) => {
    writeProject(box, { version: 1, agents: { "*": { bash: "ask" }, worker: { edit: { "*.md": "allow" } } } });
    const file = loadProjectPolicy(box.cwd);
    assert.equal(file.status, POLICY_FILE_STATUS.loaded);
    assert.deepEqual(file.policy?.agents.worker, { edit: { "*.md": "allow" } });
  });
});

test("loader: relative trustedProjects entry is invalid", () => {
  withSandbox((box) => {
    writeUser(box, { version: 1, trustedProjects: ["relative/dir"] });
    const file = loadUserPolicy(box.agentDir);
    assert.equal(file.status, POLICY_FILE_STATUS.invalid);
    assert.match(file.error ?? "", /trustedProjects\[0\]/);
  });
});

// ─── Resolver ────────────────────────────────────────────────────────────────

test("resolver: no policy files returns undefined", () => {
  withSandbox((box) => {
    assert.equal(
      resolvePolicy({ agent: baseAgent, cwd: box.cwd, agentDir: box.agentDir, user: missingUser, project: missingProject }),
      undefined,
    );
  });
});

test("resolver: trusted project rules beat frontmatter; rule order is own, *, agent, hard", () => {
  withSandbox((box) => {
    const agent = { ...baseAgent, permission: { bash: { pytest: "deny" } } } as AgentDefinition;
    const policy = resolvePolicy({
      agent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: userFile({ trustedProjects: [box.cwd] }),
      project: projectFile({ "*": { bash: { "ls*": "ask" } }, worker: { bash: { pytest: "allow" } } }),
    });
    assert.ok(policy);
    assert.equal(policy.trusted, true);
    assert.equal(evaluate("bash", "pytest", policy.rules).action, "allow");
    assert.deepEqual(
      policy.rules.slice(0, 3).map((r) => [r.pattern, r.action]),
      [["pytest", "deny"], ["ls*", "ask"], ["pytest", "allow"]],
    );
    assert.deepEqual(policy.rules.slice(3), policy.hardRules);
  });
});

test("resolver: untrusted project drops allow rules and warns once", () => {
  withSandbox((box) => {
    const agent = { ...baseAgent, permission: { bash: { pytest: "deny" } } } as AgentDefinition;
    const policy = resolvePolicy({
      agent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: userFile(),
      project: projectFile({ worker: { bash: { pytest: "allow", "rm*": "deny" } } }),
    });
    assert.ok(policy);
    assert.equal(policy.trusted, false);
    assert.equal(evaluate("bash", "pytest", policy.rules).action, "deny");
    assert.equal(evaluate("bash", "rm x", policy.rules).action, "deny");
    assert.equal(policy.warnings.length, 1);
    assert.match(policy.warnings[0], /not in trustedProjects/);
    assert.match(policy.warnings[0], /1 non-deny/);
  });
});

test("resolver: trust covers subdirectories, rejects sibling prefixes, expands ~/", () => {
  withSandbox((box) => {
    const resolveTrust = (cwd: string, trusted: string[]) => {
      mkdirSync(cwd, { recursive: true });
      return resolvePolicy({
        agent: baseAgent,
        cwd,
        agentDir: box.agentDir,
        home: box.home,
        user: userFile({ trustedProjects: trusted }),
        project: missingProject,
      })?.trusted;
    };

    const trustedRoot = join(box.root, "a", "proj");
    assert.equal(resolveTrust(join(trustedRoot, "sub", "deep"), [trustedRoot]), true);
    assert.equal(resolveTrust(trustedRoot, [trustedRoot]), true);
    assert.equal(resolveTrust(join(box.root, "a", "project"), [trustedRoot]), false);
    assert.equal(resolveTrust(join(box.home, "work", "x"), ["~/work"]), true);
    assert.equal(resolveTrust(join(box.home, "other"), ["~/work"]), false);
  });
});

test("resolver: hard path denies beat project allow", () => {
  withSandbox((box) => {
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      home: box.home,
      user: userFile({
        trustedProjects: [box.cwd],
        alwaysDeny: { gitWrite: true, paths: ["~/secrets/**"], tools: [], bash: [] },
      }),
      project: projectFile({ worker: { edit: { "**": "allow" }, write: { "**": "allow" } } }),
    });
    assert.ok(policy);
    const denied = [
      join(box.cwd, ".git", "config"),
      join(box.cwd, ".pi", "permissions.json"),
      join(box.agentDir, "agents", "x.md"),
      join(box.home, "secrets", "key.txt"),
    ];
    for (const target of denied) {
      assert.equal(evaluate("edit", target, policy.rules).action, "deny", target);
      assert.equal(evaluate("write", target, policy.rules).action, "deny", target);
    }
    assert.equal(evaluate("edit", join(box.cwd, "src", "a.ts"), policy.rules).action, "allow");
  });
});

test("resolver: invalid project file fails closed, user denies still apply", () => {
  withSandbox((box) => {
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      home: box.home,
      user: userFile({ alwaysDeny: { gitWrite: true, paths: ["~/secrets/**"], tools: [], bash: [] } }),
      project: { path: "/p/.pi/permissions.json", status: POLICY_FILE_STATUS.invalid, error: "bad thing" },
    });
    assert.ok(policy);
    for (const category of ["bash", "edit", "write"]) {
      assert.ok(
        policy.hardRules.some((r) => r.permission === category && r.pattern === "*" && r.action === "deny"),
        category,
      );
    }
    assert.equal(policy.warnings.length, 1);
    assert.match(policy.warnings[0], /bad thing/);
    assert.equal(evaluate("edit", join(box.home, "secrets", "k"), policy.rules).action, "deny");
  });
});

test("resolver: invalid project file hard denies shell and powershell calls", () => {
  withSandbox((box) => {
    const policy = resolvePolicy({
      agent: { ...baseAgent, permission: { bash: "allow", shell: "allow", powershell: "allow" } },
      cwd: box.cwd,
      agentDir: box.agentDir,
      home: box.home,
      user: userFile({ alwaysDeny: { gitWrite: true, paths: [], tools: [], bash: [] } }),
      project: { path: "/p/.pi/permissions.json", status: POLICY_FILE_STATUS.invalid, error: "bad thing" },
    });
    assert.ok(policy);
    for (const toolName of ["bash", "shell", "powershell"]) {
      const decision = decidePolicyCall({ toolName, input: { command: "ls" }, policy, inherited: [], cwd: box.cwd, home: box.home });
      assert.equal(decision.action, "deny", toolName);
      assert.equal(decision.hard, true, toolName);
    }
  });
});

test("resolver: alwaysDeny.tools become hard denies via permission mapping", () => {
  withSandbox((box) => {
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: userFile({ alwaysDeny: { gitWrite: true, paths: [], tools: ["apply_patch", "webfetch"], bash: [] } }),
      project: missingProject,
    });
    assert.ok(policy);
    assert.equal(evaluate("edit", join(box.cwd, "a.ts"), policy.rules).action, "deny");
    assert.equal(evaluate("webfetch", "https://x.test", policy.rules).action, "deny");
    assert.equal(evaluate("read", "a.ts", policy.rules).action, "ask");
  });
});

test("resolver: without an agent only project * rules apply", () => {
  withSandbox((box) => {
    const policy = resolvePolicy({
      agent: undefined,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: userFile({ trustedProjects: [box.cwd] }),
      project: projectFile({ "*": { bash: { ls: "allow" } }, worker: { bash: { pwd: "allow" } } }),
    });
    assert.ok(policy);
    assert.equal(policy.agentName, undefined);
    assert.equal(evaluate("bash", "ls", policy.rules).action, "allow");
    assert.equal(evaluate("bash", "pwd", policy.rules).action, "ask");
  });
});

test("resolver: denyGitWrite defaults true without user file; bashDeny passes through raw", () => {
  withSandbox((box) => {
    const noUser = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: missingUser,
      project: projectFile({}),
    });
    assert.ok(noUser);
    assert.equal(noUser.denyGitWrite, true);
    assert.deepEqual(noUser.bashDeny, []);

    const withBash = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: userFile({ alwaysDeny: { gitWrite: false, paths: [], tools: [], bash: ["rm -rf *", "curl *"] } }),
      project: missingProject,
    });
    assert.ok(withBash);
    assert.equal(withBash.denyGitWrite, false);
    assert.deepEqual(withBash.bashDeny, ["rm -rf *", "curl *"]);
    assert.equal(withBash.rules.some((r) => r.permission === "bash"), false);
  });
});

// ─── Resolver: canonicalization and gaps ─────────────────────────────────────

const EDIT_AND_WRITE = ["edit", "write"] as const;

test("resolver: symlinked cwd keeps hard denies on the real path and trust works for both spellings", () => {
  withSandbox((box) => {
    const link = join(box.root, "proj-link");
    symlinkSync(box.cwd, link);
    for (const trusted of [link, box.cwd]) {
      const policy = resolvePolicy({
        agent: baseAgent,
        cwd: link,
        agentDir: box.agentDir,
        home: box.home,
        user: userFile({ trustedProjects: [trusted] }),
        project: projectFile({ worker: { edit: { "**": "allow" } } }),
      });
      assert.ok(policy);
      assert.equal(policy.trusted, true, trusted);
      for (const target of [join(box.cwd, ".pi", "x"), join(box.cwd, ".git", "config")]) {
        assert.equal(evaluate("edit", target, policy.rules).action, "deny", target);
      }
    }
  });
});

test("resolver: project .pi symlinked outside the project is denied on both spellings", () => {
  withSandbox((box) => {
    const outside = join(box.root, "outside");
    mkdirSync(outside);
    symlinkSync(outside, join(box.cwd, PROJECT_POLICY_DIR));
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      home: box.home,
      user: userFile({ trustedProjects: [box.cwd] }),
      project: projectFile({ worker: { edit: { "**": "allow" } } }),
    });
    assert.ok(policy);
    assert.equal(evaluate("edit", join(outside, POLICY_FILE_NAME), policy.rules).action, "deny");
    assert.equal(evaluate("edit", join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), policy.rules).action, "deny");
  });
});

test("resolver: absolute alwaysDeny path is canonicalized through symlinks; missing prefix stays usable", () => {
  withSandbox((box) => {
    const real = join(box.root, "real");
    mkdirSync(real);
    symlinkSync(real, join(box.root, "link"));
    const missing = join(box.root, "not-yet", "dir");
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      home: box.home,
      user: userFile({
        alwaysDeny: { gitWrite: true, paths: [join(box.root, "link", "secrets", "**"), `${missing}/**`], tools: [], bash: [] },
      }),
      project: missingProject,
    });
    assert.ok(policy);
    assert.equal(evaluate("edit", join(real, "secrets", "a"), policy.rules).action, "deny");
    assert.equal(evaluate("edit", join(box.root, "link", "secrets", "a"), policy.rules).action, "deny");
    assert.equal(evaluate("write", join(missing, "a"), policy.rules).action, "deny");
  });
});

test("resolver: relative alwaysDeny entry anchors to cwd", () => {
  withSandbox((box) => {
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      home: box.home,
      user: userFile({ alwaysDeny: { gitWrite: true, paths: ["config/prod/**"], tools: [], bash: [] } }),
      project: missingProject,
    });
    assert.ok(policy);
    assert.equal(evaluate("edit", join(box.cwd, "config", "prod", "x.yml"), policy.rules).action, "deny");
    assert.notEqual(evaluate("edit", join(box.cwd, "config", "dev", "x.yml"), policy.rules).action, "deny");
  });
});

test("resolver: built-in protected paths deny edit and write, including .git as a file", () => {
  withSandbox((box) => {
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      home: box.home,
      user: userFile({ trustedProjects: [box.cwd] }),
      project: projectFile({ worker: { edit: { "**": "allow" }, write: { "**": "allow" } } }),
    });
    assert.ok(policy);
    const targets = [
      join(box.cwd, ".opencode", "agents", "a.md"),
      join(box.cwd, ".agents", "a.md"),
      join(box.cwd, ".git"),
    ];
    for (const target of targets) {
      for (const category of EDIT_AND_WRITE) {
        assert.equal(evaluate(category, target, policy.rules).action, "deny", `${category} ${target}`);
      }
    }
  });
});

test("resolver: invalid user file blocks risky tools, distrusts the project and names its path", () => {
  withSandbox((box) => {
    const userPath = "/u/broken-permissions.json";
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      home: box.home,
      user: { path: userPath, status: POLICY_FILE_STATUS.invalid, error: "bad user" },
      project: projectFile({ worker: { bash: { "*": "allow" } } }),
    });
    assert.ok(policy);
    assert.equal(policy.trusted, false);
    for (const category of ["bash", "edit", "write"]) {
      assert.ok(
        policy.hardRules.some((r) => r.permission === category && r.pattern === "*" && r.action === "deny"),
        category,
      );
    }
    assert.equal(evaluate("bash", "ls", policy.rules).action, "deny");
    assert.ok(policy.warnings.some((w) => w.includes(userPath) && w.includes("bad user")));
    assert.ok(policy.warnings.some((w) => /not in trustedProjects/.test(w)));
  });
});

test("loader: unreadable (non-ENOENT) project file is invalid", () => {
  withSandbox((box) => {
    mkdirSync(join(box.cwd, PROJECT_POLICY_DIR, POLICY_FILE_NAME), { recursive: true });
    assert.equal(loadProjectPolicy(box.cwd).status, POLICY_FILE_STATUS.invalid);
  });
});

test("resolver: untrusted project drops ask rules", () => {
  withSandbox((box) => {
    const agent = { ...baseAgent, permission: { bash: { pytest: "allow" } } } as AgentDefinition;
    const policy = resolvePolicy({
      agent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: userFile(),
      project: projectFile({ worker: { bash: { pytest: "ask", "rm*": "allow" } } }),
    });
    assert.ok(policy);
    assert.equal(policy.trusted, false);
    assert.equal(evaluate("bash", "pytest", policy.rules).action, "allow");
    assert.equal(policy.rules.some((r) => r.action === "ask"), false);
    assert.equal(policy.rules.some((r) => r.pattern === "rm*"), false);
    assert.match(policy.warnings[0], /2 non-deny/);
  });
});

test("resolver: untrusted ask cannot soften a frontmatter deny", () => {
  withSandbox((box) => {
    const agent = { ...baseAgent, permission: { bash: { rm: "deny" } } } as AgentDefinition;
    const policy = resolvePolicy({
      agent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: userFile(),
      project: projectFile({ worker: { bash: { rm: "ask" } } }),
    });
    assert.ok(policy);
    assert.equal(evaluate("bash", "rm", policy.rules).action, "deny");
  });
});

test("resolver: symlinked cwd cannot bypass .pi/agents deny via lexical spelling", () => {
  withSandbox((box) => {
    const real = join(box.root, "real");
    const link = join(box.root, "link");
    const shared = join(box.root, "shared");
    mkdirSync(join(real, PROJECT_POLICY_DIR), { recursive: true });
    mkdirSync(shared, { recursive: true });
    symlinkSync(shared, join(real, PROJECT_POLICY_DIR, "agents"));
    symlinkSync(real, link);
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: link,
      agentDir: box.agentDir,
      user: userFile({ trustedProjects: [real] }),
      project: projectFile({ worker: { edit: { "**": "allow" } } }),
    });
    assert.ok(policy);
    assert.equal(policy.trusted, true);
    assert.equal(evaluate("edit", join(link, PROJECT_POLICY_DIR, "agents", "x.md"), policy.rules).action, "deny");
    assert.equal(evaluate("edit", join(shared, "x.md"), policy.rules).action, "allow");
  });
});

test("resolver: agentDir given via symlink is protected under its link spelling", () => {
  withSandbox((box) => {
    const link = join(box.root, "agent-link");
    symlinkSync(box.agentDir, link);
    const policy = resolvePolicy({
      agent: baseAgent,
      cwd: box.cwd,
      agentDir: link,
      user: userFile({ trustedProjects: [box.cwd] }),
      project: projectFile({ worker: { edit: { "**": "allow" } } }),
    });
    assert.ok(policy);
    assert.equal(evaluate("edit", join(link, "x.md"), policy.rules).action, "deny");
    assert.equal(evaluate("edit", join(box.agentDir, "x.md"), policy.rules).action, "deny");
  });
});

test("resolver: alwaysDeny.tools beats frontmatter allow and trusted project allow", () => {
  withSandbox((box) => {
    const agent = { ...baseAgent, permission: { webfetch: "allow" } } as AgentDefinition;
    const policy = resolvePolicy({
      agent,
      cwd: box.cwd,
      agentDir: box.agentDir,
      user: userFile({ trustedProjects: [box.cwd], alwaysDeny: { gitWrite: true, paths: [], tools: ["webfetch"], bash: [] } }),
      project: projectFile({ worker: { webfetch: "allow" } }),
    });
    assert.ok(policy);
    assert.equal(policy.trusted, true);
    assert.equal(evaluate("webfetch", "https://x.test", policy.rules).action, "deny");
  });
});
