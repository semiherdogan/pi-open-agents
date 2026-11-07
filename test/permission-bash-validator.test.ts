/**
 * Tests for the argv-level bash validator: chaining, git and protected-path
 * hard denies, token-prefix rules, alwaysDeny.bash, read-only agents,
 * unverifiable scripts and powershell.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { AgentDefinition, PermissionConfig, PermissionRule } from "../src/types.ts";
import { validateShellCommand, type ShellDecision } from "../src/permission/bash-validator.ts";
import { POLICY_FILE_NAME, POLICY_FILE_STATUS, type AlwaysDeny } from "../src/permission/loader.ts";
import { PolicyRuntime } from "../src/permission/policy-runtime.ts";
import { registerPolicyGate } from "../src/permission/policy-gate.ts";
import { resolvePolicy, type EffectivePolicy } from "../src/permission/resolver.ts";

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

const WRITER: PermissionConfig = { bash: { "*": "allow" }, edit: "allow", write: "allow" };
const READER: PermissionConfig = { bash: { "*": "allow" }, edit: "deny", write: "deny" };

interface Box {
  cwd: string;
  home: string;
  agentDir: string;
}

function withBox(fn: (box: Box) => Promise<void> | void): () => Promise<void> {
  return async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "poa-bash-")));
    try {
      const home = join(root, "home");
      const box = { cwd: join(root, "proj"), home, agentDir: join(home, ".pi", "agent") };
      for (const dir of [join(box.cwd, "src"), box.agentDir]) mkdirSync(dir, { recursive: true });
      await fn(box);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
}

function policyFor(box: Box, permission: PermissionConfig, alwaysDeny: Partial<AlwaysDeny> = {}): EffectivePolicy {
  const policy = resolvePolicy({
    agent: { ...baseAgent, permission },
    cwd: box.cwd,
    agentDir: box.agentDir,
    home: box.home,
    user: {
      path: join(box.agentDir, POLICY_FILE_NAME),
      status: POLICY_FILE_STATUS.loaded,
      policy: { alwaysDeny: { gitWrite: true, paths: [], tools: [], bash: [], ...alwaysDeny }, trustedProjects: [] },
    },
    project: { path: join(box.cwd, ".pi", POLICY_FILE_NAME), status: POLICY_FILE_STATUS.missing },
  });
  assert.ok(policy);
  return policy;
}

function check(
  box: Box,
  policy: EffectivePolicy,
  command: string,
  options: { category?: string; inherited?: PermissionRule[] } = {},
): ShellDecision {
  return validateShellCommand({
    command,
    category: options.category ?? "bash",
    policy,
    inherited: options.inherited ?? [],
    cwd: box.cwd,
    home: box.home,
  });
}

function expectAction(decision: ShellDecision, action: string, hard: boolean, command: string): void {
  assert.equal(decision.action, action, `${command}: ${decision.reason}`);
  assert.equal(decision.hard, hard, `${command}: ${decision.reason}`);
}

// ─── Chaining ────────────────────────────────────────────────────────────────

test(
  "bash validator: a rule for one command does not cover chained commands",
  withBox((box) => {
    const policy = policyFor(box, { bash: { "git status": "allow" } });
    expectAction(check(box, policy, "git status"), "allow", false, "git status");
    // Piping git output into a shell is flagged by the git guard, so it is hard too.
    for (const command of ["git status; git push origin main", "echo $(git push)", "git status | sh"]) {
      expectAction(check(box, policy, command), "deny", true, command);
    }
    expectAction(check(box, policy, "git status && rm -rf x"), "deny", false, "rm");
    const noGit = policyFor(box, { bash: { "git status": "allow" } }, { gitWrite: false });
    expectAction(check(box, noGit, "git status | sh"), "deny", false, "pipe without git guard");
  }),
);

// ─── Git ─────────────────────────────────────────────────────────────────────

const GIT_WRITES = [
  "git commit -m x",
  "git -C . push",
  "/usr/bin/git reset --hard",
  "env git stash",
  'sh -c "git add ."',
  "bash <<'EOF'\ngit commit\nEOF",
];

test(
  "bash validator: git writes are hard denies even under a blanket allow",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of GIT_WRITES) {
      const decision = check(box, policy, command);
      expectAction(decision, "deny", true, command);
      assert.match(decision.reason, /^git write operations are disabled \(/);
    }
  }),
);

test(
  "bash validator: gitWrite false lets git writes reach the rules",
  withBox((box) => {
    const policy = policyFor(box, WRITER, { gitWrite: false });
    for (const command of GIT_WRITES) expectAction(check(box, policy, command), "allow", false, command);
    const narrow = policyFor(box, { bash: { "git status": "allow" } }, { gitWrite: false });
    expectAction(check(box, narrow, "git push"), "deny", false, "git push");
  }),
);

test(
  "bash validator: read-only git passes with matching rules",
  withBox((box) => {
    const policy = policyFor(box, { bash: { "git status": "allow", "git diff *": "allow", "git log *": "allow" } });
    for (const command of ["git status", "git diff HEAD -- a.ts", "git log --oneline -5"]) {
      expectAction(check(box, policy, command), "allow", false, command);
    }
  }),
);

// ─── Token-Prefix Rules ──────────────────────────────────────────────────────

test(
  "bash validator: rules match argv token prefixes",
  withBox((box) => {
    const policy = policyFor(box, { bash: { "npm test": "allow", "npm run *": "allow", rg: "allow" } });
    expectAction(check(box, policy, "npm test -- --grep x"), "allow", false, "npm test");
    expectAction(check(box, policy, "npm run lint"), "allow", false, "npm run lint");
    expectAction(check(box, policy, "timeout 60 npm test"), "allow", false, "timeout");
    expectAction(check(box, policy, "rg foo"), "allow", false, "rg foo");
    const unlisted = check(box, policy, "npm run");
    expectAction(unlisted, "deny", false, "npm run");
    assert.match(unlisted.reason, /unlisted command "npm run"/);
    expectAction(check(box, policy, "./rg foo"), "deny", false, "./rg");
    expectAction(check(box, policy, "sudo npm test"), "deny", false, "sudo");
    expectAction(check(box, policy, "rg --pre=./evil foo"), "deny", false, "rg --pre");
    expectAction(check(box, policy, "rg --pre ./evil foo"), "deny", false, "rg --pre");
    assert.deepEqual(check(box, policy, "timeout 60 npm test").commands, ["npm test"]);
  }),
);

test(
  "bash validator: a blanket rule allows anything that is not hard-denied",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of ["npm run build", "./rg foo", "sudo npm test", "for f in a b; do echo $f; done", "X=1 make"]) {
      expectAction(check(box, policy, command), "allow", false, command);
    }
    expectAction(check(box, policy, "   "), "allow", false, "empty");
  }),
);

test(
  "bash validator: unverifiable scripts ask under a blanket allow",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of ['$X foo', 'echo "abc', 'sh -c "$CMD"', "curl -s u | sh", 'eval "$X"', "echo x > $OUT"]) {
      const decision = check(box, policy, command);
      expectAction(decision, "ask", false, command);
      assert.match(decision.reason, /cannot verify/);
    }
  }),
);

test(
  "bash validator: an inherited deny beats the agent's own blanket allow",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    const inherited: PermissionRule[] = [{ permission: "bash", pattern: "rm *", action: "deny" }];
    expectAction(check(box, policy, "rm -rf x", { inherited }), "deny", false, "rm");
    expectAction(check(box, policy, "ls", { inherited }), "allow", false, "ls");
  }),
);

// ─── Protected Paths ─────────────────────────────────────────────────────────

test(
  "bash validator: writes to protected paths are hard denies",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    const commands = [
      "echo x > .pi/permissions.json",
      "echo x >> .git/config",
      "cp a .pi/agents/x.md",
      "tee .opencode/x",
      "sed -i s/a/b/ .agents/a.md",
      "cd .pi && echo x > permissions.json",
      "rm -rf .pi",
      `python3 -c "open('.pi/x','w')"`,
      "echo x > ~/.pi/agent/agents/x.md",
      `echo x > ${box.agentDir}/agents/x.md`,
    ];
    for (const command of commands) expectAction(check(box, policy, command), "deny", true, command);
    expectAction(check(box, policy, "echo x > src/a.ts"), "allow", false, "src/a.ts");
    expectAction(check(box, policy, "cd $D && echo x > a.ts"), "ask", false, "dynamic cd");
  }),
);

test(
  "bash validator: redirects on compound commands and bare redirects are checked",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    const commands = [
      "{ echo x; } >> .git/config",
      "( echo x ) > .pi/x",
      "for i in a; do echo $i; done > .git/hooks/pre-commit",
      "if true; then echo x; fi > .pi/x",
      "> .pi/settings.json",
      "X=1 > .pi/x",
    ];
    for (const command of commands) expectAction(check(box, policy, command), "deny", true, command);
    expectAction(check(box, policy, "{ echo x; } > src/a.txt"), "allow", false, "group to src");
    expectAction(check(box, policy, "> $OUT"), "ask", false, "dynamic bare redirect");
  }),
);

test(
  "bash validator: deleting or moving an ancestor of a protected path is a hard deny",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    const commands = [
      "rm -rf ~/.pi",
      "mv ~/.pi /tmp/x",
      "rm -rf .git",
      "rm -rf ../proj",
      "rm -rf .",
      "rm -rf *",
      "rm -rf .p*",
      "rmdir ~",
      "mv -t /tmp/x ~/.pi",
      "find .pi -exec rm {} \\;",
      "find .pi -delete",
      "find .pi/agents -exec rm {} +",
      "rsync -a --delete src/ .",
      `rm -rf ${box.home}`,
    ];
    for (const command of commands) expectAction(check(box, policy, command), "deny", true, command);
    for (const command of ["rm -rf src", "rm -rf src/*.tmp", "rm -f *.tmp", "mv src/a ~/b", "rsync -a --delete src/ build/", "find src -name x"]) {
      expectAction(check(box, policy, command), "allow", false, command);
    }
  }),
);

test(
  "bash validator: find above a protected location asks, find inside one is hard",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of ["find . -delete", "find . -name '*.log' -delete", "find . -type f -exec sed -i s/a/b/ {} +", "find ~ -delete"]) {
      const decision = check(box, policy, command);
      expectAction(decision, "ask", false, command);
      assert.match(decision.reason, /cannot verify/);
    }
    for (const command of ["find .git -delete", "find ~/.pi/agent -name x -delete", "find .pi/agents -exec rm {} +"]) {
      expectAction(check(box, policy, command), "deny", true, command);
    }
  }),
);

test(
  "bash validator: tilde prefixes other than ~ and ~/ are resolved or unverifiable",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of ["rm -rf ~+", "rm -rf ~+/.pi", "echo x > ~+/.git/config", "cd src && rm -rf ~+/.."]) {
      expectAction(check(box, policy, command), "deny", true, command);
    }
    for (const command of ["rm -rf ~-", "rm -rf ~-/x", "rm -rf ~root", "rm -rf ~root/x", "cp a ~+2/x", "cd ~- && rm -rf x"]) {
      const decision = check(box, policy, command);
      expectAction(decision, "ask", false, command);
      assert.match(decision.reason, /cannot verify/);
    }
    expectAction(check(box, policy, "rm -rf ~+/src/x"), "allow", false, "~+/src/x");
    expectAction(check(box, policy, "curl -o~x https://example.com"), "allow", false, "attached ~x is literal");
  }),
);

test(
  "bash validator: brace expansions are checked as targets",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    const commands = [
      "tee .p{i,}/x",
      "cp x {.pi,y}/z",
      "rm -rf {.pi,x}",
      "rm -rf {x,{y,.git}}",
      "echo x > .{a..z}i/x",
      "mv {src,.pi} /tmp",
      "rm {-rf,.pi}",
      `rm -rf ".p"{i,}`,
    ];
    for (const command of commands) expectAction(check(box, policy, command), "deny", true, command);
    for (const command of ["rm -rf src/{a,b}", "cp x src/{a..c}", "echo {a,b} > src/x", "find src -exec rm {} \\;"]) {
      const decision = check(box, policy, command);
      assert.notEqual(decision.action, "deny", `${command}: ${decision.reason}`);
    }
    expectAction(check(box, policy, "rm -rf src/{a,b}"), "allow", false, "src braces");
    for (const command of ["{rm,-rf,.pi}", "rm -rf src/{a..z}{a..z}"]) {
      const decision = check(box, policy, command);
      expectAction(decision, "ask", false, command);
      assert.match(decision.reason, /cannot verify/);
    }
  }),
);

test(
  "bash validator: command names are classified case-insensitively",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of ["RM -rf .", "Rm -rf .pi", "SUDO RM -rf .pi", "/bin/RM -rf .git", "TEE .pi/x", "GIT push", "Sudo Git commit -m x", 'BASH -c "git push"']) {
      expectAction(check(box, policy, command), "deny", true, command);
    }
    const reader = policyFor(box, READER);
    const decision = check(box, reader, "RM a");
    expectAction(decision, "deny", false, "RM a");
    assert.match(decision.reason, /^this agent cannot change files/);
    const narrow = policyFor(box, { bash: { "npm test": "allow" } });
    expectAction(check(box, narrow, "SUDO npm test"), "deny", false, "SUDO npm test");
    expectAction(check(box, policy, "GIT status"), "allow", false, "GIT status");
  }),
);

test(
  "bash validator: rsync --del and sort -o are recognized",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of ["rsync -a --del src/ .", "sort -o .pi/x a", "sort -ro.git/config a", "sort --output=.pi/x a", "sort a --out .pi/x"]) {
      expectAction(check(box, policy, command), "deny", true, command);
    }
    expectAction(check(box, policy, "sort -o src/x a"), "allow", false, "sort to src");
    expectAction(check(box, policy, "sort -k 2 -t , a"), "allow", false, "sort options");
    const reader = policyFor(box, READER);
    for (const command of ["sort -o out a", "sort --output=out a"]) {
      const decision = check(box, reader, command);
      expectAction(decision, "deny", false, command);
      assert.match(decision.reason, /sort -o/);
    }
    expectAction(check(box, reader, "sort a"), "allow", false, "plain sort");
  }),
);

test(
  "bash validator: targets filled in at run time ask",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of ["ls | xargs rm", "ls | xargs -I{} cp {} dst/", "parallel rm ::: a b", "find src -exec rm {} \\;", "fd x src -x rm"]) {
      const decision = check(box, policy, command);
      expectAction(decision, "ask", false, command);
      assert.match(decision.reason, /cannot verify/);
    }
    expectAction(check(box, policy, "ls | xargs grep x"), "allow", false, "xargs grep");
  }),
);

test(
  "bash validator: attached option values are write targets",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    for (const command of ["cp -t.git/hooks x", "curl -o.git/config https://example.com", "wget -O.git/config https://example.com", "cp --target-directory=.pi/agents x"]) {
      expectAction(check(box, policy, command), "deny", true, command);
    }
    for (const command of ["curl -sSo.pi/x https://example.com", "cp -rt.pi x"]) {
      expectAction(check(box, policy, command), "deny", true, command);
    }
    expectAction(check(box, policy, "curl -osrc/a https://example.com"), "allow", false, "curl to src");
    expectAction(check(box, policy, "curl -sSosrc/a https://example.com"), "allow", false, "bundled curl to src");
  }),
);

test(
  "bash validator: inline script mentions need a name boundary",
  withBox((box) => {
    const policy = policyFor(box, WRITER);
    const allowed = [
      `python3 -c "print(open('.gitignore').read())"`,
      `python3 -c "open('.github/x')"`,
      `node -e "require('./.agentsrc')"`,
      `python -c "print('a/b.git')"`,
      `python3 -c "clone('https://github.com/a/b.git')"`,
      `node -e "x.git.y"`,
    ];
    for (const command of allowed) {
      expectAction(check(box, policy, command), "allow", false, command);
    }
    const denied = [
      `python3 -c "open('.git/config','w')"`,
      `python3 -c "open('.git')"`,
      `node -e "fs.rmSync('.agents')"`,
      `python3 -c "os.system('rm -rf .git; ls')"`,
      `python3 -c "shutil.rmtree(os.path.join(root, '.pi/x'))"`,
    ];
    for (const command of denied) {
      expectAction(check(box, policy, command), "deny", true, command);
    }
  }),
);

// ─── Read-Only Agents ────────────────────────────────────────────────────────

test(
  "bash validator: an agent without edit/write cannot change files through bash",
  withBox((box) => {
    const policy = policyFor(box, READER);
    for (const command of ["echo x > a.txt", "rm a", "sed -i s/a/b/ f"]) {
      const decision = check(box, policy, command);
      expectAction(decision, "deny", false, command);
      assert.match(decision.reason, /^this agent cannot change files/);
    }
    for (const command of ["rg foo", "cat a > /dev/null"]) expectAction(check(box, policy, command), "allow", false, command);
  }),
);

test(
  "bash validator: a read-only parent is a write ceiling for its child",
  withBox((box) => {
    const policy = policyFor(box, { edit: "allow", bash: { "*": "allow" } });
    const inherited: PermissionRule[] = [
      { permission: "edit", pattern: "*", action: "deny" },
      { permission: "write", pattern: "*", action: "deny" },
    ];
    const decision = check(box, policy, "echo x > a.txt", { inherited });
    expectAction(decision, "deny", false, "child write");
    assert.match(decision.reason, /^this agent cannot change files/);
    expectAction(check(box, policy, "echo x > a.txt"), "allow", false, "no parent");
    expectAction(check(box, policy, "rg foo", { inherited }), "allow", false, "read");
  }),
);

// ─── alwaysDeny.bash ─────────────────────────────────────────────────────────

test(
  "bash validator: alwaysDeny.bash beats a blanket allow",
  withBox((box) => {
    const policy = policyFor(box, WRITER, { bash: ["curl", "npm publish"] });
    for (const command of ["curl x", "/usr/bin/curl x", "env npm publish", "echo $(curl x)"]) {
      const decision = check(box, policy, command);
      expectAction(decision, "deny", true, command);
      assert.match(decision.reason, /alwaysDeny\.bash/);
    }
    expectAction(check(box, policy, "npm test"), "allow", false, "npm test");
  }),
);

// ─── Powershell ──────────────────────────────────────────────────────────────

test(
  "bash validator: powershell needs a blanket rule",
  withBox((box) => {
    const blanket = policyFor(box, { powershell: "allow" });
    expectAction(check(box, blanket, "Get-ChildItem", { category: "powershell" }), "allow", false, "blanket");
    expectAction(check(box, blanket, "git push", { category: "powershell" }), "deny", true, "git push");
    const specific = policyFor(box, { powershell: { "Get-ChildItem": "allow" } });
    const denied = check(box, specific, "Get-ChildItem", { category: "powershell" });
    expectAction(denied, "deny", false, "specific");
    assert.match(denied.reason, /only a blanket rule can allow them/);
  }),
);

// ─── Gate ────────────────────────────────────────────────────────────────────

test(
  "bash validator: an unverifiable command is blocked through a headless gate",
  withBox(async (box) => {
    writeFileSync(join(box.agentDir, POLICY_FILE_NAME), JSON.stringify({ version: 1 }));
    const handlers = new Map<string, (event: unknown, ctx: unknown) => unknown>();
    const pi = { on: (event: string, handler: (event: unknown, ctx: unknown) => unknown) => handlers.set(event, handler) };
    registerPolicyGate(pi as never, {
      runtime: new PolicyRuntime({ agentDir: box.agentDir, home: box.home }),
      resolveAgent: () => ({ ...baseAgent, permission: WRITER }),
      inheritedRules: () => [],
    });
    const ctx = { cwd: box.cwd, hasUI: false, ui: { select: async () => undefined, notify: () => {} } };
    handlers.get("before_agent_start")?.({}, ctx);
    const call = async (command: string) =>
      (await handlers.get("tool_call")?.({ toolName: "bash", input: { command } }, ctx)) as
        | { block: true; reason: string }
        | undefined;
    assert.equal(await call("ls -la"), undefined);
    const blocked = await call('echo "abc');
    assert.match(blocked?.reason ?? "", /^Permission denied\.\nOperation: bash echo "abc\nReason: cannot verify/);
    assert.match(blocked?.reason ?? "", /non-interactive/);
    const git = await call("git status; git push");
    assert.match(git?.reason ?? "", /git write operations are disabled \(git push\)/);
  }),
);
