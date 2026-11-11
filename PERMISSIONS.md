# Permission policy

This fork adds a strict, file-based permission policy on top of the upstream per-agent `permission` frontmatter. This document describes how it works, how to configure it, and what it does not protect against.

## Overview

Strict mode turns on when at least one of these files exists:

- `~/.pi/agent/permissions.json` (user file; the agent dir follows `PI_CODING_AGENT_DIR`)
- `<project>/.pi/permissions.json` (project file, looked up in the session cwd)

Without either file, upstream behavior applies unchanged: the legacy gate enforces only the agent's frontmatter `permission` rules, and a call that matches no rule proceeds.

In strict mode every tool call is decided: hard denies first, then rules, then a per-category default. Policy files are read once per agent run. Edits apply from the next run, and a running subagent never widens its permissions mid-run. Deleting a policy file mid-session does not lift its rules: the last loaded version is kept until pi restarts.

## File formats

### User file

```json
{
  "version": 1,
  "alwaysDeny": {
    "gitWrite": true,
    "paths": ["~/.ssh/**", "secrets/**"],
    "tools": ["powershell"],
    "bash": ["curl", "sudo", "npm publish"]
  },
  "trustedProjects": ["~/Projects", "/work/client-repo"],
  "agents": {
    "*": { "bash": { "git status": "allow" } },
    "implementer": { "bash": { "pytest": "allow" } }
  }
}
```

- `version`: must be `1`.
- `alwaysDeny.gitWrite` (default `true`): blocks every git operation that changes repository state.
- `alwaysDeny.paths`: paths no agent may read or write (credentials such as `~/.ssh/**`). Relative patterns are anchored to the project, `~/` expands to the home dir. See [Protected paths](#protected-paths).
- `alwaysDeny.tools`: tools denied for every agent.
- `alwaysDeny.bash`: command prefixes denied for every agent (same token-prefix matching as bash rules, command name compared case-insensitively and by basename).
- `trustedProjects`: absolute or `~/` paths. A project at or below an entry is trusted.
- `agents`: same map format as the [project file](#project-file). Applies in every project, trusted or not (the user file is never trust-filtered). `*` also covers sessions without an agent.

Unknown keys, a wrong `version` or wrong types make the file invalid.

### Project file

```json
{
  "version": 1,
  "agents": {
    "*": { "bash": { "npm test": "allow" } },
    "implementer": { "bash": { "pytest": "allow" }, "edit": { "dist/**": "deny" } }
  }
}
```

- `agents["*"]` applies to every agent and to sessions without an agent.
- `agents["<name>"]` applies to that agent only, after `*`.
- Each value is a permission map: `category: action` or `category: { pattern: action }`, with action `allow`, `ask` or `deny`.

### Agent frontmatter

```yaml
---
name: architect
mode: primary
tools: [read, grep, find, ls, bash, subagent]
allowedAgents: [implementer, reviewer]
delegation:
  implementer: role
permission:
  edit: deny
  write: deny
  bash:
    "git status": allow
    "rg": allow
---
```

- `permission`: the agent's own rules, same map format as the project file.
- `tools`: without a `permission` block, a `tools` list grants exactly the listed tools (each as `allow` with `*`).
- `allowedAgents`: which agents this agent may delegate to.
- `delegation`: per child agent, `restrict` (default) or `role`. See [Delegation](#delegation).

## Precedence

Rules are concatenated in this order and evaluated last match wins:

1. Safe defaults (per category, see below)
2. User `agents["*"]`
3. Agent frontmatter `permission` (or `tools`)
4. User `agents["<agent>"]`
5. Project `agents["*"]`
6. Project `agents["<agent>"]`
7. `alwaysDeny` and protected paths: hard denies, checked before any rule and never overridden, not even by an "always" answer

Additional rules:

- An untrusted project (not under any `trustedProjects` entry) contributes only its `deny` rules. Its `allow` and `ask` rules are ignored with a warning.
- An invalid policy file fails closed: `bash`, `shell`, `powershell`, `edit` and `write` are hard denied until it is fixed. Other categories keep working.

## Strict defaults and ask

Calls that match no rule fall back to a per-category default:

| Category | Default |
|---|---|
| `read`, `grep`, `find`, `ls`, `subagent`, `search_agents` | allow |
| `bash`, `shell`, `powershell`, `edit`, `write` | deny |
| Any other tool (MCP, web fetch, extension tools) | ask |

`ask` behavior:

- Interactive sessions show a dialog: allow once, allow always (this session), deny.
- "Always" is remembered per exact command or path set for risky categories (`bash`, `edit`, ...), per category for the rest. It never applies to hard denies.
- Headless subagents cannot answer, so `ask` is a deny there (fail closed).

`edit` and `write` with no path field (for example a patch tool carrying paths inside its text) are hard denied because their target cannot be verified.

## Bash rules

Bash patterns use token-prefix matching. The pattern is split on whitespace; token `i` must glob-match argument `i` of the command, and extra arguments are allowed.

| Pattern | Matches | Does not match |
|---|---|---|
| `npm test` | `npm test`, `npm test -- --watch` | `npm run test`, `npm` |
| `npm run *` | `npm run build`, `npm run lint --fix` | `npm test` |
| `git status` | `git status -s` | `git stash` |
| `*` | every command | |

What is parsed before matching:

- Chains and pipelines (`&&`, `||`, `;`, `|`, `&`): every command is judged on its own; the strictest verdict wins.
- Command substitutions (`$(...)`, backticks) and process substitutions (`<(...)`): inner commands are judged too.
- Nested shells (`sh -c`, `bash -c`, `zsh -c`), `eval` with static text, and heredocs or herestrings given directly to a shell (`sh <<EOF`).
- Wrappers: `env`, `command`, `exec`, `nohup`, `time`, `nice`, `timeout`, `stdbuf`, `xargs`, `parallel`, `mise exec`, `uv run` and similar are skipped to judge the real command.
- `find -exec`/`-execdir`/`-ok`, `fd -x`/`-X`, `rg --pre`, `sort --compress-program`: the executed command is judged.
- Brace expansion, `cd`/`pushd` targets for later relative paths, and `~` expansion (`~`, `~+` and `~<current user>`; other tilde prefixes such as `~-` or `~otheruser` ask). Once a script assigns `CDPATH`, every `cd` target counts as unknown.

Anything the parser cannot see through (a dynamic command name, a script from a variable, a script piped into a shell, arguments coming from stdin via `xargs`) turns an `allow` into `ask`.

Environment assignments are judged too, because rules match argv only. Collected from `NAME=value` and `NAME[i]=value` prefixes, assignments passed through wrappers (`env A=1 cmd`), `export`/`declare -x`/`typeset -x`/`local -x` (options in any position, `export -n` included) and, under `set -a` or a later `export NAME`, plain assignments. A dangerous name (below) also counts when it is only named: `export NAME`, `declare NAME`, `printf -v NAME`, `read NAME`, `read -a NAME`, `mapfile`/`readarray NAME`, `for NAME in`, `${NAME:=x}`/`${NAME=x}`. `env -P DIR` (and `--path`) counts as a `PATH` assignment:

- `GIT_*` and pager/editor variables (`PAGER`, `GIT_PAGER`, `MANPAGER`, `LESSOPEN`, `LESSCLOSE`, `EDITOR`, `VISUAL`) in a script that mentions git: hard deny while `gitWrite` is on (`GIT_EXTERNAL_DIFF=rm git diff`, `PAGER='sh -c x' git log`).
- Variables that make a program load or run something else (`PATH`, `HOME`, `CDPATH`, `LD_PRELOAD`, `DYLD_*` loader variables, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`, `IFS`, `npm_config_*` and similar, plus the git and pager variables above when git is not mentioned): deny, never asked. A plain `PATH=x` without `export` counts too, since such variables are normally exported already.
- Harmless variables (`CI`, `NODE_ENV`, `FORCE_COLOR`, `NO_COLOR`, `TERM`, `TZ`, `LANG`, `LC_*`, `DEBUG`, `RUST_BACKTRACE`, `RUST_LOG`, `PYTHONUNBUFFERED`, `PYTHONDONTWRITEBYTECODE`, `COLUMNS`, `LINES`): no effect, so `CI=1 npm test` passes a `npm test` rule.
- Any other variable a command receives (`FOO=1 npm test`, `export FOO=1`): ask (deny in headless subagents). A plain `FOO=1` that is never exported is ignored.

`export`, `set` and `declare` are commands like any other and still need a rule of their own.

Privilege wrappers (`sudo`, `doas`, `su`, `pkexec`, `run0`) are judged twice: the wrapped command and the full command line must both pass, so `sudo rm` needs a rule for `sudo` itself.

A path-like command word only matches a path-like pattern: rule `rg` allows `rg`, not `./rg` or `/tmp/rg`.

Agents without any `edit`/`write` allow rule cannot change files through bash either: redirections, `tee`, `sed -i`, `cp`, `mv`, `rm` and similar are denied for them. Writes hidden in options and scripts count as well:

- `sed -i`/`-I` (GNU and BSD forms; after a bare `-i`, the next word is a BSD suffix only when it holds no sed delimiters, so `sed -i 's/a/b/' env.ts` edits `env.ts`), sed script commands `w FILE`/`W FILE` and the `s///w FILE` flag; the sed `e` command and `s///e` flag run commands, so they ask even for writers.
- `yq -i`/`--inplace` and `yq -s`/`--split-exp` (split file names are computed at run time, so they ask).
- `uniq IN OUT`, `file -C`, `sort -o`.
- curl `-o`/`-O`/`--output-dir`, `-D`/`--dump-header`, `-c`/`--cookie-jar`, `--trace`, `--trace-ascii`, `--stderr`, `--libcurl`, `--etag-save`, `--hsts`, `--alt-svc` and `-K`/`--config` (a config file can set `output`); `-` and `/dev/null` count as no file.
- `lightpanda --cookie-jar`/`--output`/`-o`.

The file arguments of these commands are write targets for the protected-path check below.

## Git protection

With `alwaysDeny.gitWrite` (default `true`) every git command is a hard deny unless it is read-only: `status`, `log`, `diff`, `show`, `blame`, `rev-parse`, `ls-files`, `grep` and similar. Blocked: staging, committing, pushing, pulling, fetching, reset, checkout/switch/restore, stash, rebase, merge, cherry-pick, branch and tag changes, config changes, `--output=` writes, and options that run commands (`ls-remote --upload-pack`, `grep -O`). `git -c KEY=VALUE` and `--config-env` are blocked for every key outside a short safe list (`color.*`, `log.*`, `format.*`, `i18n.*`, `core.quotepath`, `core.abbrev`, `diff.renames`, `diff.noprefix`), since keys such as `core.pager`, `diff.external` or `alias.*` run programs. Git is detected through wrappers, nested shells, `eval` and case variants of the name. Read-only git still needs an allow rule such as `git status`.

Set `"gitWrite": false` only if the agent really must change the repository.

## Protected paths

`edit` and `write` (and bash writes, deletes and moves) to these locations are hard denied:

- Built-in, anchored to the project: `.git`, `.git/**`, `.pi/**`, `.opencode/**`, `.agents/**`
- Built-in, anywhere: `**/.git`, `**/.git/**`, `**/.pi/**`, `**/.opencode/**`, `**/.agents/**`
- The agent dir (`~/.pi/agent/**`), both its lexical and its resolved path
- Every `alwaysDeny.paths` entry

`alwaysDeny.paths` entries are read-protected too, for every agent: `read`, `grep`, `find` and `ls` on them (or rooted at an entry's directory) are hard denied, and so is a bash command with any static argument naming one: plain words, `key=value` values, `@file` forms (`curl -d @~/.aws/credentials`), attached short-option values, input redirects (`< file`), `$HOME/...`, `~+/...` after a `cd ~`, `~<current user>/...` and globs that can expand into the entry (`cat ~/.a*/credentials`). A tilde prefix only known at run time (`~-`, `~otheruser`) asks. The built-in protected paths stay readable (`cat .git/config` works); they are write-protected only.

Paths are checked both lexically and after resolving symlinks, case-insensitively. Deleting or moving a directory that contains one of the anchored protected locations is a hard deny too: the project's own `.git`, `.pi`, `.opencode` and `.agents`, the agent dir, or an `alwaysDeny.paths` entry (for example `rm -rf .` in the project root). A directory that merely contains some other nested `.pi` or `.git` (for example `rm -rf packages` with `packages/x/.git`) is not blocked, while writing into or deleting those nested directories directly is.

## Delegation

Each subagent call runs in one of two modes, chosen by the delegating agent's frontmatter, never by the model:

- `restrict` (default): the child runs with its own policy, and the parent's policy is added as a ceiling. Every call must pass both.
- `role`: the child runs with its own role policy; the parent is not added as a ceiling.

`role` is granted only when all of these hold, otherwise it falls back to `restrict` with a note:

- The child is listed in the delegating agent's `allowedAgents`.
- The delegating agent is a global agent, or the project is trusted.
- The child is a global agent, or both the project and the child's project are trusted.

Ceilings accumulate across hops: a ceiling imposed further up the chain still applies under `role`. A hard deny from any ceiling wins; otherwise the most restrictive decision wins.

Inherited rules: deny and ask rules handed down by a legacy (non-strict) ancestor through `PI_OPEN_AGENTS_PARENT_RULES` are appended after the child's own rules, so they always win.

The parent passes everything in a snapshot in `PI_OPEN_AGENTS_POLICY`: the child's resolved policy, the ceilings, inherited rules and the policy files. The child does not re-read the user file. An unreadable or mismatched snapshot blocks every tool call in the child.

Child cwd and project root: a child whose cwd is at or below the parent's cwd uses the parent's project file from the snapshot. A child elsewhere uses the nearest ancestor of its cwd with a `.pi/permissions.json` (the search stops below the home dir), read at spawn time; trust is computed for that project root.

## Awareness

In strict mode a `## Runtime Permissions` section is appended to the system prompt of every run, after upstream and any agent `systemPrompt: replace-all`. Every verdict in it is computed by the same engine the gate uses, so the prompt cannot promise what the gate denies. It lists file verdicts, allowed bash prefixes, git and protected paths, delegation targets with their mode, and other tools. The section is deterministic, which keeps prompt caching intact.

## Commands

All `/permissions` commands are read-only; nothing writes policy files or executes the explained call.

| Command | Shows |
|---|---|
| `/permissions` | The awareness summary for the active agent, plus the policy sources. Without a policy: that strict mode is off and which files it looks for. |
| `/permissions <agent>` | The summary for `<agent>` as a primary agent in the current cwd (no ceilings). |
| `/permissions source` | Each file's path and status (missing, loaded, invalid with error), trust and the matching `trustedProjects` entry, the active agent's definition file, and in a subagent the snapshot ceilings and inherited rules. |
| `/permissions reload` | Re-reads the policy files and reports status and warnings. Refused while an agent run is in progress. Running subagents keep their snapshot. |
| `/permissions explain <tool> <argument...>` | How a call would be decided: action, hard yes/no, reason, matched rule. Example: `explain bash git push origin main`, `explain edit src/a.ts`, `explain webfetch https://x`. `explain apply_patch <text>` is a hard deny, as in the gate (the target path cannot be verified). In legacy mode it uses the legacy gate and says so. |
| `/permissions help` | Usage. |

## Security levels

1. **Awareness** (prompt section): tells the model what it may do. It is guidance, not a guarantee.
2. **Tool enforcement** (this policy): every tool call through pi's `tool_call` hook is checked: file tools by path, shell commands by parsed argv, git writes, protected paths, unknown tools ask. It cannot see what a permitted program does after it starts.
3. **OS isolation** (recommended for real guarantees): run pi in a container or sandbox where `.git` and `~/.pi/agent` are mounted read-only (including the metadata of linked worktrees, which lives in the main repository's `.git`), and the environment holds no push credentials or tokens. The `docker/` setup in this repository is a starting point for such a sandbox; it does not implement these restrictions yet.

## Known limitations

- Script files are not inspected: `npm run x`, `make`, `bash x.sh`, `python script.py`, `source x.sh` and `sed -f script.sed` are judged by their command line only. Allow them only for agents you would trust with the script's contents.
- Read protection of `alwaysDeny.paths` sees static paths only. A path built at run time (`cat $DIR/id_rsa` with `DIR=~/.ssh`, `cd "$D"`), a recursive read of a parent directory (`rg --hidden x ~`, `tar c ~`, `cp -r ~ /tmp`, the grep tool rooted at `~`) and program-internal reads (a tool that reads `~/.aws` by itself) are not caught.
- Environment variables are judged by name only; a variable already set in the parent environment is not visible, and only the variables named in [Bash rules](#bash-rules) are treated as dangerous.
- Archive extraction (`tar -x`, `unzip`) can write anywhere the archive says, including protected paths.
- Obfuscated inline scripts (encoded, assembled at run time) are not detected.
- Arguments from stdin (`xargs`, `parallel`) cannot be verified; such commands ask instead of being allowed.
- Rule patterns are tokenized on whitespace only; quoting inside a pattern is not understood.
- `powershell` is allowed only by a blanket `*` rule, and `alwaysDeny.bash` and protected-path checks do not apply to its commands.
- Deleting a parent directory of the project's own protected locations, the agent dir or an `alwaysDeny.paths` entry is blocked; deleting a parent of a nested `.pi` or `.git` elsewhere (`rm -rf packages` with `packages/x/.git`) is not. Deleting those nested directories directly is blocked.
- A nested symlink inside a protected directory, written through its real target path, is not caught.
- After `set_agent`, the prompt section still shows the previous agent until the next run; enforcement switches immediately.
- Other extensions loaded later can still change the system prompt or add tools; unknown tools ask.
- A permitted process can start another pi or call tools directly; only OS-level isolation prevents that.
- The network is not policed: `curl` and similar commands can send data out once allowed.

## Example setup

User file `~/.pi/agent/permissions.json`:

```json
{
  "version": 1,
  "alwaysDeny": {
    "gitWrite": true,
    "paths": ["~/.ssh/**", "~/.aws/**", ".env"],
    "tools": [],
    "bash": ["sudo", "wget", "npm publish", "docker"]
  },
  "trustedProjects": ["~/Projects"]
}
```

Agents in `~/.pi/agent/agents/`:

```yaml
---
name: architect
mode: primary
description: Plans and delegates; never changes files
allowedAgents: [implementer, reviewer, explorer, researcher]
delegation:
  implementer: role
  reviewer: role
  explorer: role
  researcher: role
permission:
  edit: deny
  write: deny
  bash:
    "git status": allow
    "git diff": allow
    "git log": allow
    "rg": allow
    "ls": allow
---
```

```yaml
---
name: implementer
mode: all
description: Writes code and runs the tests
permission:
  edit: allow
  write: allow
  bash:
    "git status": allow
    "git diff": allow
    "npm test": allow
    "npm run *": allow
    "npx tsc": allow
    "rg": allow
    "ls": allow
---
```

```yaml
---
name: reviewer
mode: subagent
description: Reviews diffs, read-only
permission:
  edit: deny
  write: deny
  bash:
    "git diff": allow
    "git log": allow
    "git show": allow
    "rg": allow
---
```

```yaml
---
name: explorer
mode: subagent
description: Finds code, read-only
tools: [read, grep, find, ls]
---
```

```yaml
---
name: researcher
mode: subagent
description: Reads docs and the web
permission:
  edit: deny
  write: deny
  webfetch: allow
  bash:
    "rg": allow
    "curl": allow
    "lightpanda fetch": allow
---
```

Project file `<project>/.pi/permissions.json` (the project is under `~/Projects`, so it is trusted):

```json
{
  "version": 1,
  "agents": {
    "implementer": { "bash": { "pytest": "allow", "uv run pytest": "allow" } }
  }
}
```

The architect delegates all four children in `role` mode; they are all global definitions, so the delegation is trusted. Each child then runs with its own read-only or write role, because `restrict` would add the architect's policy as a ceiling and block the researcher's `curl` and the reviewer's `git show`; `role` never removes hard rules or ceilings that apply above the architect. Nobody can commit or push, `curl` cannot write into protected paths, and only the implementer runs `pytest` in this project.
