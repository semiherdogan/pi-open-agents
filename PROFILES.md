# Agent profiles

Profiles map agents to physical models without editing agent files. Models resolve at request time, so switching a profile applies to every running pi process (other sessions, subagent children) on its next request, with no reload and no rewritten agent files.

## Files

Profile files live in the agent dir, which follows `PI_CODING_AGENT_DIR` (default `~/.pi/agent`):

- `<agentDir>/profiles/<name>.json`: one profile. The file name is the profile name, `[A-Za-z0-9_-]+`.
- `<agentDir>/profile-state.json`: the global selection, `{"active": "work"}`. `/profile` writes it.
- `<project>/.pi/profile.json`: optional project layer, read at session start, only in a primary process and only when the project is trusted.

### Profile file

```json
{
  "implementer": {
    "model": "anthropic/claude-sonnet-4-5",
    "thinking": "high",
    "escalationModel": "anthropic/claude-opus-4-5"
  },
  "reviewer": {
    "model": "claude-bridge/claude-fable-5-2"
  }
}
```

- Each key is an agent name, each value one entry.
- `model` (required): a physical model in `provider/id` form. A `profile/...` reference is rejected.
- `escalationModel` (optional): registers a second virtual model, `profile/<agent>-escalation`, for calls that need a stronger model.
- `thinking` (optional): `off`, `minimal`, `low`, `medium`, `high`, `xhigh` or `max`.
- Unknown fields, unknown thinking levels and a missing `model` are errors: the whole profile is rejected, never half-applied.

### Project layer

```json
{
  "profile": "work",
  "agents": {
    "implementer": { "model": "claude-bridge/claude-fable-5-2", "thinking": "low" }
  }
}
```

- `profile` (optional): which profile this project uses, over the global selection.
- `agents` (optional): field-wise overrides on top of that profile. An override for an agent the profile does not define needs its own `model`; without one it is ignored, the rest of the layer stays active, and session start warns once: `.pi/profile.json: no model for <agents> in profile <name>; these overrides are ignored`. If no base profile can be resolved, the check is skipped silently.
- Unknown fields are errors. An untrusted project, invalid JSON, a wrong shape, or a `profile` name that does not exist: the file is ignored with a warning at session start.

## Following and pinning

- An agent whose frontmatter has no `model:` follows the profile. At session start it gets the virtual model `profile/<agent-name>`; pi selects it through the normal agent path.
- An agent without `model:` that any installed profile names follows the profile mechanism. If the active profile does not define it, its requests fail with `profile <name> does not define <agent>` instead of falling back to a default model. That is designed: a silent fallback would hide a stale profile.
- An agent whose frontmatter has `model:` is pinned: the profile never touches it. `/profile` lists pinned agents whose name is also in the profile.
- Profile `thinking` wins over frontmatter `thinking` and over a level chosen manually: the router returns the profile level on every request, and the footer is synced so it does not show a level the request will not use.

## Precedence

1. The project layer's `profile` decides which profile is active in this project. Without it, the global selection in `profile-state.json` applies.
2. The project layer's `agents.<agent>` fields apply over the selected profile entry, field by field (`model`, `escalationModel`, `thinking`).
3. An explicit frontmatter `model:` sits outside the profile entirely. Those agents are never bound and never routed.
4. Profile `thinking` wins over frontmatter and over a manual thinking level.

## Live semantics

- `route()` runs before every request made with a `profile/*` model. It reads the active profile live through a version cache (`ino`, `mtime` and size), so `/profile work` in one session applies in other sessions and in already running subagent children on their next request. Only parse and validation errors are cached; an unreadable file is retried on the next request.
- The first request after a user message (`reason: "user"`) resolves fresh.
- pi marks every request without a new user message as a continuation. Such a request with a `previous` response keeps that physical model and thinking level, so a run started by an extension message also stays on the previous model. Prompt caches and thinking signatures stay valid, and a switch is guaranteed from the next message the user writes.
- A subagent child inherits the project layer through `PI_OPEN_AGENTS_PROFILE_LAYER` and resolves it live against the current profile. It never inherits a resolved table, so a profile switch applies to children too.
- Retries and direct (non-agent-loop) requests resolve fresh on purpose, so a switch away from a failing provider takes effect on retry.
- A profile change needs no reload and no idle wait.
- A new profile file that introduces a new agent name is registered at the next session start or `/reload`, because its virtual model must be registered first. Editing an existing profile is visible on the next request.

## Subagent model allow-list

The `subagent` tool accepts only:

- no `model` field, which lets the child follow the profile, or
- `profile/<key>`, where the key is registered by a loaded profile (`<agent>` or `<agent>-escalation`).

A physical `model` string is blocked: it would escape the profile and survive a switch. The blocked call names the allowed virtual ids.

## Errors

- No profile selected: `no active profile; run /profile <name>`.
- Key missing from the selected profile: `profile <name> does not define <key>`.
- Physical model not in the catalog: `profile <name>: model <ref> (<key>) is not available`.
- Invalid profile file: `profile <name> is invalid: <reason>`.

A routing error ends the request with that message.

## Inert mode

Until at least one profile file exists, the extension registers nothing: no virtual model, no session handler, no `/profile` command. The feature stays invisible, and a legacy external extension that still provides `profile/*` models and `/profile` keeps working. Adding the first profile file takes effect at the next pi start or `/reload`.

## Footer and command

- `/profile` without an argument opens a picker; `/profile <name>` switches directly. Both write `profile-state.json`.
- The footer shows `[<profile>]`, `[<profile> · <provider/id>]` when the active bound agent is on its virtual model, `[<profile> · project]` when a project layer is active, and `[<profile> · project · <provider/id>]` with both.
- The command summary lists every agent of the resolved profile, plus pinned agents and, when the project layer selects its own profile, a note that the layer wins in this project.

## Limitations

- The footer may show the virtual id (`profile/<agent>`) until the first response routes it. Other extensions reading `ctx.model` see the virtual model, not the physical one.
- A manual `/model` choice is replaced by the profile's virtual model on every `session_start` (startup, new session, resume, fork, reload): each one reselects `profile/<agent>` for a bound agent whose `ctx.model` is physical. Selecting a `profile/*` virtual model manually routes through the profile regardless.
- Project layers are read at session start only. Edits apply at the next session start or `/reload`.
- A key removed from every profile stays registered until reload. Requests using it fail with `profile <name> does not define <key>`.
- Profiles do not change tool, permission or prompt configuration; they only choose models and thinking levels.
