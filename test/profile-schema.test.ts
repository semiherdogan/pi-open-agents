import assert from "node:assert/strict";
import { test } from "node:test";

import {
  isProfileName,
  parseProfile,
  parseProfileState,
  parseProjectLayer,
} from "../src/profile/schema.ts";

test("parses a valid profile", () => {
  const json = JSON.stringify({
    implementer: {
      model: "claude-bridge/sonnet",
      escalationModel: "claude-bridge/opus",
      thinking: "medium",
    },
    explorer: { model: "codex-bridge/gpt-5/high" },
  });
  assert.deepEqual(parseProfile(json), {
    implementer: {
      model: "claude-bridge/sonnet",
      escalationModel: "claude-bridge/opus",
      thinking: "medium",
    },
    explorer: { model: "codex-bridge/gpt-5/high" },
  });
});

test("parses an empty profile", () => {
  assert.deepEqual(parseProfile("{}"), {});
});

test("rejects invalid profile shapes", () => {
  assert.throws(() => parseProfile("[]"), /JSON object/);
  assert.throws(() => parseProfile("null"), /JSON object/);
  assert.throws(() => parseProfile('"x"'), /JSON object/);
  assert.throws(() => parseProfile('{"worker": "a/b"}'), /must be an object/);
  assert.throws(() => parseProfile('{"worker": {}}'), /needs a model/);
  assert.throws(() => parseProfile('{"worker": {"model": "plain"}}'), /physical model/);
  assert.throws(() => parseProfile('{"worker": {"model": "x/"}}'), /physical model/);
  assert.throws(() => parseProfile('{"worker": {"model": "/id"}}'), /physical model/);
  assert.throws(() => parseProfile('{"worker": {"model": "a b/c"}}'), /physical model/);
  assert.throws(() => parseProfile('{"worker": {"model": "profile/implementer"}}'), /physical model/);
  assert.throws(
    () => parseProfile('{"worker": {"model": "a/b", "escalationModel": "profile/worker"}}'),
    /physical model/,
  );
  assert.throws(
    () => parseProfile('{"worker": {"model": "a/b", "thinking": "turbo"}}'),
    /thinking level/,
  );
  assert.throws(
    () => parseProfile('{"worker": {"model": "a/b", "extra": true}}'),
    /unknown field: extra/,
  );
  assert.throws(() => parseProfile('{"../escape": {"model": "a/b"}}'), /invalid agent name/);
  assert.throws(() => parseProfile('{"": {"model": "a/b"}}'), /invalid agent name/);
});

test("a __proto__ agent key stays an own property", () => {
  const profile = parseProfile('{"__proto__": {"model": "a/b"}}');
  assert.equal(Object.getPrototypeOf(profile), Object.prototype);
  assert.equal(Object.hasOwn(profile, "__proto__"), true);
  assert.deepEqual(profile["__proto__"], { model: "a/b" });
});

test("parses a full project layer", () => {
  const json = JSON.stringify({
    profile: "cheap",
    agents: { implementer: { model: "a/haiku", escalationModel: "a/sonnet", thinking: "low" } },
  });
  assert.deepEqual(parseProjectLayer(json), {
    profile: "cheap",
    agents: { implementer: { model: "a/haiku", escalationModel: "a/sonnet", thinking: "low" } },
  });
});

test("parses project layer agents only and empty layers", () => {
  const parsed = parseProjectLayer('{"agents": {"explorer": {"thinking": "high"}}}');
  assert.deepEqual(parsed, { agents: { explorer: { thinking: "high" } } });
  assert.equal(Object.hasOwn(parsed, "profile"), false);
  assert.deepEqual(parseProjectLayer("{}"), { agents: {} });
  assert.deepEqual(parseProjectLayer('{"profile": "cheap"}'), { profile: "cheap", agents: {} });
});

test("rejects invalid project layers", () => {
  assert.throws(() => parseProjectLayer("[]"), /JSON object/);
  assert.throws(() => parseProjectLayer("null"), /JSON object/);
  assert.throws(() => parseProjectLayer('{"extra": 1}'), /unknown field: extra/);
  assert.throws(() => parseProjectLayer('{"profile": "../x"}'), /profile name/);
  assert.throws(() => parseProjectLayer('{"profile": 3}'), /profile name/);
  assert.throws(() => parseProjectLayer('{"agents": []}'), /agents must be an object/);
  assert.throws(() => parseProjectLayer('{"agents": null}'), /agents must be an object/);
  assert.throws(() => parseProjectLayer('{"agents": {"a": "x/y"}}'), /must be an object/);
  assert.throws(() => parseProjectLayer('{"agents": {"a": {"foo": 1}}}'), /unknown field: foo/);
  assert.throws(() => parseProjectLayer('{"agents": {"a": {"model": "plain"}}}'), /physical model/);
  assert.throws(
    () => parseProjectLayer('{"agents": {"a": {"model": "profile/implementer"}}}'),
    /physical model/,
  );
  assert.throws(
    () => parseProjectLayer('{"agents": {"a": {"escalationModel": "profile/implementer"}}}'),
    /physical model/,
  );
  assert.throws(() => parseProjectLayer('{"agents": {"a": {"thinking": "turbo"}}}'), /thinking level/);
});

test("a __proto__ override stays an own property", () => {
  const layer = parseProjectLayer('{"agents": {"__proto__": {"model": "a/b"}}}');
  assert.equal(Object.getPrototypeOf(layer.agents), Object.prototype);
  assert.equal(Object.hasOwn(layer.agents, "__proto__"), true);
  assert.deepEqual(layer.agents["__proto__"], { model: "a/b" });
});

test("parses profile state", () => {
  assert.deepEqual(parseProfileState('{"active": "cheap"}'), { active: "cheap" });
  assert.deepEqual(parseProfileState("{}"), {});
});

test("rejects invalid profile state", () => {
  assert.throws(() => parseProfileState("[]"), /JSON object/);
  assert.throws(() => parseProfileState("null"), /JSON object/);
  assert.throws(() => parseProfileState('{"active": 3}'), /profile name/);
  assert.throws(() => parseProfileState('{"active": "../x"}'), /profile name/);
  assert.throws(() => parseProfileState('{"other": "x"}'), /unknown field: other/);
});

test("recognizes profile names", () => {
  assert.equal(isProfileName("cheap"), true);
  assert.equal(isProfileName("Agent_1-test"), true);
  assert.equal(isProfileName(""), false);
  assert.equal(isProfileName("a/b"), false);
  assert.equal(isProfileName("a b"), false);
  assert.equal(isProfileName("../x"), false);
});
