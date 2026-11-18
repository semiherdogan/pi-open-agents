/**
 * Pure formatter for the `/profile` summary.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildProfileSummary,
  PINNED_HEADER,
  PROJECT_OVERRIDE_NOTE,
  type ProfileSummaryInput,
} from "../src/profile/summary.ts";

const PINNED_FILE = "/home/user/.pi/agent/agents/pinned.agent.md";

function input(overrides: Partial<ProfileSummaryInput> = {}): ProfileSummaryInput {
  return {
    name: "work",
    projectOverride: false,
    profile: {
      alpha: { model: "anthropic/claude-a" },
      beta: { model: "anthropic/claude-b", thinking: "high", escalationModel: "anthropic/claude-big" },
    },
    pinned: [],
    ...overrides,
  };
}

test("summary: header, one line per agent, thinking and escalation", () => {
  const text = buildProfileSummary(input());
  assert.equal(
    text,
    [
      "Profile work",
      "alpha: anthropic/claude-a",
      "beta: anthropic/claude-b · high (escalation: anthropic/claude-big)",
    ].join("\n"),
  );
});

test("summary: a project layer is named in the header", () => {
  const text = buildProfileSummary(input({ projectOverride: true }));
  assert.equal(text.split("\n")[0], `Profile work (${PROJECT_OVERRIDE_NOTE})`);
});

test("summary: pinned agents are listed only when there are any", () => {
  assert.ok(!buildProfileSummary(input()).includes(PINNED_HEADER));

  const text = buildProfileSummary(
    input({ pinned: [{ name: "pinned", model: "anthropic/claude-pinned", filePath: PINNED_FILE }] }),
  );
  assert.ok(text.includes(`${PINNED_HEADER}\npinned: anthropic/claude-pinned (${PINNED_FILE})`));
});

test("summary: a layer that selects its own profile says so", () => {
  const text = buildProfileSummary(input({ projectOverride: true, layerProfile: "home", globalProfile: "work" }));
  assert.ok(
    text.includes(".pi/profile.json selects home in this project; the global selection (work) applies elsewhere."),
  );
});

test("summary: the layer note omits a global name it does not have", () => {
  const text = buildProfileSummary(input({ projectOverride: true, layerProfile: "home" }));
  assert.ok(
    text.includes(".pi/profile.json selects home in this project; the global selection applies elsewhere."),
  );
});

test("summary: no layer selection line without a layer profile", () => {
  assert.ok(!buildProfileSummary(input()).includes("selects"));
});

test("summary: an empty profile prints only the header", () => {
  assert.equal(buildProfileSummary(input({ profile: {} })), "Profile work");
});
