import assert from "node:assert/strict";
import { test } from "node:test";

import type { Profile } from "../src/profile/schema.ts";
import {
  applyLayer,
  incompleteOverrides,
  lookupRoute,
  routeKeys,
  splitModelRef,
  subagentModelViolation,
  virtualModelRef,
} from "../src/profile/resolve.ts";

const BASE: Profile = {
  implementer: { model: "a/sonnet", escalationModel: "a/opus", thinking: "medium" },
  explorer: { model: "a/haiku", thinking: "low" },
};

test("applies an override field by field", () => {
  const result = applyLayer(BASE, {
    agents: { implementer: { model: "b/haiku", thinking: "high" } },
  });
  assert.deepEqual(result.implementer, {
    model: "b/haiku",
    escalationModel: "a/opus",
    thinking: "high",
  });
  assert.deepEqual(result.explorer, BASE.explorer);
});

test("adds an agent that has a model", () => {
  const result = applyLayer(BASE, {
    agents: { architect: { model: "b/opus", escalationModel: "b/haiku", thinking: "max" } },
  });
  assert.deepEqual(result.architect, { model: "b/opus", escalationModel: "b/haiku", thinking: "max" });
});

test("ignores an unknown agent without a model instead of failing", () => {
  const result = applyLayer(BASE, { agents: { architect: { thinking: "high" } } });
  assert.deepEqual(result, BASE);
  assert.equal(lookupRoute(result, "architect"), undefined);
});

test("does not mutate the base profile", () => {
  const before = structuredClone(BASE);
  applyLayer(BASE, {
    agents: {
      implementer: { model: "b/haiku" },
      architect: { model: "b/opus" },
      ghost: { thinking: "high" },
    },
  });
  assert.deepEqual(BASE, before);
});

test("reports the overrides that were skipped", () => {
  assert.deepEqual(incompleteOverrides(BASE, undefined), []);
  assert.deepEqual(incompleteOverrides(BASE, { agents: {} }), []);
  assert.deepEqual(
    incompleteOverrides(BASE, {
      agents: {
        ghost: { thinking: "high" },
        implementer: { thinking: "low" },
        architect: { model: "b/opus" },
        phantom: { escalationModel: "a/opus" },
      },
    }),
    ["ghost", "phantom"],
  );
});

test("returns a new table without a layer", () => {
  const result = applyLayer(BASE, undefined);
  assert.notEqual(result, BASE);
  assert.deepEqual(result, BASE);
});

test("lists routes and their escalation routes", () => {
  assert.deepEqual(routeKeys(BASE), ["implementer", "implementer-escalation", "explorer"]);
  assert.deepEqual(routeKeys({}), []);
});

test("looks up plain and escalation routes", () => {
  assert.deepEqual(lookupRoute(BASE, "implementer"), { model: "a/sonnet", thinking: "medium" });
  assert.deepEqual(lookupRoute(BASE, "implementer-escalation"), { model: "a/opus", thinking: "medium" });
  assert.deepEqual(lookupRoute(BASE, "explorer"), { model: "a/haiku", thinking: "low" });
});

test("looks up an agent without thinking", () => {
  assert.deepEqual(lookupRoute({ worker: { model: "a/sonnet" } }, "worker"), { model: "a/sonnet" });
});

test("returns undefined for missing routes", () => {
  assert.equal(lookupRoute(BASE, "explorer-escalation"), undefined);
  assert.equal(lookupRoute(BASE, "missing"), undefined);
  assert.equal(lookupRoute(BASE, "missing-escalation"), undefined);
});

test("a plain agent name wins over the escalation suffix", () => {
  const profile: Profile = {
    worker: { model: "a/base", escalationModel: "a/escalation" },
    "worker-escalation": { model: "a/plain", thinking: "high" },
  };
  assert.deepEqual(lookupRoute(profile, "worker-escalation"), { model: "a/plain", thinking: "high" });
});

test("splits at the first slash", () => {
  assert.deepEqual(splitModelRef("a/b/c"), { provider: "a", id: "b/c" });
  assert.deepEqual(splitModelRef("a//b"), { provider: "a", id: "/b" });
  assert.equal(splitModelRef("plain"), undefined);
  assert.equal(splitModelRef("/id"), undefined);
  assert.equal(splitModelRef("x/"), undefined);
  assert.equal(splitModelRef(""), undefined);
});

test("builds a virtual model reference", () => {
  assert.equal(virtualModelRef("implementer"), "profile/implementer");
});

test("allows an omitted subagent model", () => {
  assert.equal(subagentModelViolation(undefined, ["implementer"]), undefined);
});

test("allows a virtual model id for a known key", () => {
  const keys = ["implementer", "implementer-escalation"];
  assert.equal(subagentModelViolation("profile/implementer", keys), undefined);
  assert.equal(subagentModelViolation("profile/implementer-escalation", keys), undefined);
});

test("rejects physical, unknown and non-string subagent models", () => {
  const keys = ["implementer"];
  assert.ok(subagentModelViolation("a/sonnet", keys));
  assert.ok(subagentModelViolation("profile/missing", keys));
  assert.ok(subagentModelViolation("profile/toString", keys));
  assert.ok(subagentModelViolation(42, keys));
  assert.ok(subagentModelViolation(null, keys));
});

test("lists the allowed virtual models in the rejection", () => {
  assert.equal(
    subagentModelViolation("a/sonnet", ["a", "b"]),
    'subagent model "a/sonnet" is not allowed; omit it or use one of: profile/a, profile/b',
  );
});
