import assert from "node:assert/strict";
import { describe, it, mock } from "node:test";

import { formatElapsed, liveElapsedMs, trackLiveElapsed } from "../src/subagent/elapsed.ts";
import type { AgentProgress, AgentToolLog } from "../src/subagent/executor.ts";
import { formatResultLines } from "../src/subagent/render.ts";

function progress(overrides: Partial<AgentProgress> = {}): AgentProgress {
  return {
    agent: "implementer",
    status: "running",
    startedAt: 1000,
    elapsedMs: 0,
    tools: [],
    output: "",
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, contextTokens: 0 },
    ...overrides,
  } as AgentProgress;
}

describe("formatElapsed", () => {
  it("formats seconds, minutes and hours", () => {
    assert.equal(formatElapsed(0), "0s");
    assert.equal(formatElapsed(87000), "1m27s");
    assert.equal(formatElapsed(59499), "59s");
    assert.equal(formatElapsed(59500), "1m0s");
    assert.equal(formatElapsed(3723000), "1h2m3s");
  });
});

describe("liveElapsedMs", () => {
  it("uses wall clock while running", () => {
    assert.equal(liveElapsedMs(progress(), () => 6000), 5000);
  });

  it("uses the recorded value once final", () => {
    assert.equal(liveElapsedMs(progress({ status: "done" }), () => 6000), 0);
    assert.equal(liveElapsedMs(progress({ status: "done", elapsedMs: 4200 }), () => 6000), 4200);
  });
});

describe("formatResultLines", () => {
  const statusText = (p: AgentProgress, now?: () => number, live?: boolean): string => {
    const line = formatResultLines(p, { expanded: false, now, live }).find((l) => l.kind === "status");
    assert.ok(line);
    return line.text;
  };

  const nestedStatusText = (
    parent: AgentProgress,
    options: { live: boolean; now: () => number },
  ): string => {
    const lines = formatResultLines(parent, { expanded: true, ...options });
    const line = lines.filter((l) => l.kind === "status")[1];
    assert.ok(line);
    assert.ok(line.text.startsWith("  "));
    return line.text;
  };

  const withNested = (
    parentStatus: AgentProgress["status"],
    toolStatus: AgentToolLog["status"],
    nested: AgentProgress,
  ): AgentProgress => {
    const tool = { id: "1", name: "subagent", args: {}, status: toolStatus, nested } as AgentToolLog;
    return progress({ status: parentStatus, tools: [tool] });
  };

  it("shows live elapsed for a running agent", () => {
    const T = 10_000;
    const text = statusText(progress({ startedAt: T }), () => T + 5000, true);
    assert.ok(text.includes("5s"));
    assert.ok(!text.includes("0s"));
  });

  it("shows recorded elapsed for a running agent when not live", () => {
    const T = 10_000;
    const now = () => T + 50_000;
    for (const live of [undefined, false]) {
      const text = statusText(progress({ startedAt: T, elapsedMs: 2000 }), now, live);
      assert.ok(text.includes("2s"));
      assert.ok(!text.includes("50s"));
    }
  });

  it("nested row in a final view shows recorded elapsed", () => {
    const nested = progress({ status: "running", elapsedMs: 3000, startedAt: 1000 });
    const parent = withNested("done", "done", nested);
    const text = nestedStatusText(parent, { live: false, now: () => 1_000_000 });
    assert.ok(text.includes("3s"));
    assert.ok(!text.includes("1000s"));
  });

  it("running nested row in a live view counts from the wall clock", () => {
    const T = 10_000;
    const nested = progress({ status: "running", startedAt: T });
    const parent = withNested("running", "running", nested);
    const text = nestedStatusText(parent, { live: true, now: () => T + 7000 });
    assert.ok(text.includes("7s"));
  });

  it("finished nested tool in a live view stops counting", () => {
    const nested = progress({ status: "running", elapsedMs: 3000, startedAt: 1000 });
    const parent = withNested("running", "done", nested);
    const text = nestedStatusText(parent, { live: true, now: () => 1_000_000 });
    assert.ok(text.includes("3s"));
    assert.ok(!text.includes("1000s"));
  });

  it("shows recorded elapsed for a finished agent", () => {
    const text = statusText(progress({ status: "done", elapsedMs: 87000 }));
    assert.ok(text.includes("1m27s"));
  });
});

describe("trackLiveElapsed", () => {
  it("starts, keeps and clears the interval", () => {
    let calls = 0;
    const state: { elapsedInterval?: ReturnType<typeof setInterval> } = {};
    const context = {
      state,
      invalidate: () => {
        calls += 1;
      },
    };
    mock.timers.enable({ apis: ["setInterval"] });
    try {
      trackLiveElapsed(context as never, true);
      const first = state.elapsedInterval;
      assert.ok(first);
      trackLiveElapsed(context as never, true);
      assert.equal(state.elapsedInterval, first);
      mock.timers.tick(1000);
      assert.equal(calls, 1);
      trackLiveElapsed(context as never, false);
      assert.equal(state.elapsedInterval, undefined);
      mock.timers.tick(1000);
      assert.equal(calls, 1);
    } finally {
      if (state.elapsedInterval) clearInterval(state.elapsedInterval);
      mock.timers.reset();
    }
  });

  it("ignores an undefined context", () => {
    assert.doesNotThrow(() => trackLiveElapsed(undefined, true));
  });
});
