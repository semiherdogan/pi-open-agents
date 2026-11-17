import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it, mock } from "node:test";

import { ACTIVITY_STATUS_KEY, registerActivityStatus } from "../src/primary/activity.ts";

type Handler = (event: { type: string }, ctx: unknown) => void;

function harness(hasUI = true) {
  let t = 0;
  const handlers = new Map<string, Handler>();
  const statuses: Array<string | undefined> = [];
  const ctx = {
    hasUI,
    ui: {
      theme: { fg: (color: string, text: string) => `${color}:${text}` },
      setStatus(key: string, text: string | undefined) {
        assert.equal(key, ACTIVITY_STATUS_KEY);
        statuses.push(text);
      },
    },
  };
  const pi = {
    on(name: string, handler: Handler) {
      handlers.set(name, handler);
    },
  };
  registerActivityStatus(pi as never, { now: () => t });
  return {
    statuses,
    advance(ms: number) {
      t += ms;
    },
    emit(event: { type: string } & Record<string, unknown>) {
      handlers.get(event.type)?.(event, ctx);
    },
    last: () => statuses[statuses.length - 1],
  };
}

const assistantEnd = (extra: Record<string, unknown> = {}) => ({
  type: "message_end",
  message: { role: "assistant", ...extra },
});

describe("registerActivityStatus", () => {
  beforeEach(() => {
    mock.timers.enable({ apis: ["setInterval"] });
  });

  afterEach(() => {
    mock.timers.reset();
  });

  it("shows what the run is waiting on and flags a silent provider", () => {
    const h = harness();
    h.emit({ type: "agent_start" });
    assert.deepEqual(h.statuses, []);
    h.emit({ type: "turn_start" });
    assert.equal(h.last(), "dim:waiting for provider 0s");
    h.advance(31000);
    mock.timers.tick(1000);
    assert.equal(h.last(), "warning:waiting for provider 31s");
  });

  it("tells a responding provider from a silent one", () => {
    const h = harness();
    h.emit({ type: "agent_start" });
    h.emit({ type: "turn_start" });
    h.emit({ type: "after_provider_response", status: 200, headers: {} });
    assert.equal(h.last(), "dim:waiting for first token 0s");
  });

  it("names the running tool, then summarizes the run once settled", () => {
    const h = harness();
    h.emit({ type: "agent_start" });
    h.emit({ type: "turn_start" });
    h.advance(6000);
    h.emit(assistantEnd({ usage: { output: 50 } }));
    h.emit({ type: "tool_execution_start", toolCallId: "t1", toolName: "subagent" });
    assert.equal(h.last(), "dim:running subagent 0s");
    h.advance(3000);
    h.emit({ type: "tool_execution_end", toolCallId: "t1" });
    h.emit({ type: "agent_end", messages: [] });
    h.emit({ type: "agent_settled", aborted: false });
    assert.equal(h.last(), "dim:last run: model 6s (wait 6s) · tools 3s");

    const count = h.statuses.length;
    h.advance(5000);
    mock.timers.tick(5000);
    assert.equal(h.statuses.length, count);
  });

  it("starts the breakdown over for the next run", () => {
    const h = harness();
    h.emit({ type: "agent_start" });
    h.emit({ type: "turn_start" });
    h.advance(6000);
    h.emit(assistantEnd());
    h.emit({ type: "agent_settled", aborted: false });

    h.advance(60000);
    h.emit({ type: "agent_start" });
    h.emit({ type: "turn_start" });
    assert.equal(h.last(), "dim:waiting for provider 0s");
    h.advance(1000);
    h.emit(assistantEnd());
    h.emit({ type: "agent_settled", aborted: false });
    assert.equal(h.last(), "dim:last run: model 1s (wait 1s)");
  });

  it("flags a provider error and keeps counting it across the retry", () => {
    const h = harness();
    h.emit({ type: "agent_start" });
    h.emit({ type: "turn_start" });
    h.advance(2000);
    h.emit(assistantEnd({ stopReason: "error", errorMessage: "503 Service Unavailable" }));
    assert.equal(h.last(), "error:provider error 0s: 503 Service Unavailable");
    h.emit({ type: "agent_end", messages: [] });
    h.advance(4000);
    h.emit({ type: "agent_start" });
    h.emit({ type: "turn_start" });
    assert.equal(h.last(), "dim:waiting for provider 0s · 1 failed");
    h.advance(1000);
    h.emit(assistantEnd());
    h.emit({ type: "agent_settled", aborted: false });
    assert.equal(h.last(), "dim:last run: model 3s (wait 3s) · errors 1 (4s)");
  });

  it("stays silent without a UI", () => {
    const h = harness(false);
    h.emit({ type: "agent_start" });
    h.emit({ type: "turn_start" });
    assert.deepEqual(h.statuses, []);
  });

  it("clears the status and stops ticking on shutdown", () => {
    const h = harness();
    h.emit({ type: "agent_start" });
    h.emit({ type: "turn_start" });
    h.emit({ type: "session_shutdown", reason: "quit" });
    assert.equal(h.last(), undefined);
    const count = h.statuses.length;
    h.advance(5000);
    mock.timers.tick(5000);
    assert.equal(h.statuses.length, count);
  });
});
