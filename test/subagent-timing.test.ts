import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { AgentDefinition } from "../src/types.ts";
import type {
  AgentProgress,
  AgentToolLog,
  ExecutorFs,
  PiResolution,
} from "../src/subagent/executor.ts";
import { formatResultLines } from "../src/subagent/render.ts";
import { createTimingTracker, Phase, StreamKind } from "../src/subagent/timing.ts";
import {
  formatLivePhase,
  formatTimingSummary,
  timingSeverity,
} from "../src/subagent/timing-format.ts";

type RunSubagent = typeof import("../src/subagent/executor.ts").runSubagent;

// executor.ts loads the optional pi peer dependency; skip its test where that is absent.
let runSubagent: RunSubagent | undefined;
try {
  ({ runSubagent } = await import("../src/subagent/executor.ts"));
} catch {
  runSubagent = undefined;
}

function clock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
}

const assistant = (extra: Record<string, unknown> = {}) => ({ role: "assistant", ...extra });

const textDelta = (delta: string, extra: Record<string, unknown> = {}) => ({
  type: "message_update",
  assistantMessageEvent: { type: "text_delta", delta },
  ...extra,
});

const providerError = {
  type: "message_end",
  message: assistant({ stopReason: "error", errorMessage: "503 Service Unavailable" }),
};

/** 2s startup, 6s waiting, 4s streaming (200 tokens), 3s in one bash call. */
function finishedRun() {
  const c = clock();
  const tracker = createTimingTracker(c.now);
  c.advance(2000);
  tracker.handle({ type: "agent_start" });
  tracker.handle({ type: "turn_start" });
  c.advance(5000);
  tracker.handle({ type: "message_start", message: assistant() });
  c.advance(1000);
  tracker.handle(textDelta("hello world!"));
  c.advance(4000);
  tracker.handle({ type: "message_end", message: assistant({ usage: { output: 200 } }) });
  tracker.handle({ type: "tool_execution_start", toolCallId: "t1", toolName: "bash" });
  c.advance(3000);
  tracker.handle({ type: "tool_execution_end", toolCallId: "t1" });
  return { c, tracker };
}

function progress(overrides: Partial<AgentProgress> = {}): AgentProgress {
  return {
    agent: "implementer",
    status: "running",
    startedAt: 0,
    elapsedMs: 0,
    tools: [],
    output: "",
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, contextTokens: 0 },
    ...overrides,
  } as AgentProgress;
}

describe("timing tracker", () => {
  it("attributes wall clock to startup, waiting, streaming and tools", () => {
    const snapshot = finishedRun().tracker.snapshot();
    assert.equal(snapshot.phase, Phase.other);
    assert.equal(snapshot.totals.startup, 2000);
    assert.equal(snapshot.totals.waiting, 6000);
    assert.equal(snapshot.totals.streaming, 4000);
    assert.equal(snapshot.totals.tool, 3000);
    assert.equal(snapshot.totals.other, 0);
    assert.equal(snapshot.outputTokens, 200);
    assert.deepEqual(snapshot.toolMs, { t1: 3000 });
  });

  it("marks the provider as responded once the assistant message starts", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    assert.equal(tracker.snapshot().responded, false);
    assert.equal(tracker.handle({ type: "message_start", message: { role: "user" } }), false);
    assert.equal(tracker.handle({ type: "message_start", message: assistant() }), true);
    assert.equal(tracker.snapshot().responded, true);
    tracker.handle({ type: "turn_start" });
    assert.equal(tracker.snapshot().responded, false);
  });

  it("prefers the reported tool duration and skips fast calls", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "tool_execution_start", toolCallId: "slow", toolName: "bash" });
    c.advance(5000);
    tracker.handle({ type: "tool_execution_end", toolCallId: "slow", durationMs: 4200 });
    tracker.handle({ type: "tool_execution_start", toolCallId: "fast", toolName: "read" });
    c.advance(10);
    tracker.handle({ type: "tool_execution_end", toolCallId: "fast" });
    assert.deepEqual(tracker.snapshot().toolMs, { slow: 4200 });
  });

  it("keeps the tool phase until the last parallel call ends", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "tool_execution_start", toolCallId: "a", toolName: "bash" });
    c.advance(1000);
    tracker.handle({ type: "tool_execution_start", toolCallId: "b", toolName: "read" });
    c.advance(1000);
    tracker.handle({ type: "tool_execution_end", toolCallId: "a" });
    assert.equal(tracker.snapshot().phase, Phase.tool);
    assert.deepEqual(
      tracker.snapshot().runningTools.map((tool) => tool.id),
      ["b"],
    );
    c.advance(2000);
    tracker.handle({ type: "tool_execution_end", toolCallId: "b" });
    const snapshot = tracker.snapshot();
    assert.equal(snapshot.phase, Phase.other);
    assert.equal(snapshot.totals.tool, 4000);
  });

  it("tracks provider errors and retry attempts", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    c.advance(3000);
    assert.equal(tracker.handle(providerError), true);
    assert.equal(tracker.handle({ type: "agent_end", messages: [], willRetry: true }), false);
    tracker.handle({
      type: "auto_retry_start",
      attempt: 1,
      maxAttempts: 3,
      delayMs: 2000,
      errorMessage: "503 Service Unavailable",
    });
    let snapshot = tracker.snapshot();
    assert.equal(snapshot.phase, Phase.retry);
    assert.equal(snapshot.failures, 1);
    assert.equal(snapshot.lastError, "503 Service Unavailable");
    assert.equal(snapshot.retryAttempt, 1);
    assert.equal(snapshot.retryMaxAttempts, 3);

    c.advance(2000);
    assert.equal(tracker.handle({ type: "agent_start" }), false);
    assert.equal(tracker.snapshot().phase, Phase.retry);
    tracker.handle({ type: "turn_start" });
    assert.equal(tracker.snapshot().phase, Phase.waiting);

    c.advance(1000);
    tracker.handle(providerError);
    tracker.handle({ type: "agent_end", messages: [], willRetry: false });
    snapshot = tracker.snapshot();
    assert.equal(snapshot.phase, Phase.other);
    assert.equal(snapshot.failures, 2);
    assert.equal(snapshot.totals.retry, 2000);
    assert.equal(snapshot.totals.waiting, 4000);
    assert.equal(formatTimingSummary(snapshot), "model 4s (wait 4s) · errors 2 (2s)");
  });

  it("reports streaming progress at most once per interval", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    assert.equal(tracker.handle(textDelta("a")), true);
    assert.equal(tracker.handle(textDelta("b")), false);
    c.advance(999);
    assert.equal(tracker.handle(textDelta("c")), false);
    c.advance(1);
    assert.equal(tracker.handle(textDelta("d")), true);
  });

  it("reports a change of stream kind at once", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    tracker.handle({
      type: "message_update",
      assistantMessageEvent: { type: "thinking_delta", delta: "hm" },
    });
    assert.equal(tracker.snapshot().streamKind, StreamKind.thinking);
    assert.equal(tracker.handle(textDelta("answer")), true);
    assert.equal(tracker.snapshot().streamKind, StreamKind.text);
  });

  it("estimates live tokens from text until the provider reports usage", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    tracker.handle(textDelta("x".repeat(40), { usage: { output: 0 } }));
    let snapshot = tracker.snapshot();
    assert.equal(snapshot.liveTokens, 10);
    assert.equal(snapshot.liveTokensEstimated, true);
    tracker.handle(textDelta("x", { usage: { output: 25 } }));
    snapshot = tracker.snapshot();
    assert.equal(snapshot.liveTokens, 25);
    assert.equal(snapshot.liveTokensEstimated, false);
  });

  it("ignores a placeholder usage count while text keeps streaming", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    tracker.handle(textDelta("x".repeat(400), { usage: { output: 1 } }));
    c.advance(2000);
    const snapshot = tracker.snapshot();
    assert.equal(snapshot.liveTokens, 100);
    assert.equal(snapshot.liveTokensEstimated, true);
    assert.equal(formatLivePhase(snapshot, c.now()), "writing 2s · ~50 tok/s");
  });

  it("caps the stored provider error", () => {
    const tracker = createTimingTracker(() => 0, Phase.other);
    tracker.handle({ type: "turn_start" });
    tracker.handle({
      type: "message_end",
      message: assistant({ stopReason: "error", errorMessage: "x".repeat(5000) }),
    });
    assert.equal(tracker.snapshot().lastError?.length, 300);
  });

  it("accepts extension event shapes", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.idle);
    tracker.handle({ type: "agent_start" });
    tracker.handle({ type: "turn_start" });
    assert.equal(tracker.handle({ type: "after_provider_response", status: 200, headers: {} }), true);
    assert.equal(tracker.handle({ type: "after_provider_response", status: 200, headers: {} }), false);
    assert.equal(tracker.snapshot().responded, true);
    tracker.handle({
      type: "message_update",
      message: assistant({ usage: { output: 12 } }),
      assistantMessageEvent: { type: "thinking_delta", delta: "hm" },
    });
    const snapshot = tracker.snapshot();
    assert.equal(snapshot.liveTokens, 12);
    assert.equal(snapshot.streamKind, StreamKind.thinking);
    assert.equal(tracker.handle({ type: "agent_settled", aborted: false }), true);
    assert.equal(tracker.snapshot().phase, Phase.idle);
  });

  it("ignores values that are not session events", () => {
    const tracker = createTimingTracker(() => 0);
    assert.equal(tracker.handle(undefined), false);
    assert.equal(tracker.handle("agent_start"), false);
    assert.equal(tracker.handle({}), false);
    assert.equal(tracker.handle({ type: "entry_appended" }), false);
    assert.equal(tracker.snapshot().phase, Phase.startup);
  });
});

describe("formatLivePhase", () => {
  it("separates a silent provider from a pending first token", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    c.advance(2000);
    assert.equal(formatLivePhase(tracker.snapshot(), c.now()), "waiting for provider 2s");
    tracker.handle({ type: "message_start", message: assistant() });
    c.advance(3000);
    assert.equal(formatLivePhase(tracker.snapshot(), c.now()), "waiting for first token 5s");
  });

  it("flags a provider that stays silent", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    c.advance(14000);
    assert.equal(timingSeverity(tracker.snapshot(), c.now()), "dim");
    c.advance(17000);
    const snapshot = tracker.snapshot();
    assert.equal(formatLivePhase(snapshot, c.now()), "waiting for provider 31s");
    assert.equal(timingSeverity(snapshot, c.now()), "warning");
  });

  it("shows the token rate while streaming", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    tracker.handle(textDelta("x".repeat(400)));
    c.advance(2000);
    assert.equal(formatLivePhase(tracker.snapshot(), c.now()), "writing 2s · ~50 tok/s");
    tracker.handle(textDelta("", { usage: { output: 120 } }));
    assert.equal(formatLivePhase(tracker.snapshot(), c.now()), "writing 2s · 60 tok/s");
  });

  it("flags a stream that stops sending data", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    tracker.handle(textDelta("partial"));
    c.advance(40000);
    const snapshot = tracker.snapshot();
    assert.equal(formatLivePhase(snapshot, c.now()), "writing stalled, no data for 40s");
    assert.equal(timingSeverity(snapshot, c.now()), "warning");
  });

  it("names the running tool and counts parallel calls", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "tool_execution_start", toolCallId: "a", toolName: "bash" });
    tracker.handle({ type: "tool_execution_start", toolCallId: "b", toolName: "read" });
    c.advance(22000);
    const snapshot = tracker.snapshot();
    assert.equal(formatLivePhase(snapshot, c.now()), "running bash +1 22s");
    assert.equal(timingSeverity(snapshot, c.now()), "dim");
  });

  it("shows the provider error, with the retry attempt when known", () => {
    const c = clock();
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    tracker.handle(providerError);
    c.advance(1000);
    let snapshot = tracker.snapshot();
    assert.equal(formatLivePhase(snapshot, c.now()), "provider error 1s: 503 Service Unavailable");
    assert.equal(timingSeverity(snapshot, c.now()), "error");

    tracker.handle({ type: "auto_retry_start", attempt: 2, maxAttempts: 3, errorMessage: "503\n  down" });
    c.advance(1000);
    snapshot = tracker.snapshot();
    assert.equal(formatLivePhase(snapshot, c.now()), "retry 2/3 2s: 503 down");

    tracker.handle({ type: "agent_start" });
    tracker.handle({ type: "turn_start" });
    assert.equal(formatLivePhase(tracker.snapshot(), c.now()), "waiting for provider 0s · 1 failed");
  });
});

describe("formatTimingSummary", () => {
  it("breaks a finished run down by phase", () => {
    assert.equal(
      formatTimingSummary(finishedRun().tracker.snapshot()),
      "model 10s (wait 6s, stream 4s, 50 tok/s) · tools 3s · startup 2s",
    );
  });

  it("returns nothing when no phase took measurable time", () => {
    assert.equal(formatTimingSummary(createTimingTracker(() => 0, Phase.idle).snapshot()), undefined);
  });
});

describe("formatResultLines with timing", () => {
  it("adds the breakdown under the status line and a duration to slow tools", () => {
    const tools: AgentToolLog[] = [
      { id: "t1", name: "bash", args: { command: "sleep 3" }, status: "done" },
    ];
    const lines = formatResultLines(
      progress({ status: "done", tools, timing: finishedRun().tracker.snapshot() }),
      { expanded: false },
    );
    const statusIndex = lines.findIndex((line) => line.kind === "status");
    assert.deepEqual(lines[statusIndex + 1], {
      text: "  model 10s (wait 6s, stream 4s, 50 tok/s) · tools 3s · startup 2s",
      kind: "timing",
      singleLine: true,
      severity: "dim",
    });
    const toolLine = lines.find((line) => line.kind === "tool");
    assert.equal(toolLine?.text, "  $ sleep 3 3s");
    assert.equal(toolLine?.tool?.durationMs, 3000);
  });

  it("shows the live phase while running", () => {
    const c = clock(1000);
    const tracker = createTimingTracker(c.now, Phase.other);
    tracker.handle({ type: "turn_start" });
    const running = progress({ timing: tracker.snapshot() });
    const timingText = (options: { live?: boolean; now?: () => number }) =>
      formatResultLines(running, { expanded: false, ...options }).find(
        (line) => line.kind === "timing",
      )?.text;
    assert.equal(timingText({ live: true, now: () => 15000 }), "  waiting for provider 14s");
    assert.equal(timingText({}), "  waiting for provider 0s");
  });

  it("adds no line for progress without timing", () => {
    const lines = formatResultLines(progress({ status: "done" }), { expanded: false });
    assert.equal(
      lines.some((line) => line.kind === "timing"),
      false,
    );
  });
});

describe("runSubagent timing", () => {
  const agent: AgentDefinition = {
    name: "worker",
    mode: "subagent",
    hidden: true,
    disable: false,
    thinking: "off",
    systemPrompt: "replace",
    maxDepth: 1,
    prompt: "You are a worker subagent.",
    source: "project",
    filePath: "/tmp/worker.agent.md",
  };

  const fakeFs: ExecutorFs = {
    makeTempDir: async () => "/tmp/fake-subagent",
    writeFile: async () => {},
    removeDir: async () => {},
  };

  const fakeResolvePi = async (): Promise<PiResolution> => ({
    command: "node",
    entryPoint: "/fake/cli.js",
  });

  (runSubagent ? it : it.skip)("attaches timing to progress and to the result", async () => {
    const c = clock(1000);
    const steps: Array<[number, object]> = [
      [2000, { type: "agent_start" }],
      [0, { type: "turn_start" }],
      [5000, { type: "message_start", message: { role: "assistant" } }],
      [1000, textDelta("done")],
      [
        4000,
        {
          type: "message_end",
          message: {
            role: "assistant",
            content: [{ type: "text", text: "done" }],
            usage: { output: 100 },
          },
        },
      ],
      [0, { type: "agent_end", messages: [], willRetry: false }],
    ];
    const phases: string[] = [];

    const result = await runSubagent!({
      agent,
      task: "Task: say done",
      cwd: process.cwd(),
      now: c.now,
      fs: fakeFs,
      resolvePi: fakeResolvePi,
      runner: async (_invocation, handlers) => {
        for (const [ms, event] of steps) {
          c.advance(ms);
          handlers.stdout(`${JSON.stringify(event)}\n`);
        }
        return { exitCode: 0 };
      },
      onProgress: (update) => {
        if (update.timing) phases.push(update.timing.phase);
      },
    });

    assert.equal(result.output, "done");
    assert.equal(result.timing?.totals.startup, 2000);
    assert.equal(result.timing?.totals.waiting, 6000);
    assert.equal(result.timing?.totals.streaming, 4000);
    assert.equal(result.timing?.outputTokens, 100);
    assert.ok(phases.includes(Phase.waiting));
    assert.ok(phases.includes(Phase.streaming));
  });
});
