/**
 * Phase timing for an agent run: where the wall clock goes (provider wait,
 * streaming, tools, retries) and what the run is blocked on right now.
 *
 * A pure state machine over pi session events. The subagent executor feeds it
 * the child's JSON stream, the primary activity status feeds it extension events.
 */

export const Phase = {
  startup: "startup",
  waiting: "waiting",
  streaming: "streaming",
  tool: "tool",
  retry: "retry",
  compaction: "compaction",
  other: "other",
  idle: "idle",
} as const;

export type TimingPhase = (typeof Phase)[keyof typeof Phase];

export const StreamKind = {
  thinking: "thinking",
  text: "text",
  toolcall: "toolcall",
} as const;

export type TimingStreamKind = (typeof StreamKind)[keyof typeof StreamKind];

/** Event names shared by the JSON stream and the extension API. */
export const TimingEventType = {
  agentStart: "agent_start",
  agentEnd: "agent_end",
  agentSettled: "agent_settled",
  turnStart: "turn_start",
  messageStart: "message_start",
  messageUpdate: "message_update",
  messageEnd: "message_end",
  toolStart: "tool_execution_start",
  toolEnd: "tool_execution_end",
  retryStart: "auto_retry_start",
  retryEnd: "auto_retry_end",
  compactionStart: "compaction_start",
  compactionEnd: "compaction_end",
  providerResponse: "after_provider_response",
} as const;

const ASSISTANT_ROLE = "assistant";
const ERROR_STOP_REASON = "error";
const FALLBACK_TOOL_NAME = "tool";

/** Streaming reports are throttled to this interval; each one re-renders the row. */
const REPORT_INTERVAL_MS = 1000;
/** Tool calls faster than this get no duration label. */
export const TOOL_DURATION_MIN_MS = 1000;
/** Rough text length per token, for providers that report usage only at the end. */
const CHARS_PER_TOKEN = 4;
/** Gateway error bodies can be whole HTML pages, and the snapshot is copied on every report. */
const ERROR_MAX_LENGTH = 300;

export interface TimingRunningTool {
  id: string;
  name: string;
  startedAt: number;
}

export interface TimingSnapshot {
  phase: TimingPhase;
  phaseStartedAt: number;
  lastEventAt: number;
  /** Clock value the snapshot was taken at; totals include the open phase up to here. */
  at: number;
  totals: Record<TimingPhase, number>;
  /** Waiting only: the provider answered, the first token is still pending. */
  responded: boolean;
  streamKind?: TimingStreamKind;
  /** Output tokens of the message being streamed; estimated from text length when that exceeds the provider's count. */
  liveTokens: number;
  liveTokensEstimated: boolean;
  /** Output tokens of completed assistant messages. */
  outputTokens: number;
  runningTools: TimingRunningTool[];
  /** Duration per tool call id, only for calls slow enough to label. */
  toolMs: Record<string, number>;
  retryAttempt?: number;
  retryMaxAttempts?: number;
  /** Provider errors seen during the run. */
  failures: number;
  lastError?: string;
}

export interface TimingTracker {
  /** Feed one session event. Returns true when the change is worth a progress report. */
  handle(event: unknown): boolean;
  snapshot(): TimingSnapshot;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : undefined;
}

function numberField(source: Record<string, unknown> | undefined, key: string): number | undefined {
  const value = source?.[key];
  return typeof value === "number" ? value : undefined;
}

function stringField(source: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = source?.[key];
  return typeof value === "string" ? value : undefined;
}

function errorField(source: Record<string, unknown> | undefined, key: string): string | undefined {
  return stringField(source, key)?.slice(0, ERROR_MAX_LENGTH);
}

function streamKindOf(type: unknown): TimingStreamKind | undefined {
  if (typeof type !== "string") return undefined;
  return Object.values(StreamKind).find((kind) => type.startsWith(`${kind}_`));
}

function emptyTotals(): Record<TimingPhase, number> {
  return Object.fromEntries(Object.values(Phase).map((phase) => [phase, 0])) as Record<
    TimingPhase,
    number
  >;
}

export function createTimingTracker(
  now: () => number = Date.now,
  initialPhase: TimingPhase = Phase.startup,
): TimingTracker {
  let phase: TimingPhase = initialPhase;
  let phaseStartedAt = now();
  let lastEventAt = phaseStartedAt;
  let lastReportAt = phaseStartedAt;
  const totals = emptyTotals();
  let responded = false;
  let streamKind: TimingStreamKind | undefined;
  let streamChars = 0;
  let reportedTokens = 0;
  let outputTokens = 0;
  const running = new Map<string, { name: string; startedAt: number }>();
  const toolMs: Record<string, number> = {};
  let retryAttempt: number | undefined;
  let retryMaxAttempts: number | undefined;
  let failures = 0;
  let lastError: string | undefined;

  const enter = (next: TimingPhase, at: number): boolean => {
    if (next === phase) return false;
    totals[phase] += Math.max(0, at - phaseStartedAt);
    phase = next;
    phaseStartedAt = at;
    return true;
  };

  const resetStream = () => {
    streamKind = undefined;
    streamChars = 0;
    reportedTokens = 0;
  };

  const apply = (event: Record<string, unknown>, type: string, at: number): boolean => {
    switch (type) {
      case TimingEventType.agentStart:
        // A retried run restarts the agent; keep the retry phase until its turn starts.
        return phase === Phase.retry ? false : enter(Phase.other, at);
      case TimingEventType.turnStart:
        responded = false;
        resetStream();
        return enter(Phase.waiting, at);
      case TimingEventType.providerResponse:
        if (phase !== Phase.waiting || responded) return false;
        responded = true;
        return true;
      case TimingEventType.messageStart: {
        if (asRecord(event.message)?.role !== ASSISTANT_ROLE) return false;
        const entered = enter(Phase.waiting, at);
        const flipped = !responded;
        responded = true;
        return entered || flipped;
      }
      case TimingEventType.messageUpdate: {
        const inner = asRecord(event.assistantMessageEvent);
        const kind = streamKindOf(inner?.type);
        const delta = inner?.delta;
        if (typeof delta === "string") streamChars += delta.length;
        // The JSON stream carries usage at the top level, extension events inside the message.
        const reported =
          numberField(asRecord(event.usage), "output") ??
          numberField(asRecord(asRecord(event.message)?.usage), "output");
        if (reported !== undefined && reported > 0) reportedTokens = reported;
        const kindChanged = kind !== undefined && kind !== streamKind;
        if (kind !== undefined) streamKind = kind;
        return enter(Phase.streaming, at) || kindChanged;
      }
      case TimingEventType.messageEnd: {
        const message = asRecord(event.message);
        if (message?.role !== ASSISTANT_ROLE) return false;
        resetStream();
        if (message.stopReason === ERROR_STOP_REASON) {
          failures++;
          lastError = errorField(message, "errorMessage") ?? lastError;
          enter(Phase.retry, at);
          return true;
        }
        outputTokens += numberField(asRecord(message.usage), "output") ?? 0;
        retryAttempt = undefined;
        retryMaxAttempts = undefined;
        enter(Phase.other, at);
        return true;
      }
      case TimingEventType.toolStart: {
        const id = String(event.toolCallId ?? running.size);
        running.set(id, {
          name: stringField(event, "toolName") ?? FALLBACK_TOOL_NAME,
          startedAt: at,
        });
        enter(Phase.tool, at);
        return true;
      }
      case TimingEventType.toolEnd: {
        const id = String(event.toolCallId ?? "");
        const started = running.get(id);
        running.delete(id);
        const duration =
          numberField(event, "durationMs") ?? (started ? at - started.startedAt : undefined);
        if (duration !== undefined && duration >= TOOL_DURATION_MIN_MS) {
          toolMs[id] = Math.round(duration);
        }
        // Parallel calls share one tool phase, so the total is wall clock, not a sum.
        if (running.size === 0) enter(Phase.other, at);
        return true;
      }
      case TimingEventType.retryStart:
        retryAttempt = numberField(event, "attempt");
        retryMaxAttempts = numberField(event, "maxAttempts");
        lastError = errorField(event, "errorMessage") ?? lastError;
        enter(Phase.retry, at);
        return true;
      case TimingEventType.retryEnd:
        retryAttempt = undefined;
        retryMaxAttempts = undefined;
        lastError = errorField(event, "finalError") ?? lastError;
        return phase === Phase.retry ? enter(Phase.other, at) : false;
      case TimingEventType.compactionStart:
        return enter(Phase.compaction, at);
      case TimingEventType.compactionEnd:
        return phase === Phase.compaction ? enter(Phase.other, at) : false;
      case TimingEventType.agentEnd:
        if (phase === Phase.compaction) return false;
        // The failed run ends before its backoff; only an explicit "no retry" leaves the phase.
        if (phase === Phase.retry && event.willRetry !== false) return false;
        running.clear();
        return enter(Phase.other, at);
      case TimingEventType.agentSettled:
        running.clear();
        return enter(Phase.idle, at);
      default:
        return false;
    }
  };

  return {
    handle(raw) {
      const event = asRecord(raw);
      const type = event?.type;
      if (!event || typeof type !== "string") return false;
      const at = now();
      lastEventAt = at;
      const changed = apply(event, type, at);
      const due = phase === Phase.streaming && at - lastReportAt >= REPORT_INTERVAL_MS;
      if (!changed && !due) return false;
      lastReportAt = at;
      return true;
    },

    snapshot() {
      const at = now();
      const open = { ...totals };
      open[phase] += Math.max(0, at - phaseStartedAt);
      // Some providers report a placeholder count until the message ends; trust the larger one.
      const estimatedTokens = Math.ceil(streamChars / CHARS_PER_TOKEN);
      return {
        phase,
        phaseStartedAt,
        lastEventAt,
        at,
        totals: open,
        responded,
        ...(streamKind !== undefined ? { streamKind } : {}),
        liveTokens: Math.max(reportedTokens, estimatedTokens),
        liveTokensEstimated: estimatedTokens > reportedTokens,
        outputTokens,
        runningTools: [...running].map(([id, tool]) => ({ id, ...tool })),
        toolMs: { ...toolMs },
        ...(retryAttempt !== undefined ? { retryAttempt } : {}),
        ...(retryMaxAttempts !== undefined ? { retryMaxAttempts } : {}),
        failures,
        ...(lastError !== undefined ? { lastError } : {}),
      };
    },
  };
}
