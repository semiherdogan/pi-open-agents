/**
 * Text for the timing snapshot: the live "blocked on" label for a running
 * agent and the time breakdown once it is done.
 */

import type { AgentProgress } from "./executor.ts";
import { formatElapsed } from "./elapsed.ts";
import { Phase, StreamKind, type TimingSnapshot, type TimingStreamKind } from "./timing.ts";
import { preview } from "../utils/format.ts";

export type TimingSeverity = "dim" | "warning" | "error";

export interface TimingLine {
  text: string;
  severity: TimingSeverity;
}

/** Provider silence longer than this is flagged as a stall. */
export const STALL_MS = 30_000;
/** A rate over a shorter window is noise. */
const MIN_RATE_WINDOW_MS = 1000;
/** Breakdown parts that would round to 0s are dropped. */
const MIN_PART_MS = 500;
const MS_PER_SECOND = 1000;
const ERROR_PREVIEW_LENGTH = 80;
const RUNNING_STATUS: AgentProgress["status"] = "running";

const STREAM_LABEL: Record<TimingStreamKind, string> = {
  [StreamKind.thinking]: "thinking",
  [StreamKind.text]: "writing",
  [StreamKind.toolcall]: "writing tool call",
};

function tokensPerSecond(tokens: number, ms: number): number | undefined {
  if (tokens <= 0 || ms < MIN_RATE_WINDOW_MS) return undefined;
  return Math.round(tokens / (ms / MS_PER_SECOND));
}

function errorSuffix(message: string | undefined): string {
  if (!message) return "";
  return `: ${preview(message.replace(/\s+/g, " ").trim(), ERROR_PREVIEW_LENGTH)}`;
}

function isStalled(timing: TimingSnapshot, now: number): boolean {
  const onProvider = timing.phase === Phase.waiting || timing.phase === Phase.streaming;
  return onProvider && now - timing.lastEventAt >= STALL_MS;
}

export function timingSeverity(timing: TimingSnapshot, now: number): TimingSeverity {
  if (timing.phase === Phase.retry) return "error";
  return isStalled(timing, now) ? "warning" : "dim";
}

/** What a running agent is blocked on right now, with how long it has been. */
export function formatLivePhase(timing: TimingSnapshot, now: number): string {
  const elapsed = formatElapsed(Math.max(0, now - timing.phaseStartedAt));
  switch (timing.phase) {
    case Phase.startup:
      return `starting ${elapsed}`;
    case Phase.waiting: {
      const target = timing.responded ? "first token" : "provider";
      const failed = timing.failures > 0 ? ` · ${timing.failures} failed` : "";
      return `waiting for ${target} ${elapsed}${failed}`;
    }
    case Phase.streaming: {
      const label = STREAM_LABEL[timing.streamKind ?? StreamKind.text];
      if (isStalled(timing, now)) {
        return `${label} stalled, no data for ${formatElapsed(now - timing.lastEventAt)}`;
      }
      const rate = tokensPerSecond(timing.liveTokens, now - timing.phaseStartedAt);
      const speed =
        rate === undefined ? "" : ` · ${timing.liveTokensEstimated ? "~" : ""}${rate} tok/s`;
      return `${label} ${elapsed}${speed}`;
    }
    case Phase.tool: {
      const [first, ...rest] = timing.runningTools;
      const more = rest.length > 0 ? ` +${rest.length}` : "";
      return `running ${first?.name ?? "tool"}${more} ${elapsed}`;
    }
    case Phase.retry: {
      const max = timing.retryMaxAttempts !== undefined ? `/${timing.retryMaxAttempts}` : "";
      const label =
        timing.retryAttempt !== undefined ? `retry ${timing.retryAttempt}${max}` : "provider error";
      return `${label} ${elapsed}${errorSuffix(timing.lastError)}`;
    }
    case Phase.compaction:
      return `compacting ${elapsed}`;
    case Phase.idle:
      return `finishing ${elapsed}`;
    default:
      return `processing ${elapsed}`;
  }
}

/** Where a finished run spent its time; undefined when nothing is worth showing. */
export function formatTimingSummary(timing: TimingSnapshot): string | undefined {
  const totals = timing.totals;
  const part = (label: string, ms: number): string | undefined =>
    ms >= MIN_PART_MS ? `${label} ${formatElapsed(ms)}` : undefined;
  const present = (value: string | undefined): value is string => value !== undefined;

  const rate = tokensPerSecond(timing.outputTokens, totals.streaming);
  const modelDetail = [
    part("wait", totals.waiting),
    part("stream", totals.streaming),
    rate === undefined ? undefined : `${rate} tok/s`,
  ].filter(present);
  const model = part("model", totals.waiting + totals.streaming);

  const parts = [
    model !== undefined && modelDetail.length > 0 ? `${model} (${modelDetail.join(", ")})` : model,
    part("tools", totals.tool),
    timing.failures > 0
      ? `errors ${timing.failures} (${formatElapsed(totals.retry)})`
      : part("retry", totals.retry),
    part("compaction", totals.compaction),
    part("startup", totals.startup),
    part("other", totals.other),
  ].filter(present);

  return parts.length > 0 ? parts.join(" · ") : undefined;
}

/**
 * The timing line for a result row: the live phase while running, the
 * breakdown once final. A non-live render reads the clock off the snapshot.
 */
export function formatTimingLine(
  progress: Pick<AgentProgress, "status" | "timing">,
  options: { live?: boolean; now?: () => number } = {},
): TimingLine | undefined {
  const timing = progress.timing;
  if (!timing) return undefined;
  if (progress.status !== RUNNING_STATUS) {
    const summary = formatTimingSummary(timing);
    return summary === undefined ? undefined : { text: summary, severity: "dim" };
  }
  const now = options.live ? (options.now ?? Date.now)() : timing.at;
  return { text: formatLivePhase(timing, now), severity: timingSeverity(timing, now) };
}
