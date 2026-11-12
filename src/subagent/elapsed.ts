/**
 * Live elapsed time for the subagent status line.
 *
 * The executor only refreshes elapsedMs when the child emits an event, so a
 * running row recomputes from startedAt and asks the TUI to redraw once a second.
 */

import type { AgentProgress } from "./executor.ts";

const TICK_MS = 1000;
const SECONDS_PER_MINUTE = 60;
const MINUTES_PER_HOUR = 60;

/** Row-local state kept in `ToolRenderContext.state`. */
export interface LiveElapsedState {
  elapsedInterval?: ReturnType<typeof setInterval>;
}

// ToolRenderContext is not exported from the package root, so type the used subset.
export interface LiveElapsedContext {
  state: LiveElapsedState;
  invalidate: () => void;
}

/** Wall-clock elapsed for a running progress; the recorded value once it is final. */
export function liveElapsedMs(progress: AgentProgress, now: () => number = Date.now): number {
  if (progress.status !== "running") return progress.elapsedMs;
  return Math.max(0, now() - progress.startedAt);
}

/** `42s` below a minute, then `1m27s`, then `1h2m3s`. Rounded to whole seconds. */
export function formatElapsed(ms: number): string {
  const totalSeconds = Math.max(0, Math.round(ms / 1000));
  const seconds = totalSeconds % SECONDS_PER_MINUTE;
  const totalMinutes = Math.floor(totalSeconds / SECONDS_PER_MINUTE);
  const minutes = totalMinutes % MINUTES_PER_HOUR;
  const hours = Math.floor(totalMinutes / MINUTES_PER_HOUR);
  if (hours > 0) return `${hours}h${minutes}m${seconds}s`;
  if (totalMinutes > 0) return `${minutes}m${seconds}s`;
  return `${seconds}s`;
}

/**
 * Keep a 1s redraw interval alive while the result is partial, stop it once final.
 * `context.invalidate()` re-runs renderResult, which recomputes the status line.
 */
export function trackLiveElapsed(
  context: LiveElapsedContext | undefined,
  isPartial: boolean,
): void {
  if (!context?.state) return;
  const state = context.state;
  if (isPartial) {
    if (state.elapsedInterval) return;
    const interval = setInterval(() => context.invalidate(), TICK_MS);
    interval.unref?.();
    state.elapsedInterval = interval;
    return;
  }
  if (state.elapsedInterval) {
    clearInterval(state.elapsedInterval);
    state.elapsedInterval = undefined;
  }
}
