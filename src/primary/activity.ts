/**
 * Footer status for the primary agent: what the run is blocked on right now
 * (the provider, the first token, a tool, a retry) and where the last run
 * spent its time.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import {
  createTimingTracker,
  Phase,
  TimingEventType,
  type TimingTracker,
} from "../subagent/timing.ts";
import {
  formatLivePhase,
  formatTimingSummary,
  timingSeverity,
} from "../subagent/timing-format.ts";

export const ACTIVITY_STATUS_KEY = "open-agents-activity";

const TICK_MS = 1000;
const LAST_RUN_PREFIX = "last run: ";
const SHUTDOWN_EVENT = "session_shutdown";

export interface ActivityStatusOptions {
  now?: () => number;
}

export function registerActivityStatus(
  pi: ExtensionAPI,
  options: ActivityStatusOptions = {},
): void {
  const now = options.now ?? Date.now;
  let tracker: TimingTracker = createTimingTracker(now, Phase.idle);
  let latest: ExtensionContext | undefined;
  let interval: ReturnType<typeof setInterval> | undefined;
  let shown: string | undefined;

  const show = (ctx: ExtensionContext, text: string | undefined) => {
    if (text === shown) return;
    shown = text;
    ctx.ui.setStatus(ACTIVITY_STATUS_KEY, text);
  };

  const stopTicking = () => {
    if (!interval) return;
    clearInterval(interval);
    interval = undefined;
  };

  const refresh = () => {
    const ctx = latest;
    if (!ctx) return;
    const timing = tracker.snapshot();
    if (timing.phase === Phase.idle) {
      stopTicking();
      const summary = formatTimingSummary(timing);
      show(
        ctx,
        summary === undefined ? undefined : ctx.ui.theme.fg("dim", `${LAST_RUN_PREFIX}${summary}`),
      );
      return;
    }
    // The elapsed part of the label only moves with the clock, not with events.
    if (!interval) {
      interval = setInterval(refresh, TICK_MS);
      interval.unref?.();
    }
    show(
      ctx,
      ctx.ui.theme.fg(timingSeverity(timing, timing.at), formatLivePhase(timing, timing.at)),
    );
  };

  const feed = (event: { type: string }, ctx: ExtensionContext) => {
    if (!ctx.hasUI) return;
    // Retries restart the agent inside one run, so only an idle tracker starts over.
    if (event.type === TimingEventType.agentStart && tracker.snapshot().phase === Phase.idle) {
      tracker = createTimingTracker(now, Phase.other);
    }
    if (!tracker.handle(event)) return;
    latest = ctx;
    refresh();
  };

  pi.on(TimingEventType.agentStart, feed);
  pi.on(TimingEventType.agentEnd, feed);
  pi.on(TimingEventType.agentSettled, feed);
  pi.on(TimingEventType.turnStart, feed);
  pi.on(TimingEventType.messageStart, feed);
  pi.on(TimingEventType.messageUpdate, feed);
  pi.on(TimingEventType.messageEnd, feed);
  pi.on(TimingEventType.toolStart, feed);
  pi.on(TimingEventType.toolEnd, feed);
  pi.on(TimingEventType.providerResponse, feed);

  pi.on(SHUTDOWN_EVENT, (_event, ctx) => {
    stopTicking();
    latest = undefined;
    shown = undefined;
    if (ctx.hasUI) ctx.ui.setStatus(ACTIVITY_STATUS_KEY, undefined);
  });
}
