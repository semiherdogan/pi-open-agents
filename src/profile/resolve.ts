/**
 * Profile resolution: layer application, route naming and subagent model checks.
 *
 * All functions are pure so a router can call them on every request.
 */

import type { ThinkingLevel } from "../types.ts";
import type { Profile, ProfileEntry, ProjectLayer } from "./schema.ts";
import { ESCALATION_SUFFIX, PROFILE_PROVIDER, splitModelRef } from "./schema.ts";

export { splitModelRef };

export function virtualModelRef(key: string): string {
  return `${PROFILE_PROVIDER}/${key}`;
}

function mergeEntry(base: ProfileEntry, override: Partial<ProfileEntry>): ProfileEntry {
  const merged: ProfileEntry = { ...base };
  if (override.model !== undefined) merged.model = override.model;
  if (override.escalationModel !== undefined) merged.escalationModel = override.escalationModel;
  if (override.thinking !== undefined) merged.thinking = override.thinking;
  return merged;
}

/** Overrides that name an agent the base profile lacks and carry no model of their own. */
export function incompleteOverrides(base: Profile, layer: ProjectLayer | undefined): string[] {
  if (layer === undefined) return [];
  const skipped: string[] = [];
  for (const [agent, override] of Object.entries(layer.agents)) {
    if (override.model === undefined && !Object.hasOwn(base, agent)) skipped.push(agent);
  }
  return skipped;
}

export function applyLayer(base: Profile, layer: ProjectLayer | undefined): Profile {
  const merged = new Map<string, ProfileEntry>(
    Object.entries(base).map(([agent, entry]) => [agent, { ...entry }]),
  );
  if (layer === undefined) return Object.fromEntries(merged);

  for (const [agent, override] of Object.entries(layer.agents)) {
    const current = merged.get(agent);
    if (current === undefined) {
      // An incomplete override cannot introduce an agent. Skipping it keeps
      // every other route of the profile alive; only this key stays missing.
      if (override.model === undefined) continue;
      merged.set(agent, mergeEntry({ model: override.model }, override));
      continue;
    }
    merged.set(agent, mergeEntry(current, override));
  }
  return Object.fromEntries(merged);
}

export function routeKeys(profile: Profile): string[] {
  const keys: string[] = [];
  for (const [agent, entry] of Object.entries(profile)) {
    keys.push(agent);
    if (entry.escalationModel !== undefined) keys.push(agent + ESCALATION_SUFFIX);
  }
  return keys;
}

function route(model: string, thinking: ThinkingLevel | undefined): { model: string; thinking?: ThinkingLevel } {
  return thinking === undefined ? { model } : { model, thinking };
}

export function lookupRoute(
  profile: Profile,
  key: string,
): { model: string; thinking?: ThinkingLevel } | undefined {
  // A plain agent name wins even when it ends with the escalation suffix.
  if (Object.hasOwn(profile, key)) {
    const entry = profile[key];
    return route(entry.model, entry.thinking);
  }

  if (!key.endsWith(ESCALATION_SUFFIX)) return undefined;
  const agent = key.slice(0, -ESCALATION_SUFFIX.length);
  const entry: ProfileEntry | undefined = Object.hasOwn(profile, agent) ? profile[agent] : undefined;
  if (entry?.escalationModel === undefined) return undefined;
  return route(entry.escalationModel, entry.thinking);
}

export function subagentModelViolation(model: unknown, allowedKeys: readonly string[]): string | undefined {
  if (model === undefined) return undefined;

  const prefix = `${PROFILE_PROVIDER}/`;
  if (typeof model === "string" && model.startsWith(prefix) && allowedKeys.includes(model.slice(prefix.length))) {
    return undefined;
  }

  const allowed = allowedKeys.map(virtualModelRef);
  return `subagent model ${JSON.stringify(model)} is not allowed; omit it or use one of: ${allowed.join(", ")}`;
}
