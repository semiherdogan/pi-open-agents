/**
 * Agent profile schema: constants, types and strict parsers.
 *
 * Unknown fields and unknown thinking levels are errors: a profile that is
 * silently half-applied is worse than one that is rejected.
 */

import { THINKING_LEVELS } from "../types.ts";
import type { ThinkingLevel } from "../types.ts";

export const PROFILE_PROVIDER = "profile";
export const ESCALATION_SUFFIX = "-escalation";
export const PROFILES_DIR = "profiles";
export const PROFILE_STATE_FILE = "profile-state.json";
export const PROJECT_PROFILE_FILE = "profile.json";
export const PROFILE_FILE_EXTENSION = ".json";

const PROFILE_NAME = /^[A-Za-z0-9_-]+$/;
const VIRTUAL_MODEL_PREFIX = `${PROFILE_PROVIDER}/`;
const ENTRY_FIELDS = ["model", "escalationModel", "thinking"] as const;
const LAYER_FIELDS = ["profile", "agents"] as const;
const STATE_FIELDS = ["active"] as const;

export type ProfileEntry = {
  model: string;
  escalationModel?: string;
  thinking?: ThinkingLevel;
};

export type Profile = Record<string, ProfileEntry>;

export type ProjectLayer = {
  profile?: string;
  agents: Record<string, Partial<ProfileEntry>>;
};

export type ProfileState = {
  active?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function unknownField(obj: Record<string, unknown>, allowed: readonly string[]): string | undefined {
  return Object.keys(obj).find((key) => !allowed.includes(key));
}

function isThinkingLevel(value: unknown): value is ThinkingLevel {
  return typeof value === "string" && (THINKING_LEVELS as readonly string[]).includes(value);
}

export function isProfileName(value: string): boolean {
  return PROFILE_NAME.test(value);
}

export function splitModelRef(ref: string): { provider: string; id: string } | undefined {
  const separator = ref.indexOf("/");
  if (separator <= 0 || separator === ref.length - 1) return undefined;
  return { provider: ref.slice(0, separator), id: ref.slice(separator + 1) };
}

function parsePhysicalModel(agent: string, field: string, value: unknown): string {
  if (
    typeof value !== "string" ||
    /\s/.test(value) ||
    value.startsWith(VIRTUAL_MODEL_PREFIX) ||
    splitModelRef(value) === undefined
  ) {
    throw new Error(`agent ${agent} ${field} must be a physical model in provider/id form`);
  }
  return value;
}

function parseEntryFields(agent: string, raw: unknown): Partial<ProfileEntry> {
  if (!isRecord(raw)) throw new Error(`agent ${agent} must be an object`);
  const unknown = unknownField(raw, ENTRY_FIELDS);
  if (unknown !== undefined) throw new Error(`agent ${agent} has an unknown field: ${unknown}`);

  const fields: Partial<ProfileEntry> = {};
  if (raw.model !== undefined) fields.model = parsePhysicalModel(agent, "model", raw.model);
  if (raw.escalationModel !== undefined) {
    fields.escalationModel = parsePhysicalModel(agent, "escalationModel", raw.escalationModel);
  }
  if (raw.thinking !== undefined) {
    if (!isThinkingLevel(raw.thinking)) {
      throw new Error(`agent ${agent} has an unknown thinking level: ${JSON.stringify(raw.thinking)}`);
    }
    fields.thinking = raw.thinking;
  }
  return fields;
}

export function parseProfile(json: string): Profile {
  const data: unknown = JSON.parse(json);
  if (!isRecord(data)) throw new Error("profile must be a JSON object");

  // fromEntries defines own properties, so a "__proto__" key cannot reach the prototype.
  return Object.fromEntries(
    Object.entries(data).map(([agent, raw]) => {
      if (!isProfileName(agent)) throw new Error(`invalid agent name: ${JSON.stringify(agent)}`);
      const fields = parseEntryFields(agent, raw);
      if (fields.model === undefined) throw new Error(`agent ${agent} needs a model`);
      return [agent, fields as ProfileEntry];
    }),
  );
}

export function parseProjectLayer(json: string): ProjectLayer {
  const data: unknown = JSON.parse(json);
  if (!isRecord(data)) throw new Error("project profile must be a JSON object");
  const unknown = unknownField(data, LAYER_FIELDS);
  if (unknown !== undefined) throw new Error(`unknown field: ${unknown}`);

  const { profile } = data;
  if (profile !== undefined && (typeof profile !== "string" || !isProfileName(profile))) {
    throw new Error("profile must be a profile name");
  }

  const rawAgents = data.agents === undefined ? {} : data.agents;
  if (!isRecord(rawAgents)) throw new Error("agents must be an object");
  const agents = Object.fromEntries(
    Object.entries(rawAgents).map(([agent, raw]) => [agent, parseEntryFields(agent, raw)]),
  );
  return profile === undefined ? { agents } : { profile, agents };
}

export function parseProfileState(json: string): ProfileState {
  const data: unknown = JSON.parse(json);
  if (!isRecord(data)) throw new Error(`profile state must be a JSON object, got ${describe(data)}`);
  const unknown = unknownField(data, STATE_FIELDS);
  if (unknown !== undefined) throw new Error(`unknown field: ${unknown}`);

  const { active } = data;
  if (active === undefined) return {};
  if (typeof active !== "string" || !isProfileName(active)) {
    throw new Error("active must be a profile name");
  }
  return { active };
}
