/**
 * Human-readable summary of a resolved profile, shown by `/profile` after a
 * switch. Pure so every branch is testable without a session.
 */

import type { Profile, ProfileEntry } from "./schema.ts";

export const PROJECT_OVERRIDE_NOTE = "project override: .pi/profile.json";
export const PINNED_HEADER = "Pinned by frontmatter (not following the profile):";

const PART_SEPARATOR = " · ";

export interface PinnedAgent {
  name: string;
  model: string;
  filePath: string;
}

export interface ProfileSummaryInput {
  /** Profile selected for this summary (the project layer's choice when it names one). */
  name: string;
  /** A project layer is active, whatever profile it names. */
  projectOverride: boolean;
  profile: Profile;
  /** Loaded agents with a frontmatter model that the profile would otherwise route. */
  pinned: PinnedAgent[];
  /** Set when `.pi/profile.json` selects its own profile. */
  layerProfile?: string;
  /** Global selection, named in the note when the project layer selects its own profile. */
  globalProfile?: string;
}

function entryLine(agent: string, entry: ProfileEntry): string {
  let line = `${agent}: ${entry.model}`;
  if (entry.thinking !== undefined) line += `${PART_SEPARATOR}${entry.thinking}`;
  if (entry.escalationModel !== undefined) line += ` (escalation: ${entry.escalationModel})`;
  return line;
}

export function buildProfileSummary(input: ProfileSummaryInput): string {
  const header = input.projectOverride
    ? `Profile ${input.name} (${PROJECT_OVERRIDE_NOTE})`
    : `Profile ${input.name}`;
  const lines = [header];
  for (const [agent, entry] of Object.entries(input.profile)) {
    lines.push(entryLine(agent, entry));
  }
  if (input.pinned.length > 0) {
    lines.push(PINNED_HEADER);
    for (const pinned of input.pinned) {
      lines.push(`${pinned.name}: ${pinned.model} (${pinned.filePath})`);
    }
  }
  if (input.layerProfile !== undefined) {
    const global = input.globalProfile === undefined ? "" : ` (${input.globalProfile})`;
    lines.push(
      `.pi/profile.json selects ${input.layerProfile} in this project; the global selection${global} applies elsewhere.`,
    );
  }
  return lines.join("\n");
}
