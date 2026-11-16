/**
 * `/permissions init`: creates the project policy file from a starter
 * template. The only permission command code that writes a policy file.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

import { ALL_AGENTS_KEY, POLICY_VERSION, projectPolicyPath } from "./loader.ts";

const ALREADY_EXISTS = "EEXIST";
// Exclusive create: an existing file (or one that appears meanwhile) is never overwritten.
const EXCLUSIVE_CREATE = "wx";
const INDENT = 4;

export const INIT_STATUS = {
  created: "created",
  exists: "exists",
} as const;

export type InitStatus = (typeof INIT_STATUS)[keyof typeof INIT_STATUS];

export interface InitResult {
  path: string;
  status: InitStatus;
}

// Grants nothing: the empty bash map only shows where prefix rules go.
export const PROJECT_POLICY_TEMPLATE = {
  version: POLICY_VERSION,
  agents: { [ALL_AGENTS_KEY]: { bash: {} } },
};

export function initProjectPolicy(cwd: string): InitResult {
  const filePath = projectPolicyPath(cwd);
  // Outside the try: EEXIST from mkdir means `.pi` is a file, which is a failure, not an existing policy.
  mkdirSync(path.dirname(filePath), { recursive: true });
  try {
    writeFileSync(filePath, `${JSON.stringify(PROJECT_POLICY_TEMPLATE, null, INDENT)}\n`, { flag: EXCLUSIVE_CREATE });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === ALREADY_EXISTS) return { path: filePath, status: INIT_STATUS.exists };
    throw error;
  }
  return { path: filePath, status: INIT_STATUS.created };
}
