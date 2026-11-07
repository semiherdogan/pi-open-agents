/**
 * Tool path normalization for the policy gate.
 *
 * Mirrors pi's file-tool path resolution so the gate checks the same file the
 * tool will touch, then expands it into the spellings rules may be written in.
 */

import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalPath } from "./resolver.ts";

// Same set as pi's utils/paths.ts UNICODE_SPACES.
const UNICODE_SPACES = /[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g;
const AT_PREFIX = "@";
const HOME = "~";
const HOME_PREFIX = "~/";
const FILE_URL = /^file:\/\//;
const PARENT_DIR = "..";
const CURRENT_DIR = ".";
const POSIX_SEPARATOR = "/";

export interface PathCandidateOptions {
  home?: string;
  realpath?: (p: string) => string;
}

function expandTilde(value: string, home: string): string {
  if (value === HOME) return home;
  if (value.startsWith(HOME_PREFIX)) return path.join(home, value.slice(HOME_PREFIX.length));
  if (FILE_URL.test(value)) return fileURLToPath(value);
  return value;
}

/** Absolute lexical path, resolved exactly like pi's resolveToCwd (win32 drive rewriting excluded). */
export function normalizeToolPath(arg: string, cwd: string, home: string): string {
  let normalized = arg.replace(UNICODE_SPACES, " ");
  if (normalized.startsWith(AT_PREFIX)) normalized = normalized.slice(AT_PREFIX.length);
  normalized = expandTilde(normalized, home);
  if (path.isAbsolute(normalized)) return path.resolve(normalized);
  return path.resolve(expandTilde(cwd, home), normalized);
}

function relativeInside(root: string, target: string): string | undefined {
  const rel = path.relative(root, target);
  if (rel === "") return CURRENT_DIR;
  if (rel === PARENT_DIR || rel.startsWith(PARENT_DIR + path.sep) || path.isAbsolute(rel)) return undefined;
  return rel.split(path.sep).join(POSIX_SEPARATOR);
}

/**
 * Every spelling a rule may target: lexical and canonical absolute paths (hard
 * rules), plus cwd-relative forms of both (frontmatter patterns like `src/**`).
 */
export function pathCandidates(arg: string, cwd: string, options: PathCandidateOptions = {}): string[] {
  const home = options.home ?? homedir();
  const real = options.realpath ?? canonicalPath;
  const lexical = normalizeToolPath(arg, cwd, home);
  const canonical = real(lexical);
  const lexicalCwd = path.resolve(cwd);
  const candidates = new Set<string>([lexical, canonical]);
  const lexicalRel = relativeInside(lexicalCwd, lexical);
  if (lexicalRel !== undefined) candidates.add(lexicalRel);
  const canonicalRel = relativeInside(real(lexicalCwd), canonical);
  if (canonicalRel !== undefined) candidates.add(canonicalRel);
  return [...candidates];
}
