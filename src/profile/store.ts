/**
 * Profile storage: profile files under <agentDir>/profiles and the active
 * selection in <agentDir>/profile-state.json.
 *
 * Reads are cached per file version because a router asks for the active
 * profile and its contents on every model request.
 */

import { randomUUID } from "node:crypto";
import {
  existsSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import type { Profile, ProfileState } from "./schema.ts";
import {
  PROFILE_FILE_EXTENSION,
  PROFILES_DIR,
  PROFILE_STATE_FILE,
  isProfileName,
  parseProfile,
  parseProfileState,
} from "./schema.ts";

const NOT_FOUND = "ENOENT";

interface CacheEntry<T> {
  ino: number;
  mtimeMs: number;
  size: number;
  value?: T;
  error?: Error;
}

export interface ProfileStoreOptions {
  agentDir: string;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function errorCode(error: unknown): string | undefined {
  return error instanceof Error ? (error as NodeJS.ErrnoException).code : undefined;
}

export class ProfileStore {
  private readonly profilesDir: string;
  private readonly statePath: string;
  private readonly profileCache = new Map<string, CacheEntry<Profile>>();
  private readonly stateCache = new Map<string, CacheEntry<ProfileState>>();

  constructor(options: ProfileStoreOptions) {
    this.profilesDir = path.join(options.agentDir, PROFILES_DIR);
    this.statePath = path.join(options.agentDir, PROFILE_STATE_FILE);
  }

  list(): string[] {
    try {
      return readdirSync(this.profilesDir, { withFileTypes: true })
        .filter((entry) => entry.isFile() && entry.name.endsWith(PROFILE_FILE_EXTENSION))
        .map((entry) => entry.name.slice(0, -PROFILE_FILE_EXTENSION.length))
        .filter(isProfileName)
        .sort();
    } catch (error) {
      if (errorCode(error) === NOT_FOUND) return [];
      throw error;
    }
  }

  activeName(): string | undefined {
    try {
      return this.load(this.statePath, this.stateCache, parseProfileState, (error) => new Error(errorMessage(error)))
        .active;
    } catch {
      return undefined;
    }
  }

  read(name: string): Profile {
    const filePath = this.profilePath(name);
    try {
      return this.load(
        filePath,
        this.profileCache,
        parseProfile,
        (error) => new Error(`profile ${name} is invalid: ${errorMessage(error)}`),
      );
    } catch (error) {
      if (errorCode(error) === NOT_FOUND) throw new Error(`profile ${name} not found`);
      throw error;
    }
  }

  setActive(name: string): void {
    if (!isProfileName(name)) throw new Error(`invalid profile name: ${name}`);
    if (!existsSync(this.profilePath(name))) throw new Error(`unknown profile: ${name}`);

    const tempPath = path.join(
      path.dirname(this.statePath),
      `${PROFILE_STATE_FILE}.${process.pid}.${randomUUID()}.tmp`,
    );
    try {
      writeFileSync(tempPath, `${JSON.stringify({ active: name })}\n`, { flag: "wx" });
      renameSync(tempPath, this.statePath);
    } catch (error) {
      try {
        unlinkSync(tempPath);
      } catch {
        // rename may already have removed the temp file
      }
      throw error;
    }
  }

  private profilePath(name: string): string {
    return path.join(this.profilesDir, `${name}${PROFILE_FILE_EXTENSION}`);
  }

  private load<T>(
    filePath: string,
    cache: Map<string, CacheEntry<T>>,
    parse: (json: string) => T,
    invalid: (error: unknown) => Error,
  ): T {
    const stats = statSync(filePath);
    const cached = cache.get(filePath);
    if (
      cached !== undefined &&
      cached.ino === stats.ino &&
      cached.mtimeMs === stats.mtimeMs &&
      cached.size === stats.size
    ) {
      if (cached.error !== undefined) throw cached.error;
      return cached.value as T;
    }

    // The inode catches an atomic replace whose mtime and size did not change.
    const version = { ino: stats.ino, mtimeMs: stats.mtimeMs, size: stats.size };
    // Not cached: a transient read failure (EACCES, EMFILE, a file removed
    // after the stat) must not stick. The raw error also lets read() map a
    // vanished file to its not-found message.
    const json = readFileSync(filePath, "utf-8");
    try {
      const value = parse(json);
      cache.set(filePath, { ...version, value });
      return value;
    } catch (error) {
      const wrapped = invalid(error);
      cache.set(filePath, { ...version, error: wrapped });
      throw wrapped;
    }
  }
}
