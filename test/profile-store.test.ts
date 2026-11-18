import assert from "node:assert/strict";
import { test } from "node:test";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PROFILE_FILE_EXTENSION, PROFILES_DIR, PROFILE_STATE_FILE } from "../src/profile/schema.ts";
import { ProfileStore } from "../src/profile/store.ts";

function withStore(fn: (agentDir: string, store: ProfileStore) => void): void {
  const agentDir = realpathSync(mkdtempSync(join(tmpdir(), "poa-profile-store-")));
  try {
    fn(agentDir, new ProfileStore({ agentDir }));
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
}

function profilePath(agentDir: string, name: string): string {
  return join(agentDir, PROFILES_DIR, `${name}${PROFILE_FILE_EXTENSION}`);
}

function writeProfile(agentDir: string, name: string, body: unknown): void {
  mkdirSync(join(agentDir, PROFILES_DIR), { recursive: true });
  writeFileSync(profilePath(agentDir, name), typeof body === "string" ? body : JSON.stringify(body));
}

function statePath(agentDir: string): string {
  return join(agentDir, PROFILE_STATE_FILE);
}

function tempFiles(agentDir: string): string[] {
  return readdirSync(agentDir).filter((name) => name.endsWith(".tmp"));
}

test("lists no profiles when the directory is missing", () => {
  withStore((_agentDir, store) => {
    assert.deepEqual(store.list(), []);
  });
});

test("lists valid profile files sorted and ignores other files", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "zeta", { worker: { model: "a/b" } });
    writeProfile(agentDir, "alpha", { worker: { model: "a/b" } });
    writeFileSync(join(agentDir, PROFILES_DIR, "notes.txt"), "");
    writeFileSync(join(agentDir, PROFILES_DIR, `bad name${PROFILE_FILE_EXTENSION}`), "{}");
    mkdirSync(join(agentDir, PROFILES_DIR, "dir.json"));

    assert.deepEqual(store.list(), ["alpha", "zeta"]);
  });
});

test("activeName returns undefined when the state file is missing", () => {
  withStore((_agentDir, store) => {
    assert.equal(store.activeName(), undefined);
  });
});

test("activeName returns undefined for invalid state", () => {
  withStore((agentDir, store) => {
    writeFileSync(statePath(agentDir), "not json");
    assert.equal(store.activeName(), undefined);

    writeFileSync(statePath(agentDir), '{"active": "../escape"}');
    assert.equal(store.activeName(), undefined);

    writeFileSync(statePath(agentDir), '{"active": "cheap"}');
    assert.equal(store.activeName(), "cheap");
  });
});

test("read throws for a missing profile", () => {
  withStore((_agentDir, store) => {
    assert.throws(() => store.read("ghost"), /profile ghost not found/);
  });
});

test("read throws for an invalid profile", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "broken", "{");
    assert.throws(() => store.read("broken"), /profile broken is invalid:/);

    writeProfile(agentDir, "virtual", { worker: { model: "profile/worker" } });
    assert.throws(() => store.read("virtual"), /profile virtual is invalid: .*physical model/);
  });
});

test("read returns a parsed profile", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", {
      implementer: { model: "a/haiku", escalationModel: "a/sonnet", thinking: "low" },
    });
    assert.deepEqual(store.read("cheap"), {
      implementer: { model: "a/haiku", escalationModel: "a/sonnet", thinking: "low" },
    });
  });
});

test("setActive writes valid state and leaves no temp file", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", { worker: { model: "a/b" } });
    store.setActive("cheap");

    assert.deepEqual(JSON.parse(readFileSync(statePath(agentDir), "utf-8")), { active: "cheap" });
    assert.deepEqual(tempFiles(agentDir), []);
  });
});

test("setActive rejects unknown profiles and invalid names", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", { worker: { model: "a/b" } });
    assert.throws(() => store.setActive("ghost"), /unknown profile: ghost/);
    assert.throws(() => store.setActive("../escape"), /invalid profile name/);
    assert.equal(existsSync(statePath(agentDir)), false);
    assert.deepEqual(tempFiles(agentDir), []);
  });
});

test("setActive followed by activeName returns the new name", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", { worker: { model: "a/b" } });
    store.setActive("cheap");
    assert.equal(store.activeName(), "cheap");
  });
});

test("activeName picks up an external state rewrite", () => {
  withStore((agentDir, store) => {
    writeFileSync(statePath(agentDir), '{"active": "one"}');
    assert.equal(store.activeName(), "one");

    writeFileSync(statePath(agentDir), '{"active": "second"}');
    assert.equal(store.activeName(), "second");
  });
});

test("read caches an unchanged file", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", { worker: { model: "a/small" } });
    const first = store.read("cheap");
    const second = store.read("cheap");
    assert.equal(first, second);
    assert.deepEqual(second, { worker: { model: "a/small" } });
  });
});

test("read reparses a file with different content", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", { worker: { model: "a/small" } });
    const first = store.read("cheap");

    writeProfile(agentDir, "cheap", { worker: { model: "b/large", thinking: "high" } });
    const second = store.read("cheap");

    assert.notEqual(first, second);
    assert.deepEqual(second, { worker: { model: "b/large", thinking: "high" } });
  });
});

test("read reparses when only the mtime changes", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", { worker: { model: "a/small" } });
    assert.deepEqual(store.read("cheap"), { worker: { model: "a/small" } });

    writeProfile(agentDir, "cheap", { worker: { model: "b/large" } });
    const changed = new Date(Date.now() + 5000);
    utimesSync(profilePath(agentDir, "cheap"), changed, changed);

    assert.deepEqual(store.read("cheap"), { worker: { model: "b/large" } });
  });
});

test("read caches a parse error for the same file version", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "broken", { worker: {} });

    const errors: unknown[] = [];
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        store.read("broken");
      } catch (error) {
        errors.push(error);
      }
    }
    assert.equal(errors.length, 2);
    assert.equal(errors[0], errors[1]);

    writeProfile(agentDir, "broken", { worker: { model: "a/b" } });
    assert.deepEqual(store.read("broken"), { worker: { model: "a/b" } });
  });
});

test("read does not cache a read failure", { skip: process.getuid?.() === 0 }, () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", { worker: { model: "a/small" } });
    const target = profilePath(agentDir, "cheap");
    chmodSync(target, 0o000);

    let failure: unknown;
    try {
      store.read("cheap");
    } catch (error) {
      failure = error;
    }
    assert.equal((failure as NodeJS.ErrnoException | undefined)?.code, "EACCES");
    assert.doesNotMatch(String(failure), /is invalid/, "the read error is not a profile validation error");

    chmodSync(target, 0o644);
    assert.deepEqual(store.read("cheap"), { worker: { model: "a/small" } });
  });
});

test("read detects an atomic replace with the same size and mtime", () => {
  withStore((agentDir, store) => {
    writeProfile(agentDir, "cheap", { worker: { model: "a/small" } });
    const target = profilePath(agentDir, "cheap");
    const stamp = new Date(2024, 0, 1, 12, 0, 0);
    utimesSync(target, stamp, stamp);
    assert.deepEqual(store.read("cheap"), { worker: { model: "a/small" } });

    // Same byte length and mtime, new inode: only the inode reveals the swap.
    const replacement = join(agentDir, PROFILES_DIR, "replacement.tmp");
    writeFileSync(replacement, JSON.stringify({ worker: { model: "b/small" } }));
    utimesSync(replacement, stamp, stamp);
    renameSync(replacement, target);

    assert.equal(statSync(target).mtimeMs, stamp.getTime());
    assert.deepEqual(store.read("cheap"), { worker: { model: "b/small" } });
  });
});
