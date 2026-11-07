/**
 * Environment assignments that change what an allowed command runs:
 * `GIT_EXTERNAL_DIFF=rm git diff`, `PAGER='sh -c x' git log`, `LD_PRELOAD=x rg`.
 * Rules match argv only, so the variables a command sees are judged here.
 */

import type { PermissionAction } from "../types.ts";
import { basename, commandIndex, parseCommands, type SimpleCommand, type Word } from "./shell.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

const ACTION = {
  allow: "allow",
  ask: "ask",
  deny: "deny",
} as const satisfies Record<PermissionAction, PermissionAction>;

// `NAME[i]=` assigns an array element; for a scalar, element 0 is the variable itself.
const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\+?=/;
const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
// A name operand, optionally subscripted (`printf -v a[1]`, `read a[0]`).
const NAME_OPERAND = /^([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?$/;
// `${NAME:=word}` and `${NAME=word}` assign NAME when it is unset (or empty).
const DEFAULT_ASSIGNMENT = /\$\{([A-Za-z_][A-Za-z0-9_]*):?=/g;
const OPTION_PREFIX = "-";
const OPTION_END = "--";
const LONG_PREFIX = "--";
const VALUE_SEPARATOR = "=";

/** `cd NAME` searches CDPATH first, so relative cd targets are unknown once it is set. */
export const CDPATH_VARIABLE = "CDPATH";
const GIT_PREFIX = "GIT_";
const GIT_MENTION = /\bgit\b/i;
/** Variables naming a program git (or its pager) starts. */
const PAGER_EDITOR_VARIABLES = new Set(["PAGER", "GIT_PAGER", "MANPAGER", "LESSOPEN", "LESSCLOSE", "EDITOR", "VISUAL"]);
/** Variables that make an allowed program load or run something else. */
const DANGEROUS_VARIABLES = new Set([
  ...PAGER_EDITOR_VARIABLES,
  "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND", "IFS", "PATH",
  "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
  "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
  "XDG_CONFIG_HOME", "HOME", "ZDOTDIR", CDPATH_VARIABLE,
]);
// npm reads its config variables in either case.
const DANGEROUS_PREFIXES_ANY_CASE = ["npm_config_"];
const SAFE_VARIABLES = new Set([
  "CI", "NODE_ENV", "FORCE_COLOR", "NO_COLOR", "TERM", "TZ", "LANG", "DEBUG", "RUST_BACKTRACE", "RUST_LOG",
  "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "COLUMNS", "LINES",
]);
const SAFE_PREFIXES = ["LC_"];

const EXPORT_NAME = "export";
const DECLARATION_NAMES = new Set(["declare", "typeset", "local", "readonly"]);
const EXPORT_LETTER = "x";
const SET_NAME = "set";
const ALLEXPORT_LETTER = "a";
const SET_OPTION_FLAG = "-o";
const ALLEXPORT_OPTION = "allexport";

// Builtins that assign the variables they name.
const PRINTF_NAME = "printf";
const PRINTF_VARIABLE_LETTER = "v";
const READ_NAME = "read";
const READ_ARRAY_LETTER = "a";
const READ_VALUE_LETTERS = new Set([READ_ARRAY_LETTER, "d", "i", "n", "N", "p", "t", "u"]);
const MAPFILE_NAMES = new Set(["mapfile", "readarray"]);
const MAPFILE_VALUE_LETTERS = new Set(["d", "n", "O", "s", "u", "C", "c"]);
// `for NAME in`, `select NAME in`: the loop assigns NAME.
const LOOP_KEYWORDS = new Set(["for", "select"]);

// `env -P DIR` (BSD) searches DIR instead of PATH; the option is judged as a PATH assignment.
const ENV_NAME = "env";
const PATH_VARIABLE = "PATH";
const ENV_PATH_LETTER = "P";
const ENV_PATH_LONG = "--path";
const ENV_SPLIT_LETTER = "S";
const ENV_SPLIT_LONG = "--split-string";
const ENV_VALUE_LETTERS = new Set(["u", "C", ENV_PATH_LETTER, ENV_SPLIT_LETTER, "a"]);
const ENV_VALUE_LONG = new Set(["--unset", "--chdir", ENV_SPLIT_LONG, "--argv0", ENV_PATH_LONG]);

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EnvVerdict {
  action: PermissionAction;
  /** Non-overridable deny */
  hard: boolean;
  reason: string;
}

/** exported: a command started after it sees the value (prefix, env wrapper, export, declare -x). */
interface Assignment {
  name: string;
  exported: boolean;
}

interface Collected {
  assignments: Assignment[];
  /** Names given to `export NAME` or `declare -x NAME` without a value. */
  exportedNames: Set<string>;
  allExport: boolean;
}

// ─── Collection ──────────────────────────────────────────────────────────────

function assignedName(word: Word): string | undefined {
  return ASSIGNMENT.exec(word.text)?.[1];
}

function isOption(word: Word): boolean {
  return word.text.startsWith(OPTION_PREFIX) && word.text !== OPTION_PREFIX && word.text !== OPTION_END;
}

function hasOptionLetter(args: Word[], letter: string): boolean {
  return args.some((word) => isOption(word) && !word.text.startsWith(OPTION_END) && word.text.slice(1).includes(letter));
}

function setsAllExport(args: Word[]): boolean {
  if (hasOptionLetter(args, ALLEXPORT_LETTER)) return true;
  return args.some((word, i) => word.text === SET_OPTION_FLAG && args[i + 1]?.text === ALLEXPORT_OPTION);
}

// `export`, `declare -x` and friends, options anywhere: assignments are exported with the flag, plain (shell-local) without it.
// A bare dangerous name counts as an assignment of it (`export GIT_DIR`, `local PATH`).
function collectDeclaration(args: Word[], exported: boolean, out: Collected): void {
  for (const word of args) {
    if (isOption(word)) continue;
    const name = assignedName(word);
    if (name !== undefined) out.assignments.push({ name, exported });
    else if (VARIABLE_NAME.test(word.text)) {
      if (isDangerous(word.text)) out.assignments.push({ name: word.text, exported });
      if (exported) out.exportedNames.add(word.text);
    }
  }
}

// Names assigned by builtins (printf -v, read, mapfile) or loops; only dangerous names matter there.
function collectName(word: Word | undefined, out: Collected): void {
  if (word === undefined || word.dynamic) return;
  const name = NAME_OPERAND.exec(word.text)?.[1];
  if (name !== undefined && isDangerous(name)) out.assignments.push({ name, exported: false });
}

/**
 * Walks short-option clusters; onValue receives each value-taking letter with its value word.
 * Returns the index of the first operand.
 */
function scanOptions(args: Word[], valueLetters: Set<string>, onValue: (letter: string, value: Word | undefined) => void): number {
  let i = 0;
  for (; i < args.length; i++) {
    const word = args[i];
    if (word.text === OPTION_END) return i + 1;
    if (!isOption(word)) return i;
    const letters = word.text.slice(OPTION_PREFIX.length);
    for (let j = 0; j < letters.length; j++) {
      if (!valueLetters.has(letters[j])) continue;
      const rest = letters.slice(j + 1);
      onValue(letters[j], rest === "" ? args[++i] : { ...word, text: rest });
      break;
    }
  }
  return i;
}

function collectBuiltin(name: string, args: Word[], out: Collected): void {
  if (name === PRINTF_NAME) {
    scanOptions(args, new Set([PRINTF_VARIABLE_LETTER]), (_letter, value) => collectName(value, out));
  } else if (name === READ_NAME) {
    const first = scanOptions(args, READ_VALUE_LETTERS, (letter, value) => {
      if (letter === READ_ARRAY_LETTER) collectName(value, out);
    });
    for (const word of args.slice(first)) collectName(word, out);
  } else if (MAPFILE_NAMES.has(name)) {
    collectName(args[scanOptions(args, MAPFILE_VALUE_LETTERS, () => {})], out);
  }
}

// True when an `env` option makes it search a different PATH (`env -P DIR cmd`); `-S` text is scanned as more options.
function envChangesLookup(args: Word[]): boolean {
  for (let i = 0; i < args.length; i++) {
    const text = args[i].text;
    if (text === OPTION_END || !isOption(args[i])) return false;
    if (text.startsWith(LONG_PREFIX)) {
      const separator = text.indexOf(VALUE_SEPARATOR);
      const name = separator === -1 ? text : text.slice(0, separator);
      // GNU getopt accepts abbreviations; no other env long option starts with `--p`.
      if (name.length > LONG_PREFIX.length && ENV_PATH_LONG.startsWith(name)) return true;
      const value = separator === -1 ? args[i + 1] : { ...args[i], text: text.slice(separator + 1) };
      if (ENV_SPLIT_LONG.startsWith(name) && name.length > LONG_PREFIX.length && value !== undefined) return splitChangesLookup(value);
      if (separator === -1 && ENV_VALUE_LONG.has(name)) i++;
      continue;
    }
    const letters = text.slice(OPTION_PREFIX.length);
    for (let j = 0; j < letters.length; j++) {
      const letter = letters[j];
      if (letter === ENV_PATH_LETTER) return true;
      if (!ENV_VALUE_LETTERS.has(letter)) continue;
      const rest = letters.slice(j + 1);
      const value = rest === "" ? args[++i] : { ...args[i], text: rest };
      if (letter === ENV_SPLIT_LETTER && value !== undefined) return splitChangesLookup(value);
      break;
    }
  }
  return false;
}

function splitChangesLookup(value: Word): boolean {
  if (value.dynamic) return false;
  return envChangesLookup(parseCommands(value.text)[0]?.words ?? []);
}

function collect(commands: SimpleCommand[], script: string): Collected {
  const out: Collected = { assignments: [], exportedNames: new Set(), allExport: false };
  for (const cmd of commands) {
    const first = cmd.words[0];
    if (first !== undefined && !first.quoted && LOOP_KEYWORDS.has(first.text)) collectName(cmd.words[1], out);
    // The shell parser does not know subscripted assignments, so `a[0]=x` may be taken for the command word.
    let leading = 0;
    while (leading < cmd.words.length && assignedName(cmd.words[leading]) !== undefined) leading++;
    const index = commandIndex(cmd.words);
    if (index === undefined || index < leading) {
      const exported = index !== undefined && leading < cmd.words.length;
      for (const word of cmd.words.slice(0, leading)) out.assignments.push({ name: assignedName(word) as string, exported });
      continue;
    }
    // Leading assignments and those handed through wrappers (`env A=1 cmd`, `sudo A=1 cmd`).
    for (let i = 0; i < index; i++) {
      const word = cmd.words[i];
      const name = assignedName(word);
      if (name !== undefined) out.assignments.push({ name, exported: true });
      else if (basename(word.text) === ENV_NAME && envChangesLookup(cmd.words.slice(i + 1, index + 1))) {
        out.assignments.push({ name: PATH_VARIABLE, exported: true });
      }
    }
    const name = basename(cmd.words[index].text);
    const args = cmd.words.slice(index + 1);
    if (name === ENV_NAME && envChangesLookup(args)) out.assignments.push({ name: PATH_VARIABLE, exported: true });
    if (name === EXPORT_NAME) collectDeclaration(args, true, out);
    else if (DECLARATION_NAMES.has(name)) collectDeclaration(args, hasOptionLetter(args, EXPORT_LETTER), out);
    else if (name === SET_NAME && setsAllExport(args)) out.allExport = true;
    else collectBuiltin(name, args, out);
  }
  for (const match of script.matchAll(DEFAULT_ASSIGNMENT)) {
    if (isDangerous(match[1])) out.assignments.push({ name: match[1], exported: false });
  }
  return out;
}

// ─── Classification ──────────────────────────────────────────────────────────

function isDangerous(name: string): boolean {
  if (name.startsWith(GIT_PREFIX) || DANGEROUS_VARIABLES.has(name)) return true;
  const lower = name.toLowerCase();
  return DANGEROUS_PREFIXES_ANY_CASE.some((prefix) => lower.startsWith(prefix));
}

function isSafe(name: string): boolean {
  return SAFE_VARIABLES.has(name) || SAFE_PREFIXES.some((prefix) => name.startsWith(prefix));
}

function isGitControl(name: string): boolean {
  return name.startsWith(GIT_PREFIX) || PAGER_EDITOR_VARIABLES.has(name);
}

/** True when the script assigns the variable in any form judged here. */
export function assignsVariable(commands: SimpleCommand[], script: string, name: string): boolean {
  return collect(commands, script).assignments.some((assignment) => assignment.name === name);
}

function quoted(names: Set<string>): string {
  return [...names].map((name) => `"${name}"`).join(", ");
}

/**
 * Verdict for the variables the script's commands set, undefined when none matters.
 * commands are every flattened simple command; script is the full command text.
 */
export function judgeEnvAssignments(commands: SimpleCommand[], script: string, denyGitWrite: boolean): EnvVerdict | undefined {
  const { assignments, exportedNames, allExport } = collect(commands, script);
  const dangerous = new Set<string>();
  const unknown = new Set<string>();
  for (const { name, exported } of assignments) {
    // A plain assignment still reaches child processes when the variable is already exported (PATH, HOME, PAGER).
    if (isDangerous(name)) dangerous.add(name);
    else if (!isSafe(name) && (exported || allExport || exportedNames.has(name))) unknown.add(name);
  }

  if (dangerous.size > 0) {
    const gitControl = [...dangerous].filter(isGitControl);
    if (denyGitWrite && gitControl.length > 0 && GIT_MENTION.test(script)) {
      return {
        action: ACTION.deny,
        hard: true,
        reason: `environment variable ${quoted(new Set(gitControl))} can make git run other programs; git write operations are disabled`,
      };
    }
    return { action: ACTION.deny, hard: false, reason: `environment variable ${quoted(dangerous)} can change what the command loads or runs` };
  }
  if (unknown.size > 0) {
    return { action: ACTION.ask, hard: false, reason: `command sets environment variable ${quoted(unknown)}` };
  }
  return undefined;
}
