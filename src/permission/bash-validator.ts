/**
 * Argv-level validation of shell tool calls for the strict-mode policy gate.
 *
 * The script is parsed into simple commands (substitutions, nested shells,
 * eval and find -exec included) and every command is judged on its own, so
 * chaining cannot carry an unlisted command past a rule. Git writes, writes to
 * protected paths and alwaysDeny.bash entries are hard denies. Anything the
 * parser cannot see through turns an allow into an ask.
 */

import { homedir } from "node:os";
import path from "node:path";
import type { PermissionAction, PermissionRule } from "../types.ts";
import { matchPermissionKey } from "./evaluator.ts";
import { findGitViolations } from "./git-guard.ts";
import { matchPattern } from "./matcher.ts";
import { normalizeToolPath, pathCandidates } from "./paths.ts";
import { matchesHard } from "./policy-gate.ts";
import type { EffectivePolicy } from "./resolver.ts";
import {
  basename,
  commandIndex,
  nestedScripts,
  parseCommands,
  STDIN_PIPE,
  type NestedScripts,
  type SimpleCommand,
  type Word,
} from "./shell.ts";
import { findWriteViolations, inlineInterpreterScript, isFileWriteRedirect, mutatesFiles } from "./shell-writes.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

const ACTION = {
  allow: "allow",
  ask: "ask",
  deny: "deny",
} as const satisfies Record<PermissionAction, PermissionAction>;

const RESTRICTIVENESS: Record<PermissionAction, number> = {
  [ACTION.allow]: 0,
  [ACTION.ask]: 1,
  [ACTION.deny]: 2,
};

/** Categories whose command text is a POSIX shell script. */
export const POSIX_SHELL_CATEGORIES: readonly string[] = ["bash", "shell"];
const WRITE_CATEGORIES: readonly string[] = ["edit", "write"];
const WILDCARD = "*";
const PATH_SEPARATOR = "/";
const TOKEN_SPLIT = /\s+/;
const WORD_SEPARATOR = " ";
const HOME = "~";
const HOME_PREFIX = "~/";
// `~+` is $PWD; any other tilde prefix (`~-`, `~user`, `~+2`) is only known at run time.
const CWD_TILDE = "~+";
const GLOB_CHARS = /[*?]/;
// Shell glob characters; `[` is not understood by matchPattern, so such a segment may match anything.
const SHELL_GLOB_CHARS = /[*?[]/;
const BRACKET_GLOB = "[";
const CURRENT_DIR = ".";
// A character that continues a name, so `.git` inside `.gitignore` is not a mention.
const NAME_CHAR = /[A-Za-z0-9_.-]/;
// A mention must start a path or a path segment, so `b.git` in a URL is not one.
const MENTION_BEFORE = /[/'"`\s=(]/;
const GIT_DIR = ".git";
// `.git` only counts as a whole path segment.
const GIT_DIR_AFTER = /[/'"`\s),;]/;

const BRACE_OPEN = "{";
const BRACE_CLOSE = "}";
const BRACE_COMMA = ",";
const BRACE_SEQUENCE = /^(?:(-?\d+)\.\.(-?\d+)|([A-Za-z])\.\.([A-Za-z]))(?:\.\.(-?\d+))?$/;
const LEADING_ZERO = /^-?0\d/;
const NEGATIVE_SIGN = "-";
const ZERO_PAD = "0";
const MAX_BRACE_EXPANSIONS = 256;
const SINGLE_QUOTE = "'";
const ESCAPED_SINGLE_QUOTE = "'\\''";
const GIT_NAME = "git";

const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;
const OPTION_PREFIX = "-";
const OPTION_END = "--";
const LONG_OPTION_PREFIX = "--";
// `-oVALUE`: a single-dash word longer than this carries an attached value.
const SHORT_OPTION_LENGTH = 2;
const SORT_NAME = "sort";
const SORT_OUTPUT_LETTER = "o";
const SORT_VALUE_LETTERS = new Set(["k", "S", "t", "T"]);
const SORT_OUTPUT_LONG = "--output";
const SORT_WRITE_LABEL = "file mutation: sort -o";
const MUTATION_LABEL = "file mutation";
const VALUE_SEPARATOR = "=";
// Words that start a command without running anything (loop headers, closers, definitions).
const STRUCTURAL_WORDS = new Set([
  "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "for", "select", "case", "esac", "function", "!", "time", "{",
]);
// The parser's marker word for `(( ... ))`; substitutions inside are emitted as their own commands.
const ARITHMETIC_COMMAND = "((";
const PRIVILEGE_WRAPPERS = new Set(["sudo", "doas", "su", "pkexec", "run0"]);
const CD_COMMANDS = new Set(["cd", "pushd"]);
const PREVIOUS_DIR = "-";
const EVAL_NAME = "eval";
const SOURCE_NAMES = new Set(["source", "."]);
const HERESTRING_OP = "<<<";
const RG_NAME = "rg";
const RG_PRE = "--pre";
const RG_PRE_VALUE = "--pre=";
// Filled in by find -exec, fd -x, xargs -I or parallel, so the real target is invisible.
const PLACEHOLDER = "{}";
const STDIN_CONSUMERS = new Set(["xargs", "parallel"]);
// Commands that delete their operands; mv removes its sources.
const DELETE_COMMANDS = new Set(["rm", "rmdir", "unlink"]);
const MOVE_NAME = "mv";
const MOVE_TARGET_LETTER = "t";
const MOVE_VALUE_LETTERS = new Set([MOVE_TARGET_LETTER, "S"]);
const MOVE_TARGET_LONG = "--target-directory";
const MOVE_VALUE_LONG = new Set([MOVE_TARGET_LONG, "--suffix"]);
const RSYNC_NAME = "rsync";
const RSYNC_DELETE_PREFIX = "--delete";
// rsync's alias of --delete-during.
const RSYNC_DEL = "--del";
const FIND_NAME = "find";
const FD_NAMES = new Set(["fd", "fdfind"]);
const FIND_DELETE = "-delete";
const FIND_EXEC_FLAGS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);
// Leading find options before the start paths (GNU -H -L -P -O, BSD -E -X -d -s -x).
const FIND_LEADING_OPTION = /^-(?:[HLPEXdsx]+|O\d*)$/;
const FIND_DEBUG_OPTION = "-D";
const FIND_PATH_OPTION = "-f";
const FIND_EXPRESSION_STARTS = new Set(["(", "!", ")", ","]);
// Built-in protected locations an inline interpreter script must not mention.
const PROTECTED_MENTIONS = [GIT_DIR, ".pi/", ".opencode", ".agents"];

const NO_COMMAND_REASON = "no command to run";
const POWERSHELL_REASON = "powershell commands cannot be validated; only a blanket rule can allow them";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ShellValidationInput {
  command: string;
  category: string;
  policy: EffectivePolicy;
  inherited: PermissionRule[];
  cwd: string;
  home?: string;
  realpath?: (p: string) => string;
}

export interface ShellDecision {
  action: PermissionAction;
  /** Non-overridable deny: never asks */
  hard: boolean;
  reason: string;
  /** Argv strings that were judged */
  commands: string[];
}

/** A flattened command; cmd has its command-name words lowercased for classification, original is as written. */
interface Flat {
  cmd: SimpleCommand;
  original: SimpleCommand;
}

/** One command to judge: argv from the command word on, raw from the first non-assignment word, both as written. */
interface Judged {
  cmd: SimpleCommand;
  index: number | undefined;
  argv: Word[];
  raw: Word[];
}

/** A flattened command with its judged form, when it runs one. */
interface Entry {
  cmd: SimpleCommand;
  judged: Judged | undefined;
  renamed: boolean;
}

/** A write or delete target; literalTilde marks a value bash does not tilde-expand (mid-word). */
type Target = Word & { literalTilde?: boolean };

interface BraceGroup {
  close: number;
  /** undefined: more than MAX_BRACE_EXPANSIONS items */
  items: string[] | undefined;
}

interface Verdict {
  action: PermissionAction;
  reason: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function text(words: Word[]): string {
  return words.map((word) => word.text).join(WORD_SEPARATOR);
}

function tokens(pattern: string): string[] {
  return pattern.trim().split(TOKEN_SPLIT).filter((token) => token !== "");
}

function stricter(kept: Verdict, next: Verdict): Verdict {
  return RESTRICTIVENESS[next.action] > RESTRICTIVENESS[kept.action] ? next : kept;
}

/**
 * Token-prefix match: token i glob-matches word i. A dynamic word only matches
 * `*`. A path-like command word only matches a path-like first token, unless
 * byBasename compares the first token against the word's basename.
 */
function tokensMatch(pattern: string[], argv: Word[], byBasename: boolean): boolean {
  if (pattern.length === 0) return false;
  if (pattern.length === 1 && pattern[0] === WILDCARD) return true;
  if (argv.length < pattern.length) return false;
  return pattern.every((token, i) => {
    const word = argv[i];
    if (token === WILDCARD) return true;
    if (word.dynamic) return false;
    if (i === 0 && byBasename) return matchPattern(token, basename(word.text)) || matchPattern(token, word.text);
    if (i === 0 && word.text.includes(PATH_SEPARATOR) && !token.includes(PATH_SEPARATOR)) return false;
    return matchPattern(token, word.text);
  });
}

function opaqueReason(nested: NestedScripts, cmd: SimpleCommand): string {
  if (nested.substitution !== undefined) return `script from ${nested.substitution}`;
  if (nested.piped) return `script piped into "${text(cmd.words)}"`;
  return `dynamic script in "${text(cmd.words)}"`;
}

// A case-insensitive file system (macOS) runs `RM` as rm, so names, wrappers included, are lowercased.
function lowerCommandNames(cmd: SimpleCommand): SimpleCommand {
  let words = cmd.words;
  for (let index = commandIndex(words); index !== undefined; ) {
    const word = words[index];
    const name = basename(word.text);
    const lower = name.toLowerCase();
    if (word.dynamic || lower === name) break;
    words = [...words];
    words[index] = { ...word, text: word.text.slice(0, word.text.length - name.length) + lower };
    const next = commandIndex(words);
    if (next === index) break;
    index = next;
  }
  return words === cmd.words ? cmd : { ...cmd, words };
}

function braceSequence(body: string): string[] | undefined | null {
  const match = BRACE_SEQUENCE.exec(body);
  if (match === null) return null;
  const [, numberStart, numberEnd, letterStart, letterEnd, increment] = match;
  const numeric = numberStart !== undefined;
  const start = numeric ? Number(numberStart) : letterStart.charCodeAt(0);
  const end = numeric ? Number(numberEnd) : letterEnd.charCodeAt(0);
  const step = Math.abs(Number(increment ?? 1)) || 1;
  if (Math.floor(Math.abs(end - start) / step) + 1 > MAX_BRACE_EXPANSIONS) return undefined;
  const width = numeric && (LEADING_ZERO.test(numberStart) || LEADING_ZERO.test(numberEnd))
    ? Math.max(numberStart.length, numberEnd.length)
    : 0;
  const items: string[] = [];
  for (let value = start; start <= end ? value <= end : value >= end; value += start <= end ? step : -step) {
    if (!numeric) items.push(String.fromCharCode(value));
    else if (value < 0) items.push(NEGATIVE_SIGN + String(-value).padStart(width - NEGATIVE_SIGN.length, ZERO_PAD));
    else items.push(String(value).padStart(width, ZERO_PAD));
  }
  return items;
}

// `{a,b}` needs a top-level comma, `{x..y[..n]}` a valid sequence; anything else is literal.
function braceGroup(word: string, open: number): BraceGroup | undefined {
  const commas: number[] = [];
  let depth = 0;
  for (let i = open + 1; i < word.length; i++) {
    const ch = word[i];
    if (ch === BRACE_OPEN) depth++;
    else if (ch === BRACE_COMMA && depth === 0) commas.push(i);
    else if (ch === BRACE_CLOSE && depth > 0) depth--;
    else if (ch === BRACE_CLOSE) {
      if (commas.length === 0) {
        const items = braceSequence(word.slice(open + 1, i));
        return items === null ? undefined : { close: i, items };
      }
      const bounds = [open, ...commas, i];
      return { close: i, items: bounds.slice(1).map((bound, k) => word.slice(bounds[k] + 1, bound)) };
    }
  }
  return undefined;
}

/** Bash brace expansion of an unquoted word; undefined when it yields more than MAX_BRACE_EXPANSIONS words. */
function expandBraces(word: string): string[] | undefined {
  for (let open = word.indexOf(BRACE_OPEN); open !== -1; open = word.indexOf(BRACE_OPEN, open + 1)) {
    const group = braceGroup(word, open);
    if (group === undefined) continue;
    if (group.items === undefined) return undefined;
    const suffixes = expandBraces(word.slice(group.close + 1));
    if (suffixes === undefined) return undefined;
    const prefix = word.slice(0, open);
    const out: string[] = [];
    for (const item of group.items) {
      const inner = expandBraces(item);
      if (inner === undefined) return undefined;
      for (const middle of inner) {
        for (const suffix of suffixes) out.push(prefix + middle + suffix);
      }
      if (out.length > MAX_BRACE_EXPANSIONS) return undefined;
    }
    return out;
  }
  return [word];
}

function tooManyExpansions(text: string): string {
  return `brace expansion of "${text}" yields more than ${MAX_BRACE_EXPANSIONS} words`;
}

// Unquoted words are brace-expanded in place, as bash does before running the command.
function expandWords(words: Word[], unverifiable: string[]): Word[] {
  return words.flatMap((word) => {
    if (word.quoted || word.dynamic) return [word];
    const expanded = expandBraces(word.text);
    if (expanded !== undefined) return expanded.map((text) => ({ ...word, text }));
    unverifiable.push(tooManyExpansions(word.text));
    return [word];
  });
}

// nestedScripts is one level deep, so its commands are flattened again; eval text is parsed here.
function flatten(commands: SimpleCommand[], out: Flat[], unverifiable: string[]): void {
  for (const original of commands) {
    const cmd = lowerCommandNames(original);
    out.push({ cmd, original });
    if (cmd.unterminated) unverifiable.push(`unterminated quote or heredoc in "${text(cmd.words)}"`);
    const nested = nestedScripts(cmd);
    if (nested.opaque) unverifiable.push(opaqueReason(nested, cmd));
    flatten(nested.commands, out, unverifiable);

    const index = commandIndex(cmd.words);
    if (index === undefined) continue;
    const name = basename(cmd.words[index].text);
    const args = cmd.words.slice(index + 1);
    const dynamic = args.some((word) => word.dynamic);
    if (name === EVAL_NAME) {
      if (dynamic) unverifiable.push(`eval of dynamic text "${text(args)}"`);
      else flatten(parseCommands(text(args)), out, unverifiable);
    } else if (SOURCE_NAMES.has(name) && dynamic && !nested.opaque) {
      unverifiable.push(`source of dynamic path "${text(args)}"`);
    }
  }
}

function judge({ cmd, original }: Flat, unverifiable: string[]): Judged | undefined {
  const start = original.words.findIndex((word) => !ASSIGNMENT.test(word.text));
  if (start === -1) return undefined;
  const raw = original.words.slice(start);
  const index = commandIndex(cmd.words);
  if (index === undefined) {
    const first = raw[0];
    if (!first.quoted && STRUCTURAL_WORDS.has(first.text)) return undefined;
    // A wrapper with nothing to wrap (`sudo -s`, `env`, `command -v x`) is judged as written.
    return { cmd, index, argv: raw, raw };
  }
  const name = original.words[index];
  if (name.quoted && name.dynamic && name.text === ARITHMETIC_COMMAND) return undefined;
  if (name.dynamic) unverifiable.push(`dynamic command name "${name.text}"`);
  for (const word of original.words.slice(start, index + 1)) {
    if (word.quoted || word.dynamic) continue;
    const expanded = expandBraces(word.text);
    if (expanded?.length !== 1 || expanded[0] !== word.text) unverifiable.push(`brace expansion in command word "${word.text}"`);
  }
  return { cmd, index, argv: original.words.slice(index), raw };
}

// ─── Protected Paths ─────────────────────────────────────────────────────────

function isOption(word: Word): boolean {
  return word.text.startsWith(OPTION_PREFIX) && word.text !== OPTION_PREFIX;
}

// Static non-option arguments, plus the value of `key=value` words (dd of=, --target-directory=).
function mutationTargets(argWords: Word[]): Target[] {
  const targets: Target[] = [];
  let options = true;
  for (const word of argWords) {
    if (options && word.text === OPTION_END) {
      options = false;
      continue;
    }
    const separator = word.text.indexOf(VALUE_SEPARATOR);
    if (separator !== -1) targets.push({ ...word, text: word.text.slice(separator + 1) });
    if (!options || !isOption(word)) targets.push(word);
    else if (!word.text.startsWith(LONG_OPTION_PREFIX)) {
      // Attached short-option value (`cp -tDIR`, `curl -sSoFILE`): it may start after any letter of the cluster.
      for (let i = SHORT_OPTION_LENGTH; i < word.text.length; i++) {
        targets.push({ ...word, text: word.text.slice(i), literalTilde: true });
      }
    }
  }
  return targets;
}

// `sort -o FILE`, `-oFILE`, `-ro FILE`, `--output[=]FILE` and its abbreviations.
function sortOutputs(argWords: Word[]): Target[] {
  const outputs: Target[] = [];
  for (let i = 0; i < argWords.length; i++) {
    const word = argWords[i];
    if (word.text === OPTION_END) break;
    if (!isOption(word)) continue;
    if (word.text.startsWith(LONG_OPTION_PREFIX)) {
      const separator = word.text.indexOf(VALUE_SEPARATOR);
      const name = separator === -1 ? word.text : word.text.slice(0, separator);
      if (name.length <= LONG_OPTION_PREFIX.length || !SORT_OUTPUT_LONG.startsWith(name)) continue;
      const value = separator === -1 ? argWords[++i] : { ...word, text: word.text.slice(separator + 1) };
      if (value !== undefined) outputs.push(value);
      continue;
    }
    const letters = word.text.slice(OPTION_PREFIX.length);
    const valueAt = [...letters].findIndex((letter) => letter === SORT_OUTPUT_LETTER || SORT_VALUE_LETTERS.has(letter));
    if (valueAt === -1) continue;
    const attached = letters.slice(valueAt + 1);
    const value: Target | undefined = attached === "" ? argWords[++i] : { ...word, text: attached, literalTilde: true };
    if (letters[valueAt] === SORT_OUTPUT_LETTER && value !== undefined) outputs.push(value);
  }
  return outputs;
}

function commandName(judged: Judged): string | undefined {
  return judged.index === undefined ? undefined : basename(judged.cmd.words[judged.index].text);
}

function writeTargets(cmd: SimpleCommand, judged: Judged | undefined, args: Word[], unverifiable: string[]): Target[] {
  const redirects = cmd.redirects
    .filter(isFileWriteRedirect)
    .map((redirect) => ({ text: redirect.target, quoted: false, dynamic: redirect.targetDynamic }));
  const targets: Target[] = expandWords(redirects, unverifiable);
  if (judged?.index !== undefined && mutatesFiles(cmd)) targets.push(...mutationTargets(args));
  if (judged !== undefined && commandName(judged) === SORT_NAME) targets.push(...sortOutputs(args));
  return targets;
}

function positionals(argWords: Word[]): Word[] {
  const end = argWords.findIndex((word) => word.text === OPTION_END);
  const before = (end === -1 ? argWords : argWords.slice(0, end)).filter((word) => !isOption(word));
  return end === -1 ? before : [...before, ...argWords.slice(end + 1)];
}

// Sources of mv: every operand but the last, or all of them with -t/--target-directory.
function moveSources(argWords: Word[]): Word[] {
  const operands: Word[] = [];
  let targetDirectory = false;
  let options = true;
  for (let i = 0; i < argWords.length; i++) {
    const word = argWords[i];
    if (options && word.text === OPTION_END) {
      options = false;
      continue;
    }
    if (!options || !isOption(word)) {
      operands.push(word);
      continue;
    }
    if (word.text.startsWith(LONG_OPTION_PREFIX)) {
      const name = word.text.split(VALUE_SEPARATOR)[0];
      if (name === MOVE_TARGET_LONG) targetDirectory = true;
      if (MOVE_VALUE_LONG.has(name) && !word.text.includes(VALUE_SEPARATOR)) i++;
      continue;
    }
    const letters = word.text.slice(OPTION_PREFIX.length);
    const valueAt = [...letters].findIndex((letter) => MOVE_VALUE_LETTERS.has(letter));
    if (valueAt === -1) continue;
    if (letters[valueAt] === MOVE_TARGET_LETTER) targetDirectory = true;
    if (valueAt === letters.length - 1) i++;
  }
  return targetDirectory ? operands : operands.slice(0, -1);
}

function findStartPaths(argWords: Word[]): Word[] {
  const paths: Word[] = [];
  let i = 0;
  for (; i < argWords.length; i++) {
    const value = argWords[i].text;
    if (value === FIND_DEBUG_OPTION) i++;
    else if (value === FIND_PATH_OPTION && i + 1 < argWords.length) paths.push(argWords[++i]);
    else if (!FIND_LEADING_OPTION.test(value)) break;
  }
  for (; i < argWords.length; i++) {
    const word = argWords[i];
    if (isOption(word) || FIND_EXPRESSION_STARTS.has(word.text)) break;
    paths.push(word);
  }
  // GNU find searches the current directory when no start path is given.
  return paths.length > 0 ? paths : [{ text: CURRENT_DIR, quoted: false, dynamic: false }];
}

function runsMutation(written: SimpleCommand): boolean {
  const cmd = lowerCommandNames(written);
  if (mutatesFiles(cmd) || inlineInterpreterScript(cmd) !== undefined) return true;
  const nested = nestedScripts(cmd);
  return nested.opaque || nested.commands.some(runsMutation);
}

/** Operands whose whole subtree the command deletes or moves away. */
function destructiveTargets(judged: Judged, args: Word[]): Word[] {
  const name = commandName(judged);
  if (name === undefined) return [];
  if (DELETE_COMMANDS.has(name)) return positionals(args);
  if (name === MOVE_NAME) return moveSources(args);
  if (name === RSYNC_NAME) {
    const deletes = args.some((word) => word.text === RSYNC_DEL || word.text.startsWith(RSYNC_DELETE_PREFIX));
    return deletes ? positionals(args).slice(-1) : [];
  }
  if (name === FIND_NAME) {
    const mutating =
      args.some((word) => word.text === FIND_DELETE) ||
      (args.some((word) => FIND_EXEC_FLAGS.has(word.text)) && nestedScripts(judged.cmd).commands.some(runsMutation));
    return mutating ? findStartPaths(args) : [];
  }
  return [];
}

// Paths come from xargs/parallel input, or fd appends each match to its -x command.
function hiddenTargets(judged: Judged): boolean {
  if (judged.index === undefined) return false;
  const fedByInput = judged.cmd.words.slice(0, judged.index).some((word) => STDIN_CONSUMERS.has(basename(word.text)));
  if (fedByInput && mutatesFiles(judged.cmd)) return true;
  return FD_NAMES.has(basename(judged.cmd.words[judged.index].text)) && nestedScripts(judged.cmd).commands.some(runsMutation);
}

/** Literal directory prefixes of the protected path patterns, lowercased. */
function protectedLocations(writeRules: PermissionRule[]): string[] {
  const locations = new Set<string>();
  for (const rule of writeRules) {
    // Unanchored patterns (`**/.pi/**`) have no literal prefix: as an ancestor location they would deny every delete.
    if (rule.pattern === WILDCARD || !path.isAbsolute(rule.pattern)) continue;
    const segments = rule.pattern.split(PATH_SEPARATOR);
    const globIndex = segments.findIndex((segment) => GLOB_CHARS.test(segment));
    const literal = segments.slice(0, globIndex === -1 ? segments.length : globIndex).join(PATH_SEPARATOR);
    locations.add((literal === "" ? PATH_SEPARATOR : literal).toLowerCase());
  }
  return [...locations];
}

function isAncestorOrSelf(dir: string, location: string): boolean {
  if (dir === location) return true;
  return location.startsWith(dir.endsWith(PATH_SEPARATOR) ? dir : `${dir}${PATH_SEPARATOR}`);
}

// First path segment of location below the strict ancestor dir.
function childSegment(dir: string, location: string): string {
  const rest = location.slice(dir.endsWith(PATH_SEPARATOR) ? dir.length : dir.length + 1);
  return rest.split(PATH_SEPARATOR)[0];
}

/** The protected location a deleted or moved target equals or contains, if any. */
function destroyedLocation(target: string, base: string, locations: string[], options: { home: string; realpath?: (p: string) => string }): string | undefined {
  const absolute = (arg: string): string[] =>
    pathCandidates(arg, base, options).filter((candidate) => path.isAbsolute(candidate)).map((candidate) => candidate.toLowerCase());
  const segments = target.split(PATH_SEPARATOR);
  const globIndex = segments.findIndex((segment) => SHELL_GLOB_CHARS.test(segment));
  if (globIndex === -1) {
    const candidates = absolute(target);
    return locations.find((location) => candidates.some((candidate) => isAncestorOrSelf(candidate, location)));
  }

  const dirText = segments.slice(0, globIndex).join(PATH_SEPARATOR) || (globIndex === 0 ? CURRENT_DIR : PATH_SEPARATOR);
  const glob = segments[globIndex].toLowerCase();
  const dirs = absolute(dirText);
  return locations.find((location) =>
    dirs.some((dir) => {
      // A glob at or below a protected location can expand to anything in it.
      if (isAncestorOrSelf(location, dir)) return true;
      if (!isAncestorOrSelf(dir, location)) return false;
      return glob.includes(BRACKET_GLOB) || matchPattern(glob, childSegment(dir, location));
    }),
  );
}

function isAnchored(target: string): boolean {
  return path.isAbsolute(target) || target === HOME || target.startsWith(HOME_PREFIX);
}

// `~+[/x]` becomes `.[/x]`; undefined for a tilde prefix only known at run time.
function resolveTilde(target: string): string | undefined {
  if (!target.startsWith(HOME)) return target;
  const slash = target.indexOf(PATH_SEPARATOR);
  const prefix = slash === -1 ? target : target.slice(0, slash);
  if (prefix === HOME) return target;
  if (prefix === CWD_TILDE) return CURRENT_DIR + target.slice(prefix.length);
  return undefined;
}

/** Static texts a target can stand for; reasons go to unverifiable for parts only known at run time. */
function targetTexts(target: Target, unverifiable: string[]): string[] {
  if (target.dynamic) {
    unverifiable.push(`dynamic write target "${target.text}"`);
    return [];
  }
  if (target.text.includes(PLACEHOLDER)) {
    unverifiable.push(`write target "${target.text}" is filled in at run time`);
    return [];
  }
  let variants = [target.text];
  // Word.quoted covers any part, so an unquoted brace group or tilde may remain: check both readings.
  if (target.quoted) {
    const expanded = expandBraces(target.text);
    if (expanded === undefined) unverifiable.push(tooManyExpansions(target.text));
    else variants = [...new Set([target.text, ...expanded])];
  }
  if (target.literalTilde) return variants;
  const texts: string[] = target.quoted ? [...variants] : [];
  for (const variant of variants) {
    const resolved = resolveTilde(variant);
    if (resolved === undefined) unverifiable.push(`tilde prefix of "${variant}" is only known at run time`);
    else texts.push(resolved);
  }
  return [...new Set(texts)];
}

// A find start path inside a protected location is a hard deny; above one it only asks.
function insideLocation(target: string, base: string, locations: string[], options: { home: string; realpath?: (p: string) => string }): boolean {
  const candidates = pathCandidates(target, base, options).filter((candidate) => path.isAbsolute(candidate)).map((candidate) => candidate.toLowerCase());
  return locations.some((location) => candidates.some((candidate) => isAncestorOrSelf(location, candidate)));
}

// Directories a static cd/pushd can have moved to; dynamic marks every later relative target unverifiable.
interface Directories {
  dirs: string[];
  dynamic: boolean;
}

function trackCd(judged: Judged, state: Directories, home: string): void {
  if (judged.index === undefined) return;
  if (!CD_COMMANDS.has(basename(judged.cmd.words[judged.index].text))) return;
  const args = judged.cmd.words.slice(judged.index + 1);
  let i = 0;
  while (i < args.length && isOption(args[i]) && args[i].text !== OPTION_END) i++;
  if (args[i]?.text === OPTION_END) i++;
  const target = args[i];
  if (target === undefined) {
    state.dirs = [...new Set([...state.dirs, home])];
    return;
  }
  if (target.dynamic || target.text === PREVIOUS_DIR) {
    state.dynamic = true;
    return;
  }
  const expanded = target.quoted ? [target.text] : expandBraces(target.text);
  const resolved = expanded?.length === 1 ? (target.quoted ? expanded[0] : resolveTilde(expanded[0])) : undefined;
  if (resolved === undefined) {
    state.dynamic = true;
    return;
  }
  const moved = state.dirs.map((dir) => normalizeToolPath(resolved, dir, home));
  state.dirs = [...new Set([...state.dirs, ...moved])];
}

/** Lowercased strings an inline interpreter script must not contain. */
function protectedMentions(policy: EffectivePolicy, home: string): string[] {
  const mentions = new Set<string>([...PROTECTED_MENTIONS, ...policy.agentDirs]);
  for (const entry of policy.sources.user.policy?.alwaysDeny.paths ?? []) {
    const segments = entry.split(PATH_SEPARATOR);
    const globIndex = segments.findIndex((segment) => GLOB_CHARS.test(segment));
    const literal = segments.slice(0, globIndex === -1 ? segments.length : globIndex).join(PATH_SEPARATOR);
    if (literal === "" || literal === HOME) continue;
    mentions.add(literal);
    if (literal.startsWith(HOME_PREFIX)) mentions.add(path.join(home, literal.slice(HOME_PREFIX.length)));
  }
  return [...mentions].map((mention) => mention.toLowerCase());
}

function mentionsLocation(script: string, mention: string): boolean {
  for (let at = script.indexOf(mention); at !== -1; at = script.indexOf(mention, at + 1)) {
    const before = script[at - 1];
    if (before !== undefined && !MENTION_BEFORE.test(before)) continue;
    if (mention.endsWith(PATH_SEPARATOR)) return true;
    const next = script[at + mention.length];
    if (next === undefined) return true;
    if (mention === GIT_DIR ? GIT_DIR_AFTER.test(next) : !NAME_CHAR.test(next)) return true;
  }
  return false;
}

function inlineScriptText(cmd: SimpleCommand, index: number, command: string): string {
  // A script read from a pipe is written upstream, so the whole command line is scanned.
  if (cmd.stdin === STDIN_PIPE) return command;
  const herestrings = cmd.redirects.filter((redirect) => redirect.op === HERESTRING_OP).map((redirect) => redirect.target);
  return [text(cmd.words.slice(index + 1)), cmd.heredocBody ?? "", ...herestrings].join(WORD_SEPARATOR);
}

function protectedWrite(
  entries: Entry[],
  input: ShellValidationInput,
  home: string,
  unverifiable: string[],
): string | undefined {
  const { policy, cwd, realpath } = input;
  const writeRules = policy.hardRules.filter((rule) =>
    WRITE_CATEGORIES.some((category) => matchPermissionKey(rule.permission, category)),
  );
  const mentions = protectedMentions(policy, home);
  const locations = protectedLocations(writeRules);
  const state: Directories = { dirs: [cwd], dynamic: false };

  // Every command counts, including bare redirects and compound closers (`} > f`, `done > f`, `> f`).
  for (const { cmd, judged } of entries) {
    if (judged !== undefined && hiddenTargets(judged)) {
      unverifiable.push(`targets of "${text(judged.argv)}" are only known at run time`);
    }
    const args = judged?.index === undefined ? [] : expandWords(judged.cmd.words.slice(judged.index + 1), unverifiable);
    const resolve = (targets: Target[]): string[] =>
      targets.flatMap((target) => targetTexts(target, unverifiable)).filter((target) => {
        if (isAnchored(target) || !state.dynamic) return true;
        unverifiable.push(`write target "${target}" after a dynamic cd`);
        return false;
      });
    const destructive = resolve(judged === undefined ? [] : destructiveTargets(judged, args));
    for (const target of [...resolve(writeTargets(cmd, judged, args, unverifiable)), ...destructive]) {
      for (const base of isAnchored(target) ? [cwd] : state.dirs) {
        const candidates = pathCandidates(target, base, { home, realpath });
        // A directory target (rm -rf .pi, mv .pi x) affects everything below it.
        const spellings = [...candidates, ...candidates.map((candidate) => `${candidate}${PATH_SEPARATOR}`)];
        const rule = writeRules.find((hard) => spellings.some((spelling) => matchesHard(hard.pattern, spelling)));
        if (rule) return `write target "${target}" is protected ("${rule.pattern}")`;
      }
    }

    const finds = judged !== undefined && commandName(judged) === FIND_NAME;
    for (const target of destructive) {
      for (const base of isAnchored(target) ? [cwd] : state.dirs) {
        const location = destroyedLocation(target, base, locations, { home, realpath });
        if (location === undefined) continue;
        if (!finds || insideLocation(target, base, locations, { home, realpath })) {
          return `deleting or moving "${target}" would remove protected location "${location}"`;
        }
        unverifiable.push(`find under "${target}" can change protected location "${location}"`);
      }
    }

    if (judged === undefined) continue;
    if (judged.index !== undefined && inlineInterpreterScript(judged.cmd) !== undefined) {
      const script = inlineScriptText(judged.cmd, judged.index, input.command).toLowerCase();
      const mention = mentions.find((needle) => mentionsLocation(script, needle));
      if (mention !== undefined) return `inline script in "${text(judged.argv)}" mentions protected location "${mention}"`;
    }

    trackCd(judged, state, home);
  }
  return undefined;
}

// ─── Rules ───────────────────────────────────────────────────────────────────

// Command names compare case-insensitively (`CURL x` runs curl on macOS); arguments stay case-sensitive.
function lowerFirstWord(words: Word[]): Word[] {
  const [first, ...rest] = words;
  if (first === undefined || first.dynamic) return words;
  return [{ ...first, text: first.text.toLowerCase() }, ...rest];
}

function bashDenyHit(judged: Judged, entries: string[]): string | undefined {
  const argv = lowerFirstWord(judged.argv);
  const raw = lowerFirstWord(judged.raw);
  return entries.find((entry) => {
    const [name, ...rest] = tokens(entry);
    const pattern = name === undefined ? [] : [name.toLowerCase(), ...rest];
    return tokensMatch(pattern, argv, true) || tokensMatch(pattern, raw, true);
  });
}

function lastMatch(rules: PermissionRule[], argv: Word[]): PermissionRule | undefined {
  for (let index = rules.length - 1; index >= 0; index--) {
    if (tokensMatch(tokens(rules[index].pattern), argv, false)) return rules[index];
  }
  return undefined;
}

function ruleVerdict(rules: PermissionRule[], argv: Word[], category: string): Verdict {
  const shown = text(argv);
  const rule = lastMatch(rules, argv);
  if (rule === undefined) {
    return {
      action: ACTION.deny,
      reason: `unlisted command "${shown}"; unlisted ${category} operations are denied by the active permission policy`,
    };
  }
  const source = `rule ${rule.permission} "${rule.pattern}"`;
  if (rule.action === ACTION.deny) return { action: ACTION.deny, reason: `command "${shown}" is denied by ${source}` };
  if (rule.action === ACTION.ask) return { action: ACTION.ask, reason: `command "${shown}" requires confirmation (${source})` };
  return { action: ACTION.allow, reason: source };
}

// `rg --pre CMD` runs CMD on every searched file.
function rgPreprocessor(argv: Word[], unverifiable: string[]): Word | undefined {
  if (basename(argv[0].text) !== RG_NAME) return undefined;
  for (let i = 1; i < argv.length; i++) {
    const word = argv[i];
    if (word.text === OPTION_END) break;
    const value = word.text === RG_PRE
      ? argv[i + 1]
      : word.text.startsWith(RG_PRE_VALUE) ? { ...word, text: word.text.slice(RG_PRE_VALUE.length) } : undefined;
    if (value === undefined) continue;
    if (value.dynamic) {
      unverifiable.push(`dynamic rg preprocessor "${value.text}"`);
      return undefined;
    }
    return value;
  }
  return undefined;
}

function commandVerdict(judged: Judged, rules: PermissionRule[], category: string, unverifiable: string[]): Verdict {
  let verdict = ruleVerdict(rules, judged.argv, category);
  const wrapperEnd = judged.raw.length - judged.argv.length;
  const lowered = judged.cmd.words.slice(judged.cmd.words.length - judged.raw.length);
  const privileged = lowered.slice(0, wrapperEnd + 1).some((word) => PRIVILEGE_WRAPPERS.has(basename(word.text)));
  if (privileged) verdict = stricter(verdict, ruleVerdict(rules, judged.raw, category));
  const preprocessor = rgPreprocessor(judged.argv, unverifiable);
  if (preprocessor !== undefined) verdict = stricter(verdict, ruleVerdict(rules, [preprocessor], category));
  return verdict;
}

// ─── Validation ──────────────────────────────────────────────────────────────

function deny(reason: string, hard: boolean, commands: string[]): ShellDecision {
  return { action: ACTION.deny, hard, reason, commands };
}

function gitDeny(command: string, policy: EffectivePolicy): ShellDecision | undefined {
  if (!policy.denyGitWrite) return undefined;
  const violations = findGitViolations(command);
  if (violations.length === 0) return undefined;
  return deny(`git write operations are disabled (${violations.join(", ")})`, true, []);
}

function shellWord(word: Word): string {
  if (word.dynamic) return word.text;
  return SINGLE_QUOTE + word.text.replaceAll(SINGLE_QUOTE, ESCAPED_SINGLE_QUOTE) + SINGLE_QUOTE;
}

// The git guard matches names case-sensitively, so every flattened git command is checked again with lowered names.
function loweredGitDeny(entries: Entry[], policy: EffectivePolicy, commands: string[]): ShellDecision | undefined {
  if (!policy.denyGitWrite) return undefined;
  const violations = entries
    .filter(({ judged }) => judged !== undefined && commandName(judged) === GIT_NAME)
    .flatMap(({ cmd }) => findGitViolations(cmd.words.map(shellWord).join(WORD_SEPARATOR)));
  if (violations.length === 0) return undefined;
  return deny(`git write operations are disabled (${[...new Set(violations)].join(", ")})`, true, commands);
}

// Writes the ported scan misses: case-variant command names and sort -o.
function validatorWrites(entries: Entry[]): string[] {
  const labels: string[] = [];
  for (const { cmd, judged, renamed } of entries) {
    const name = judged === undefined ? undefined : commandName(judged);
    if (judged?.index === undefined || name === undefined) continue;
    if (renamed && (mutatesFiles(cmd) || inlineInterpreterScript(cmd) !== undefined)) labels.push(`${MUTATION_LABEL}: ${name}`);
    if (name === SORT_NAME && sortOutputs(cmd.words.slice(judged.index + 1)).length > 0) labels.push(SORT_WRITE_LABEL);
  }
  return labels;
}

// Deferred: alwaysDeny.bash and protected-path checks do not apply to powershell; only a blanket rule allows it.
function validatePowershell(input: ShellValidationInput, rules: PermissionRule[]): ShellDecision {
  const commands = [input.command];
  let rule: PermissionRule | undefined;
  for (let index = rules.length - 1; index >= 0 && rule === undefined; index--) {
    if (matchPattern(rules[index].pattern, input.command)) rule = rules[index];
  }
  if (rule === undefined || rule.pattern !== WILDCARD) return deny(POWERSHELL_REASON, false, commands);
  const reason = `rule ${rule.permission} "${rule.pattern}"`;
  if (rule.action === ACTION.deny) return deny(reason, false, commands);
  return { action: rule.action, hard: false, reason, commands };
}

// A parent whose last edit or write rule is a blanket deny is a ceiling its children cannot write through.
function inheritedWriteCeiling(inherited: PermissionRule[]): boolean {
  return WRITE_CATEGORIES.some((category) => {
    const last = inherited.filter((rule) => matchPermissionKey(rule.permission, category)).at(-1);
    return last?.action === ACTION.deny && last.pattern === WILDCARD;
  });
}

function canWrite(policy: EffectivePolicy, inherited: PermissionRule[]): boolean {
  if (inheritedWriteCeiling(inherited)) return false;
  return policy.rules.some(
    (rule) =>
      rule.action === ACTION.allow &&
      WRITE_CATEGORIES.some((category) => matchPermissionKey(rule.permission, category)),
  );
}

export function validateShellCommand(input: ShellValidationInput): ShellDecision {
  const { command, category, policy, inherited } = input;
  if (command.trim() === "") return { action: ACTION.allow, hard: false, reason: "empty command", commands: [] };

  const git = gitDeny(command, policy);
  if (git) return git;

  const rules = [...policy.rules, ...inherited].filter((rule) => matchPermissionKey(rule.permission, category));
  if (!POSIX_SHELL_CATEGORIES.includes(category)) return validatePowershell(input, rules);

  const home = input.home ?? homedir();
  const unverifiable: string[] = [];
  const flattened: Flat[] = [];
  flatten(parseCommands(command), flattened, unverifiable);
  const entries: Entry[] = flattened.map((flat) => ({
    cmd: flat.cmd,
    judged: judge(flat, unverifiable),
    renamed: flat.cmd !== flat.original,
  }));
  const judgedCommands = entries
    .map((entry) => entry.judged)
    .filter((judged): judged is Judged => judged !== undefined);
  const commands = judgedCommands.map((judged) => text(judged.argv));

  const loweredGit = loweredGitDeny(entries, policy, commands);
  if (loweredGit) return loweredGit;

  const protectedReason = protectedWrite(entries, input, home, unverifiable);
  if (protectedReason !== undefined) return deny(protectedReason, true, commands);

  for (const judged of judgedCommands) {
    const entry = bashDenyHit(judged, policy.bashDeny);
    if (entry !== undefined) return deny(`"${text(judged.argv)}" matches alwaysDeny.bash entry "${entry}"`, true, commands);
  }

  if (!canWrite(policy, inherited)) {
    const writes = [...new Set([...findWriteViolations(command), ...validatorWrites(entries)])];
    if (writes.length > 0) return deny(`this agent cannot change files (${writes.join(", ")})`, false, commands);
  }

  const verdicts = judgedCommands.map((judged) => commandVerdict(judged, rules, category, unverifiable));
  const verdict: Verdict =
    verdicts.length > 0 ? verdicts.reduce(stricter) : { action: ACTION.allow, reason: NO_COMMAND_REASON };
  if (verdict.action === ACTION.deny) return deny(verdict.reason, false, commands);

  const unique = [...new Set(unverifiable)];
  if (unique.length === 0) return { action: verdict.action, hard: false, reason: verdict.reason, commands };
  const unverified = `cannot verify the command: ${unique.join("; ")}`;
  const reason = verdict.action === ACTION.ask ? `${verdict.reason}; ${unverified}` : unverified;
  return { action: ACTION.ask, hard: false, reason, commands };
}
