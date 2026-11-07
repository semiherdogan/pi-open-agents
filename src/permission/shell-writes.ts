// Ported from the author's dotfiles pi extensions.
/**
 * Detects shell commands that write files: redirects, mutating commands,
 * in-place editors, tee, inline interpreter scripts, eval and opaque shells.
 */

import { basename, commandIndex, nestedScripts, parseCommands, type Redirect, type SimpleCommand, type Word } from "./shell.ts";

// ─── Constants ───────────────────────────────────────────────────────────────

const OPTION_PREFIX = "-";
const LONG_PREFIX = "--";
const OPTION_END = "--";
const STDIN_DASH = "-";
const VALUE_SEPARATOR = "=";
const MAX_SNIPPET_LENGTH = 40;

const LABEL_REDIRECT = "redirect";
const LABEL_SHELL_EVAL = "shell eval";
const LABEL_SED = "sed -i";
const LABEL_SED_WRITE = "sed w";
const LABEL_SED_EXEC = "sed e";
const LABEL_PERL = "perl -i";
const LABEL_TEE = "tee";
const LABEL_INLINE = "inline script";
const LABEL_MUTATION = "file mutation";

const EVAL_NAME = "eval";
const TEE_NAME = "tee";
const SHELL_COMMAND_SUFFIX = "-c";
const PIPE_PREFIX = "|";
const SUBSTITUTION_DETAIL = "<(...)";

const WRITE_REDIRECT_OPS = new Set([">", ">>", ">|", "&>", "&>>", "<>", ">&"]);
const DUP_OP = ">&";
// `>&2`, `>&-` and `>&2-` duplicate or close a descriptor instead of writing a file.
const FD_TARGET = /^(?:\d+-?|-)$/;
const HARMLESS_PATHS = new Set(["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"]);
const FD_PATH = /^\/dev\/fd\/\d+$/;
const PROCESS_SUBSTITUTION_PREFIXES = ["<(", ">("];
// Download output that goes nowhere or to stdout.
const DISCARD_TARGETS = new Set(["/dev/null", "-"]);

type Checker = (args: string[]) => boolean;
type Scan = { hit: boolean; takesNext: boolean };

// ─── Option Helpers ──────────────────────────────────────────────────────────

function isShortCluster(arg: string): boolean {
  return arg.startsWith(OPTION_PREFIX) && !arg.startsWith(LONG_PREFIX) && arg.length > OPTION_PREFIX.length;
}

function longName(flag: string): string {
  const end = flag.indexOf(VALUE_SEPARATOR);
  return end === -1 ? flag : flag.slice(0, end);
}

function longValue(flag: string, next: string | undefined): string | undefined {
  const end = flag.indexOf(VALUE_SEPARATOR);
  return end === -1 ? next : flag.slice(end + 1);
}

function hasLetter(arg: string, letters: Set<string>): boolean {
  return isShortCluster(arg) && [...arg.slice(1)].some((letter) => letters.has(letter));
}

// Walks a short cluster; letters in `stops` take a value, so the rest of the cluster is data.
function scanCluster(arg: string, targets: Set<string>, stops: Set<string>): Scan {
  const letters = arg.slice(1);
  for (let i = 0; i < letters.length; i++) {
    if (targets.has(letters[i])) return { hit: true, takesNext: false };
    if (stops.has(letters[i])) return { hit: false, takesNext: i === letters.length - 1 };
  }
  return { hit: false, takesNext: false };
}

// Looks at option words only, up to the first positional (the script or file).
function flagHit(args: string[], targets: Set<string>, stops: Set<string>, longPrefix?: string): boolean {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === OPTION_END || !arg.startsWith(OPTION_PREFIX) || arg === OPTION_PREFIX) break;
    if (longPrefix !== undefined && arg.startsWith(longPrefix)) return true;
    if (!isShortCluster(arg)) continue;
    const scan = scanCluster(arg, targets, stops);
    if (scan.hit) return true;
    if (scan.takesNext) i++;
  }
  return false;
}

function isProcessSubstitution(word: Word): boolean {
  return word.dynamic && PROCESS_SUBSTITUTION_PREFIXES.some((prefix) => word.text.startsWith(prefix));
}

function isHarmlessPath(word: Word): boolean {
  return !word.dynamic && (HARMLESS_PATHS.has(word.text) || FD_PATH.test(word.text));
}

function redirectViolation(redirect: Redirect): string | undefined {
  if (!WRITE_REDIRECT_OPS.has(redirect.op)) return undefined;
  if (redirect.op === DUP_OP && !redirect.targetDynamic && FD_TARGET.test(redirect.target)) return undefined;
  const target: Word = { text: redirect.target, quoted: false, dynamic: redirect.targetDynamic };
  if (isProcessSubstitution(target) || isHarmlessPath(target)) return undefined;
  return `${LABEL_REDIRECT} "${snippet(`${redirect.fd ?? ""}${redirect.op}`, [redirect.target])}"`;
}

// ─── Command Checkers ────────────────────────────────────────────────────────

const CURL_REMOTE_NAME = new Set(["--remote-name", "--remote-name-all"]);
const CURL_OUTPUT_DIR = "--output-dir";
// Options whose value is a file curl writes.
const CURL_FILE_OUTPUTS = new Set([
  "--output", "--dump-header", "--cookie-jar", "--trace", "--trace-ascii", "--stderr", "--libcurl", "--etag-save", "--hsts",
  "--alt-svc",
]);
// A config file can set output= and the other write options.
const CURL_CONFIG = "--config";
const CURL_REMOTE_NAME_LETTER = "O";
const CURL_CONFIG_LETTER = "K";
const CURL_FILE_OUTPUT_LETTERS = new Set(["o", "D", "c"]);
// Short options that take a value, so the rest of a cluster is not flags.
const CURL_VALUE_LETTERS = new Set([..."AbCdeEFHmPQrtTuUwxXyYz"]);

const curlWrites: Checker = (args) => {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === OPTION_END) break;
    const name = longName(arg);
    if (CURL_REMOTE_NAME.has(name) || name === CURL_OUTPUT_DIR || name === CURL_CONFIG) return true;
    if (CURL_FILE_OUTPUTS.has(name)) {
      const value = longValue(arg, args[i + 1]);
      if (value === undefined || !DISCARD_TARGETS.has(value)) return true;
      if (name === arg) i++;
      continue;
    }
    if (!isShortCluster(arg)) continue;
    const letters = arg.slice(1);
    for (let j = 0; j < letters.length; j++) {
      const letter = letters[j];
      if (letter === CURL_REMOTE_NAME_LETTER || letter === CURL_CONFIG_LETTER) return true;
      if (CURL_FILE_OUTPUT_LETTERS.has(letter)) {
        const rest = letters.slice(j + 1);
        const value = rest === "" ? args[i + 1] : rest;
        if (value === undefined || !DISCARD_TARGETS.has(value)) return true;
        if (rest === "") i++;
        break;
      }
      if (CURL_VALUE_LETTERS.has(letter)) {
        if (j === letters.length - 1) i++;
        break;
      }
    }
  }
  return false;
};

const WGET_SPIDER = "--spider";
const WGET_OUTPUT_LONG = "--output-document";
const WGET_OUTPUT_LETTER = "O";
const WGET_TARGETS = new Set([WGET_OUTPUT_LETTER]);
const WGET_VALUE_LETTERS = new Set([..."aeilotwBDIPQRTUXA"]);

const wgetWrites: Checker = (args) => {
  if (args.includes(WGET_SPIDER)) return false;
  let output: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === OPTION_END) break;
    if (longName(arg) === WGET_OUTPUT_LONG) {
      output = longValue(arg, args[i + 1]);
      continue;
    }
    if (!isShortCluster(arg)) continue;
    const letters = arg.slice(1);
    for (let j = 0; j < letters.length; j++) {
      const letter = letters[j];
      if (WGET_TARGETS.has(letter)) {
        const rest = letters.slice(j + 1);
        output = rest === "" ? args[i + 1] : rest;
        if (rest === "") i++;
        break;
      }
      if (WGET_VALUE_LETTERS.has(letter)) {
        if (j === letters.length - 1) i++;
        break;
      }
    }
  }
  return output === undefined || !DISCARD_TARGETS.has(output);
};

const PATCH_DRY_RUN = "--dry-run";
const patchWrites: Checker = (args) => !args.includes(PATCH_DRY_RUN);

const TAR_MODE_LETTERS = new Set([..."cxruA"]);
const TAR_MODE_LONG = new Set(["--create", "--extract", "--get", "--append", "--update", "--delete"]);

const tarWrites: Checker = (args) => {
  if (args.some((arg) => TAR_MODE_LONG.has(longName(arg)))) return true;
  if (args.length > 0 && !args[0].startsWith(OPTION_PREFIX) && [...args[0]].some((letter) => TAR_MODE_LETTERS.has(letter))) return true;
  return args.some((arg) => hasLetter(arg, TAR_MODE_LETTERS));
};

const UNZIP_READ_LETTERS = new Set([..."lptZv"]);
const unzipWrites: Checker = (args) => !args.some((arg) => hasLetter(arg, UNZIP_READ_LETTERS));

const GZIP_READ_LETTERS = new Set([..."clt"]);
const GZIP_STDOUT = "--stdout";
const gzipWrites: Checker = (args) => !args.some((arg) => arg === GZIP_STDOUT || hasLetter(arg, GZIP_READ_LETTERS));

const FIND_DELETE = "-delete";
const findWrites: Checker = (args) => args.includes(FIND_DELETE);

// Like flagHit, but options may follow positionals (Go and GNU argument parsers permute).
function anyFlag(args: string[], targets: Set<string>, stops: Set<string>, longNames: Set<string>): boolean {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === OPTION_END) break;
    if (arg.startsWith(LONG_PREFIX)) {
      if (longNames.has(longName(arg))) return true;
      continue;
    }
    if (!isShortCluster(arg)) continue;
    const scan = scanCluster(arg, targets, stops);
    if (scan.hit) return true;
    if (scan.takesNext) i++;
  }
  return false;
}

const YQ_NAME = "yq";
const YQ_IN_PLACE_LETTER = "i";
const YQ_SPLIT_LETTER = "s";
const YQ_SPLIT_LONG = new Set(["--split-exp", "--split-exp-file"]);
const YQ_WRITE_LETTERS = new Set([YQ_IN_PLACE_LETTER, YQ_SPLIT_LETTER]);
const YQ_WRITE_LONG = new Set(["--inplace", ...YQ_SPLIT_LONG]);
const YQ_VALUE_LETTERS = new Set([..."fIpo"]);
const yqWrites: Checker = (args) => anyFlag(args, YQ_WRITE_LETTERS, YQ_VALUE_LETTERS, YQ_WRITE_LONG);
const yqSplits = (args: string[]): boolean =>
  anyFlag(args, new Set([YQ_SPLIT_LETTER]), YQ_VALUE_LETTERS, YQ_SPLIT_LONG);

const FILE_COMPILE_LETTERS = new Set(["C"]);
const FILE_COMPILE_LONG = new Set(["--compile"]);
const FILE_VALUE_LETTERS = new Set([..."efFmP"]);
const fileWrites: Checker = (args) => anyFlag(args, FILE_COMPILE_LETTERS, FILE_VALUE_LETTERS, FILE_COMPILE_LONG);

const UNIQ_VALUE_LETTERS = new Set([..."fsw"]);
const UNIQ_VALUE_LONG = new Set(["--skip-fields", "--skip-chars", "--check-chars"]);
const UNIQ_OUTPUT_POSITION = 1;

// `uniq IN OUT` writes its second operand.
const uniqWrites: Checker = (args) => {
  const operands: string[] = [];
  let options = true;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (options && arg === OPTION_END) {
      options = false;
      continue;
    }
    if (!options || !arg.startsWith(OPTION_PREFIX) || arg === STDIN_DASH) {
      operands.push(arg);
      continue;
    }
    if (arg.startsWith(LONG_PREFIX)) {
      if (UNIQ_VALUE_LONG.has(arg)) i++;
      continue;
    }
    if (scanCluster(arg, new Set(), UNIQ_VALUE_LETTERS).takesNext) i++;
  }
  const output = operands[UNIQ_OUTPUT_POSITION];
  return output !== undefined && !DISCARD_TARGETS.has(output) && !HARMLESS_PATHS.has(output);
};

const LIGHTPANDA_WRITE_LONG = new Set(["--cookie-jar", "--output"]);
const LIGHTPANDA_OUTPUT_LETTER = "o";
const lightpandaWrites: Checker = (args) =>
  args.some((arg) => LIGHTPANDA_WRITE_LONG.has(longName(arg)) || (isShortCluster(arg) && arg[1] === LIGHTPANDA_OUTPUT_LETTER));

const DEFAULTS_WRITE_SUBCOMMANDS = new Set(["write", "delete", "import", "rename"]);
const DEFAULTS_HOST_OPTION = "-host";

const defaultsWrites: Checker = (args) => {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === DEFAULTS_HOST_OPTION) i++;
    else if (!args[i].startsWith(OPTION_PREFIX)) return DEFAULTS_WRITE_SUBCOMMANDS.has(args[i]);
  }
  return false;
};

const ALWAYS_MUTATING = new Set([
  "cp", "mv", "rm", "touch", "mkdir", "rmdir", "ln", "chmod", "chown", "truncate", "install", "dd", "rsync", "ditto", "unlink",
]);
const CONDITIONAL_MUTATING = new Map<string, Checker>([
  ["defaults", defaultsWrites],
  ["curl", curlWrites],
  ["wget", wgetWrites],
  ["patch", patchWrites],
  ["tar", tarWrites],
  ["unzip", unzipWrites],
  ["gzip", gzipWrites],
  ["gunzip", gzipWrites],
  ["find", findWrites],
  [YQ_NAME, yqWrites],
  ["file", fileWrites],
  ["uniq", uniqWrites],
  ["lightpanda", lightpandaWrites],
]);
// Without context these would flag every mention, so the raw token scan skips them.
const TOKEN_SKIPPED = new Set(["curl", "wget", "defaults", "find", YQ_NAME, "file", "uniq", "lightpanda"]);
const TOKEN_MUTATING = new Set([
  ...ALWAYS_MUTATING,
  ...[...CONDITIONAL_MUTATING.keys()].filter((name) => !TOKEN_SKIPPED.has(name)),
]);
const TOKEN_SPLIT = /[\s;&|(){}`'"\\]+/;

const SED_NAMES = new Set(["sed", "gsed"]);
const SED_IN_PLACE_LONG = "--in-place";
// GNU -i[SUFFIX], BSD -i EXT and -I EXT.
const SED_TARGETS = new Set(["i", "I"]);
const SED_STOPS = new Set([..."efl"]);
const SED_SCRIPT_LETTER = "e";
const SED_FILE_LETTER = "f";
const SED_LINE_LENGTH_LETTER = "l";
const SED_SCRIPT_LONG = "--expression";
const SED_FILE_LONG = "--file";
const SED_VALUE_LONG = new Set([SED_FILE_LONG, "--line-length"]);
// Script commands: w/W write a file, e runs a command, the rest only matter for skipping.
const SED_WRITE_COMMANDS = new Set(["w", "W"]);
const SED_EXEC_COMMAND = "e";
const SED_SUBSTITUTE = "s";
const SED_TRANSLITERATE = "y";
const SED_WRITE_FLAG = "w";
const SED_EXEC_FLAG = "e";
const SED_FLAG = /[gpiImMew0-9]/;
// Commands whose argument runs to the end of the line.
const SED_LINE_COMMANDS = new Set([..."aicrR:#"]);
// Commands whose label runs to a `;` or the end of the line.
const SED_LABEL_COMMANDS = new Set([..."btTv"]);
const SED_COMMAND_SEPARATORS = new Set([";", "\n", "{", "}", "!", " ", "\t"]);
const SED_LABEL_END = /[;\n]/;
const SED_ADDRESS_DIGIT = /[0-9]/;
const SED_REGEX_FLAG = /[IM]/;
const SED_ADDRESS_LAST = "$";
const SED_ADDRESS_STEP = "~";
const SED_ADDRESS_OFFSET = "+";
const SED_ADDRESS_RANGE = ",";
const SED_ADDRESS_NEGATE = "!";
const SED_REGEX_DELIMITER = "/";
const SED_CUSTOM_DELIMITER = "\\";
const SED_ESCAPE = "\\";
const NEWLINE = "\n";
const SED_BLANK = /[ \t]/;
// A word that can be a BSD `-i` backup suffix but holds no sed address delimiter or command separator.
const SED_SUFFIX = /^[A-Za-z0-9._~-]*$/;
// Text that is not yet known when the script is checked.
const DYNAMIC_TEXT = /[$`]/;
const PERL_NAME = "perl";
const PERL_STOPS = new Set([..."IMmCFDx"]);

const PYTHON_NAME = /^python(?:\d+(?:\.\d+)*)?$/;
const INLINE_FLAGS = new Set(["-c", "-e", "-E", "--eval", "-p", "--print"]);
const INLINE_CLUSTER_LETTERS = new Set(["e", "c"]);
const INFO_FLAGS = new Set(["--version", "-V", "-v", "--help", "-h"]);
const PYTHON_MODULE_FLAG = "-m";

type InterpreterSpec = { valueWords: Set<string>; clusterStops: Set<string>; inlineCluster: boolean };

const NODE_VALUE_WORDS = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader"]);
const PYTHON_SPEC: InterpreterSpec = { valueWords: new Set(["-W", "-X"]), clusterStops: new Set([..."WXm"]), inlineCluster: true };
const RUBY_SPEC: InterpreterSpec = { valueWords: new Set(["-I", "-r", "-C", "-E"]), clusterStops: new Set([..."IrCEK"]), inlineCluster: true };
const PERL_SPEC: InterpreterSpec = { valueWords: new Set(["-I", "-M", "-m", "-C"]), clusterStops: PERL_STOPS, inlineCluster: true };
const NODE_SPEC: InterpreterSpec = { valueWords: NODE_VALUE_WORDS, clusterStops: new Set(), inlineCluster: false };
const INTERPRETERS = new Map<string, InterpreterSpec>([
  ["node", NODE_SPEC],
  ["ruby", RUBY_SPEC],
  [PERL_NAME, PERL_SPEC],
  ["deno", NODE_SPEC],
  ["bun", NODE_SPEC],
]);

function interpreterSpec(name: string): InterpreterSpec | undefined {
  return PYTHON_NAME.test(name) ? PYTHON_SPEC : INTERPRETERS.get(name);
}

// Returns the offending flag (or the bare name when stdin is the script), undefined when a script file or module runs.
function inlineScript(name: string, spec: InterpreterSpec, cmd: SimpleCommand, args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === OPTION_END) return i + 1 < args.length ? undefined : stdinScript(name, cmd);
    if (arg === STDIN_DASH) return `${name} ${arg}`;
    if (!arg.startsWith(OPTION_PREFIX)) return undefined;
    if (arg === PYTHON_MODULE_FLAG && PYTHON_NAME.test(name)) return undefined;
    if (INFO_FLAGS.has(arg)) return undefined;
    if (INLINE_FLAGS.has(longName(arg))) return `${name} ${longName(arg)}`;
    if (spec.valueWords.has(arg)) {
      i++;
      continue;
    }
    if (!spec.inlineCluster || !isShortCluster(arg)) continue;
    const scan = scanCluster(arg, INLINE_CLUSTER_LETTERS, spec.clusterStops);
    if (scan.hit) return `${name} ${arg}`;
    if (scan.takesNext) i++;
  }
  return stdinScript(name, cmd);
}

// ─── Sed Scripts ─────────────────────────────────────────────────────────────

type SedEffects = { writes: Word[]; exec: boolean };

// Scripts given with -e/--expression, else the first operand (and the second after a BSD `-i EXT`).
function sedScripts(argWords: Word[]): Word[] {
  const scripts: Word[] = [];
  const operands: Word[] = [];
  let explicit = false;
  let separateSuffix = false;
  let options = true;
  for (let i = 0; i < argWords.length; i++) {
    const word = argWords[i];
    const arg = word.text;
    if (options && arg === OPTION_END) {
      options = false;
      continue;
    }
    if (!options || !arg.startsWith(OPTION_PREFIX) || arg === STDIN_DASH) {
      operands.push(word);
      continue;
    }
    if (arg.startsWith(LONG_PREFIX)) {
      const name = longName(arg);
      const attached = name !== arg;
      if (name === SED_SCRIPT_LONG) {
        explicit = true;
        const value = attached ? { ...word, text: arg.slice(name.length + VALUE_SEPARATOR.length) } : argWords[i + 1];
        if (value !== undefined) scripts.push(value);
      }
      if (name === SED_FILE_LONG) explicit = true;
      if (!attached && (name === SED_SCRIPT_LONG || SED_VALUE_LONG.has(name))) i++;
      continue;
    }
    const letters = arg.slice(OPTION_PREFIX.length);
    for (let j = 0; j < letters.length; j++) {
      const letter = letters[j];
      const rest = letters.slice(j + 1);
      if (letter === SED_SCRIPT_LETTER) {
        explicit = true;
        const value = rest !== "" ? { ...word, text: rest } : argWords[++i];
        if (value !== undefined) scripts.push(value);
        break;
      }
      if (letter === SED_FILE_LETTER || letter === SED_LINE_LENGTH_LETTER) {
        if (letter === SED_FILE_LETTER) explicit = true;
        if (rest === "") i++;
        break;
      }
      if (SED_TARGETS.has(letter)) {
        separateSuffix = rest === "";
        break;
      }
    }
  }
  if (explicit) return scripts;
  // GNU `-i` takes no separate suffix, so `sed -i SCRIPT FILE` names files after the script; only a word that
  // reads as a BSD suffix (`''`, `.bak`, `bak`) makes the next operand the script.
  const bsdSuffix = separateSuffix && operands.length > 1 && !operands[0].dynamic && SED_SUFFIX.test(operands[0].text);
  return operands.slice(0, bsdSuffix ? 2 : 1);
}

// Index just past the closing delimiter, honoring backslash escapes.
function skipDelimited(script: string, from: number, delimiter: string): number {
  let i = from;
  while (i < script.length && script[i] !== delimiter) i += script[i] === SED_ESCAPE ? 2 : 1;
  return i + 1;
}

function skipSedAddress(script: string, from: number): number {
  const skipBlanks = (i: number): number => {
    while (i < script.length && SED_BLANK.test(script[i])) i++;
    return i;
  };
  const skipDigits = (i: number): number => {
    while (i < script.length && SED_ADDRESS_DIGIT.test(script[i])) i++;
    return i;
  };
  const one = (start: number): number => {
    let i = start;
    const ch = script[i];
    if (ch === SED_ADDRESS_LAST) return i + 1;
    if (ch === SED_ADDRESS_OFFSET || ch === SED_ADDRESS_STEP) return skipDigits(i + 1);
    if (ch !== undefined && SED_ADDRESS_DIGIT.test(ch)) {
      i = skipDigits(i);
      return script[i] === SED_ADDRESS_STEP ? skipDigits(i + 1) : i;
    }
    if (ch === SED_REGEX_DELIMITER) i = skipDelimited(script, i + 1, SED_REGEX_DELIMITER);
    else if (ch === SED_CUSTOM_DELIMITER && i + 1 < script.length) i = skipDelimited(script, i + 2, script[i + 1]);
    else return i;
    while (i < script.length && SED_REGEX_FLAG.test(script[i])) i++;
    return i;
  };
  let i = skipBlanks(one(from));
  if (script[i] === SED_ADDRESS_RANGE) i = skipBlanks(one(skipBlanks(i + 1)));
  while (i < script.length && (script[i] === SED_ADDRESS_NEGATE || SED_BLANK.test(script[i]))) i++;
  return i;
}

// Conservative scan for w/W/e commands and the s///w and s///e flags.
function parseSedScript(script: string): { writes: string[]; exec: boolean } {
  const writes: string[] = [];
  let exec = false;
  const lineEnd = (from: number): number => {
    const end = script.indexOf(NEWLINE, from);
    return end === -1 ? script.length : end;
  };
  let i = 0;
  while (i < script.length) {
    if (SED_COMMAND_SEPARATORS.has(script[i])) {
      i++;
      continue;
    }
    const at = skipSedAddress(script, i);
    const command = script[at];
    if (command === undefined) break;
    i = at + 1;
    if (SED_WRITE_COMMANDS.has(command)) {
      const end = lineEnd(i);
      writes.push(script.slice(i, end).trim());
      i = end;
    } else if (command === SED_EXEC_COMMAND) {
      exec = true;
      i = lineEnd(i);
    } else if (SED_LINE_COMMANDS.has(command)) {
      i = lineEnd(i);
    } else if (SED_LABEL_COMMANDS.has(command)) {
      while (i < script.length && !SED_LABEL_END.test(script[i])) i++;
    } else if (command === SED_SUBSTITUTE || command === SED_TRANSLITERATE) {
      const delimiter = script[i];
      if (delimiter === undefined || delimiter === NEWLINE || delimiter === SED_ESCAPE) break;
      i = skipDelimited(script, skipDelimited(script, i + 1, delimiter), delimiter);
      while (command === SED_SUBSTITUTE && i < script.length && SED_FLAG.test(script[i])) {
        const flag = script[i++];
        if (flag === SED_EXEC_FLAG) exec = true;
        if (flag === SED_WRITE_FLAG) {
          const end = lineEnd(i);
          writes.push(script.slice(i, end).trim());
          i = end;
        }
      }
    }
  }
  return { writes, exec };
}

function sedEffects(argWords: Word[]): SedEffects {
  const effects: SedEffects = { writes: [], exec: false };
  for (const script of sedScripts(argWords)) {
    const parsed = parseSedScript(script.text);
    effects.exec ||= parsed.exec;
    for (const text of parsed.writes) {
      const target: Word = { text, quoted: true, dynamic: script.dynamic && DYNAMIC_TEXT.test(text) };
      if (!isHarmlessPath(target)) effects.writes.push(target);
    }
  }
  return effects;
}

function stdinScript(name: string, cmd: SimpleCommand): string | undefined {
  return cmd.stdin !== undefined ? name : undefined;
}

function teeWrites(args: Word[]): boolean {
  let options = true;
  for (const arg of args) {
    if (options && arg.text === OPTION_END) {
      options = false;
      continue;
    }
    if (options && arg.text.startsWith(OPTION_PREFIX) && arg.text !== STDIN_DASH) continue;
    if (!isProcessSubstitution(arg) && !isHarmlessPath(arg)) return true;
  }
  return false;
}

function snippet(name: string, args: string[]): string {
  return [name, ...args].join(" ").slice(0, MAX_SNIPPET_LENGTH);
}

function checkTokens(text: string, violations: string[]): void {
  for (const token of text.split(TOKEN_SPLIT)) {
    const name = basename(token);
    if (TOKEN_MUTATING.has(name)) violations.push(`${LABEL_MUTATION}: ${name}`);
  }
}

// ─── Command Walk ────────────────────────────────────────────────────────────

function checkCommand(cmd: SimpleCommand, violations: string[]): void {
  for (const redirect of cmd.redirects) {
    const violation = redirectViolation(redirect);
    if (violation !== undefined) violations.push(violation);
  }

  const index = commandIndex(cmd.words);
  if (index === undefined) return;
  const name = basename(cmd.words[index].text);
  const argWords = cmd.words.slice(index + 1);
  const args = argWords.map((word) => word.text);

  if (name === EVAL_NAME) violations.push(`${LABEL_SHELL_EVAL} "${EVAL_NAME}"`);

  // nestedScripts is not recursive, so the commands it returns go through checkCommands again.
  const nested = nestedScripts(cmd);
  if (nested.opaque) {
    const detail = nested.substitution !== undefined
      ? SUBSTITUTION_DETAIL
      : nested.piped ? `${PIPE_PREFIX} ${name}` : `${name} ${SHELL_COMMAND_SUFFIX}`;
    violations.push(`${LABEL_SHELL_EVAL} "${detail}"`);
  }
  checkCommands(nested.commands, violations);
  // The nested source is not exposed, so fall back to the words of the wrapper command.
  if (nested.commands.some((inner) => inner.unterminated)) checkTokens(cmd.words.map((word) => word.text).join(" "), violations);

  if (ALWAYS_MUTATING.has(name) || CONDITIONAL_MUTATING.get(name)?.(args)) violations.push(`${LABEL_MUTATION}: ${name}`);

  if (SED_NAMES.has(name)) {
    if (flagHit(args, SED_TARGETS, SED_STOPS, SED_IN_PLACE_LONG)) violations.push(`${LABEL_SED} "${snippet(name, args)}"`);
    const effects = sedEffects(argWords);
    if (effects.writes.length > 0) violations.push(`${LABEL_SED_WRITE} "${snippet(name, args)}"`);
    if (effects.exec) violations.push(`${LABEL_SED_EXEC} "${snippet(name, args)}"`);
  }
  if (name === PERL_NAME && flagHit(args, SED_TARGETS, PERL_STOPS)) violations.push(`${LABEL_PERL} "${snippet(name, args)}"`);
  if (name === TEE_NAME && teeWrites(argWords)) violations.push(`${LABEL_TEE} "${TEE_NAME}"`);

  const spec = interpreterSpec(name);
  if (spec !== undefined) {
    const inline = inlineScript(name, spec, cmd, args);
    if (inline !== undefined) violations.push(`${LABEL_INLINE} "${inline}"`);
  }
}

function checkCommands(commands: SimpleCommand[], violations: string[]): void {
  for (const cmd of commands) checkCommand(cmd, violations);
}

/** Labels of every file write the script may perform. */
export function findWriteViolations(command: string): string[] {
  const violations: string[] = [];
  const commands = parseCommands(command);
  checkCommands(commands, violations);
  // An unterminated quote makes the parse unreliable, so every token is a candidate: over-block rather than under-block.
  if (commands.some((cmd) => cmd.unterminated)) checkTokens(command, violations);
  return [...new Set(violations)];
}

// ─── Per-Command Classification (bash validator) ─────────────────────────────

/** True when the redirect writes a file (not a descriptor dup, a harmless device or a process substitution). */
export function isFileWriteRedirect(redirect: Redirect): boolean {
  return redirectViolation(redirect) !== undefined;
}

/** True when this single command (nested scripts excluded) mutates files through its arguments. */
export function mutatesFiles(cmd: SimpleCommand): boolean {
  const index = commandIndex(cmd.words);
  if (index === undefined) return false;
  const name = basename(cmd.words[index].text);
  const argWords = cmd.words.slice(index + 1);
  const args = argWords.map((word) => word.text);
  if (ALWAYS_MUTATING.has(name) || CONDITIONAL_MUTATING.get(name)?.(args)) return true;
  if (SED_NAMES.has(name)) {
    if (flagHit(args, SED_TARGETS, SED_STOPS, SED_IN_PLACE_LONG)) return true;
    const effects = sedEffects(argWords);
    if (effects.writes.length > 0 || effects.exec) return true;
  }
  if (name === PERL_NAME && flagHit(args, SED_TARGETS, PERL_STOPS)) return true;
  return name === TEE_NAME && teeWrites(argWords);
}

export interface EmbeddedWrites {
  /** Files written that are not plain arguments (sed `w FILE`); sed does not expand `~` in them. */
  targets: Word[];
  /** Reasons the written files or the run commands are only known at run time. */
  unverifiable: string[];
}

/** Writes and commands hidden inside an argument of this single command. */
export function embeddedWrites(cmd: SimpleCommand): EmbeddedWrites {
  const result: EmbeddedWrites = { targets: [], unverifiable: [] };
  const index = commandIndex(cmd.words);
  if (index === undefined) return result;
  const name = basename(cmd.words[index].text);
  const argWords = cmd.words.slice(index + 1);
  if (SED_NAMES.has(name)) {
    const effects = sedEffects(argWords);
    result.targets.push(...effects.writes);
    if (effects.exec) result.unverifiable.push(`sed script in "${snippet(name, argWords.map((word) => word.text))}" runs a command`);
  }
  if (name === YQ_NAME && yqSplits(argWords.map((word) => word.text))) {
    result.unverifiable.push(`yq --split-exp file names are computed at run time`);
  }
  return result;
}

/** Label of the inline interpreter script this command runs (python -c, node -e, heredoc to an interpreter, ...). */
export function inlineInterpreterScript(cmd: SimpleCommand): string | undefined {
  const index = commandIndex(cmd.words);
  if (index === undefined) return undefined;
  const name = basename(cmd.words[index].text);
  const spec = interpreterSpec(name);
  if (spec === undefined) return undefined;
  return inlineScript(name, spec, cmd, cmd.words.slice(index + 1).map((word) => word.text));
}
