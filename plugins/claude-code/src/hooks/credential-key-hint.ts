// A tool that prints one credential value and nothing else (`jq -r
// .auth.secret_key settings.json`, `echo $API_TOKEN`, a Read of a file named
// `secret_key`) leaves the scanner with a bare token and no field name, so no
// rule has anything to key on. The tool's INPUT does name the field. This
// module reads the key name off the input and, for an output that is a single
// high-entropy token, builds the `key: "value"` text the secret-config-value
// rule matches, so the same rule covers the bare form.
//
// Pure: no I/O, so it unit-tests without a hook process.
import { isHighEntropy } from '@akasecurity/plugin-sdk';

// The credential vocabulary of secrets-infra/secret-config-value: the rule's
// terminal words, in the same order. The rule's optional leading adjectives
// (`access`, `refresh`, `session`, ...) need no entry: a name such as
// `accessToken` or `X-Auth-Token` is matched by its ending word at a word
// edge. A name counts only when it ENDS in one of these words, so
// `max_tokens`, `token_count` and `secret_name` are not credential names.
// Nothing in the rule's terminal list is left out. `pwd` and `pin` are kept for
// parity even though the output gate (20+ characters) rarely lets a PIN or a
// working-directory value through.
const CREDENTIAL_WORD =
  'pass(?:word|wd|phrase|code)?|pwd|secret|token|pin(?:[_-]?code)?|pairing(?:[_-]?code)?|credentials?|bearer|auth|api[_-]?key|(?:private|secret|access|signing|encryption|master|auth|license)[_-]?key';

// A name (an identifier run) is a credential NAME only when
// it ends in a credential word at a word edge: the whole run (`token`), after a
// separator (`API_TOKEN`, `X-Auth-Token`) or at a camelCase hump (`accessToken`).
// `jsonwebtoken` ends in "token" but is a package name, so it is not one.
const ENDS_IN_CREDENTIAL_WORD = new RegExp(`(?:${CREDENTIAL_WORD})$`, 'i');

// Only a short input is searched: a long script names many things, and the
// output gate below is what keeps a stray match from mattering.
const MAX_INPUT_CHARS = 4_000;

// A command that prints a file's content, so the last component of its path
// names what the output holds (`cat /run/secrets/api_token`).
const FILE_READERS = new Set(['cat', 'head', 'tail', 'less', 'more', 'bat']);

// Flags of those readers that take the NEXT argument as their value, so that
// argument is not a file path (`head -c 20 file`, `less -p api_key file`).
const READER_VALUE_FLAGS = new Set([
  '-c',
  '-n',
  '--bytes',
  '--lines',
  '-s',
  '--sleep-interval',
  '--pid',
  '-p',
  '-P',
  '-b',
  '-h',
  '-j',
  '-k',
  '-o',
  '-O',
  '-t',
  '-T',
  '-x',
  '-y',
  '-z',
  '-D',
  '--pattern',
  '--prompt',
  '--tag',
  '--tag-file',
  '--shift',
  '--jump-target',
  '-l',
  '-r',
  '-H',
  '--language',
  '--line-range',
  '--highlight-line',
  '--theme',
  '--style',
  '--map-syntax',
  '--file-name',
  '--tabs',
  '--wrap',
  '--terminal-width',
  '--paging',
  '--color',
  '--decorations',
  '--diff-context',
]);

// Commands that start a command in a shell line: a prefix word runs the next
// word as the command.
const COMMAND_PREFIXES = new Set([
  'sudo',
  'time',
  'xargs',
  'env',
  'nohup',
  'command',
  'exec',
  'doas',
]);

function isCredentialName(run: string): boolean {
  const name = run.replace(/^[_-]+/, '');
  const word = ENDS_IN_CREDENTIAL_WORD.exec(name);
  if (word === null) return false;
  const before = name.slice(0, word.index);
  if (before === '' || /[_-]$/.test(before)) return true;
  const first = word[0].charAt(0);
  return /[a-z0-9]$/.test(before) && first !== first.toLowerCase();
}

interface Candidate {
  index: number;
  name: string;
}

const clean = (run: string): string => run.replace(/^[_-]+/, '');

// A credential word elsewhere in an argument (`--grep=secret_key`, `-m "add
// token"`, `--label=api_key`, a package name, the `Bearer` scheme in an
// Authorization header) says nothing about what the command prints, so it is
// not read. A name is taken only from the shapes that name printed output:
//   - a variable expansion: `$API_TOKEN`, `${API_TOKEN}`;
//   - `printenv NAME`;
//   - a lookup path (jq, yq, a JS property): the LAST component of
//     `.auth.secret_key` or `.auth["secret_key"]`;
//   - the pattern a grep looks for (`grep -i X-Auth-Token`);
//   - for a file reader, the base name of a path argument.
const EXPANSION = /\$\{?([A-Za-z_][A-Za-z0-9_]*)/g;
const PRINTENV = /(?:^|[\s;&|(])printenv\s+([A-Za-z_][A-Za-z0-9_]*)(?=\s|$|[;&|)])/g;
// A chain of `.name` / `["name"]` steps that starts an argument (after start,
// whitespace, a quote or a call/index close) and not inside a path, a file name
// or a flag value. Where the chain may sit is decided by `lookupAllowed`.
const LOOKUP_PATH =
  /(?<![A-Za-z0-9_$/\\.=:-])((?:\.[A-Za-z_][A-Za-z0-9_-]*|\[["'][^"'\]]+["']\])+)/g;
const LOOKUP_TOOL = /(?:^|[\s;&|(])(?:jq|yq|gojq|jaq)\s/g;
const SCRIPT_TOOL = /(?:^|[\s;&|(])(?:node|bun|deno|python3?)\s/g;

// The name of the last step of a lookup chain, when it is a credential name:
// `.a.secret_key` and `.a["secret_key"]` give `secret_key`, and a bracket step
// with spaces (`.a["my secret_key"]`) gives its last word. A parent segment is
// never returned for a last step that is not one.
function lastLookupStep(chain: string): string | undefined {
  const bracket = /\[["']([^"'\]]+)["']\]$/.exec(chain);
  const raw = bracket
    ? (bracket[1] ?? '').trim().split(/\s+/).pop()
    : /[A-Za-z0-9_-]+$/.exec(chain)?.[0];
  return raw === undefined || raw === '' ? undefined : raw;
}

// jq/yq read a path off their argument list: the chain must come after the
// tool word. A script one-liner reads a property off a call or index result, so
// the chain must follow `)` or `]`.
function lookupAllowed(command: string, at: number): boolean {
  const before = command.charAt(at - 1);
  for (const m of command.matchAll(LOOKUP_TOOL)) {
    if (m.index < at) return true;
  }
  if (before === ')' || before === ']') {
    for (const m of command.matchAll(SCRIPT_TOOL)) if (m.index < at) return true;
  }
  return false;
}

// Flags that NAME the field a secret-manager command prints, in `--flag=VALUE`
// and `--flag VALUE` form. Only read for the secret-manager commands below:
// `docker run --name api_key` names a container, not a field.
const FIELD_FLAGS = new Set([
  '-field',
  '--field',
  '--name',
  '--secret-id',
  '--key',
  '-p',
  '--parameter',
]);
const SECRET_CLIENTS = new Set(['aws', 'vault', 'op', 'az', 'gcloud', 'doppler', 'bw', 'consul']);

// Reader commands whose first positional argument after the subcommand names
// what they print: `terraform output api_key`, `vault kv get secret/api_key`,
// `op read op://vault/api_token`.
const POSITIONAL_SELECTORS: readonly { cmd: ReadonlySet<string>; sub: readonly string[] }[] = [
  { cmd: new Set(['terraform', 'tofu']), sub: ['output'] },
  { cmd: new Set(['vault']), sub: ['kv', 'get'] },
  { cmd: new Set(['op']), sub: ['read'] },
];

const GREP_COMMANDS = new Set(['grep', 'egrep', 'fgrep', 'rg']);
const PATTERN_WORD = /^(["']?)([A-Za-z0-9_-]+)\1$/;

function pathBasename(arg: string): string | undefined {
  const unquoted = arg.replace(/^["']|["']$/g, '');
  const base = unquoted.slice(Math.max(unquoted.lastIndexOf('/'), unquoted.lastIndexOf('\\')) + 1);
  // A `.suffix` (`secret_key.txt`) names a file of something else.
  return /^[A-Za-z0-9_-]+$/.test(base) ? base : undefined;
}

interface Token {
  index: number;
  text: string;
}

interface Segment {
  command: string;
  args: Token[];
}

// The simple commands of a shell line: the line split at `;`, `&&`, `||`, `|`,
// a newline, `(` and a backtick, each with its prefix words (`sudo`, `time`,
// `xargs`, `env`, `VAR=x`) dropped.
function segmentsOf(line: string): Segment[] {
  const out: Segment[] = [];
  for (const seg of line.matchAll(/[^;&|\n()`]+/g)) {
    const tokens = [...seg[0].matchAll(/\S+/g)].map((t) => ({
      index: seg.index + t.index,
      text: t[0],
    }));
    let i = 0;
    while (i < tokens.length) {
      const text = tokens[i]?.text ?? '';
      const prefix = COMMAND_PREFIXES.has(text.slice(text.lastIndexOf('/') + 1));
      if (prefix || /^[A-Za-z_][A-Za-z0-9_]*=/.test(text)) {
        i += 1;
        while (prefix && (tokens[i]?.text ?? '').startsWith('-')) i += 1;
      } else break;
    }
    const first = tokens[i];
    if (first === undefined) continue;
    out.push({
      command: first.text.slice(first.text.lastIndexOf('/') + 1),
      args: tokens.slice(i + 1),
    });
  }
  return out;
}

const isFlag = (t: string): boolean => t.startsWith('-');

// The file arguments of a reader: its flags and the operands of its
// value-taking flags are not paths.
function readerPaths(args: Token[]): Token[] {
  const paths: Token[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const t = args[i];
    if (t === undefined) continue;
    if (READER_VALUE_FLAGS.has(t.text)) i += 1;
    else if (!isFlag(t.text)) paths.push(t);
  }
  return paths;
}

// `grep [flags] PATTERN`, `-e PATTERN`, `--regexp=PATTERN`; the operand of
// `-f`/`--file` is a pattern FILE, and with `-f` the positional words are files.
function grepPatterns(args: Token[]): Token[] {
  const patterns: Token[] = [];
  let positional: Token | undefined;
  let explicit = false;
  let fromFile = false;
  for (let i = 0; i < args.length; i += 1) {
    const t = args[i];
    if (t === undefined) continue;
    const { text } = t;
    const long = /^--regexp=(.*)$/.exec(text);
    if (long) {
      explicit = true;
      patterns.push({ index: t.index + '--regexp='.length, text: long[1] ?? '' });
    } else if (text === '-e' || text === '--regexp') {
      explicit = true;
      const next = args[i + 1];
      if (next) patterns.push(next);
      i += 1;
    } else if (text === '-f' || text === '--file') {
      fromFile = true;
      i += 1;
    } else if (text.startsWith('--file=')) {
      fromFile = true;
    } else if (!isFlag(text) && positional === undefined) {
      positional = t;
    }
  }
  if (!explicit && !fromFile && positional) patterns.push(positional);
  return patterns;
}

function positionalSelector(segment: Segment): Token | undefined {
  for (const sel of POSITIONAL_SELECTORS) {
    if (!sel.cmd.has(segment.command)) continue;
    const words = segment.args.filter((t) => !isFlag(t.text));
    if (!sel.sub.every((w, k) => words[k]?.text === w)) continue;
    const after = segment.args.findIndex((t) => t === words[sel.sub.length - 1]) + 1;
    for (let i = after; i < segment.args.length; i += 1) {
      const t = segment.args[i];
      if (t === undefined) continue;
      if (FIELD_FLAGS.has(t.text)) i += 1;
      else if (!isFlag(t.text)) return t;
    }
  }
  return undefined;
}

function nameInCommand(command: string): string | undefined {
  const found: Candidate[] = [];
  const add = (index: number, run: string | undefined): void => {
    if (run !== undefined && isCredentialName(run)) found.push({ index, name: clean(run) });
  };
  for (const m of command.matchAll(EXPANSION)) add(m.index, m[1]);
  for (const m of command.matchAll(PRINTENV)) add(m.index, m[1]);
  for (const m of command.matchAll(LOOKUP_PATH)) {
    if (lookupAllowed(command, m.index)) add(m.index, lastLookupStep(m[1] ?? ''));
  }
  for (const segment of segmentsOf(command)) {
    if (GREP_COMMANDS.has(segment.command)) {
      for (const t of grepPatterns(segment.args)) {
        const word = PATTERN_WORD.exec(t.text);
        add(t.index, word?.[2]);
      }
    }
    if (FILE_READERS.has(segment.command)) {
      for (const t of readerPaths(segment.args)) add(t.index, pathBasename(t.text));
    }
    if (SECRET_CLIENTS.has(segment.command)) {
      for (let i = 0; i < segment.args.length; i += 1) {
        const t = segment.args[i];
        if (t === undefined) continue;
        const eq = /^(-{1,2}[A-Za-z][A-Za-z-]*)=(.+)$/.exec(t.text);
        if (eq && FIELD_FLAGS.has(eq[1] ?? '')) {
          add(t.index, pathBasename(eq[2] ?? ''));
        } else if (FIELD_FLAGS.has(t.text)) {
          const next = segment.args[i + 1];
          if (next && !isFlag(next.text)) add(next.index, pathBasename(next.text));
        }
      }
    }
    const selected = positionalSelector(segment);
    if (selected) add(selected.index, pathBasename(selected.text));
  }
  found.sort((a, b) => a.index - b.index);
  return found[0]?.name;
}

// The tool inputs that name where the printed value came from. Bash: the
// command. Read: the file path, whose last component is the name.
const INPUT_FIELD: Record<string, string> = { Bash: 'command', Read: 'file_path' };

/** The credential-like name a tool call's input mentions, if any. */
export function credentialKeyFromInput(toolName: string, toolInput: unknown): string | undefined {
  const field = Object.hasOwn(INPUT_FIELD, toolName) ? INPUT_FIELD[toolName] : undefined;
  if (field === undefined || typeof toolInput !== 'object' || toolInput === null) return undefined;
  const text: unknown = (toolInput as Record<string, unknown>)[field];
  if (typeof text !== 'string' || text.length > MAX_INPUT_CHARS) return undefined;
  if (toolName === 'Read') {
    const base = text.slice(Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\')) + 1);
    return isCredentialName(base) ? base.replace(/^[_-]+/, '') : undefined;
  }
  return nameInCommand(text);
}

// One token: no whitespace or quotes, not starting like a path. At most 256
// characters, the longest value the config-value rule reads.
const BARE_TOKEN = /^[A-Za-z0-9+_=-][A-Za-z0-9+/_=.~-]{19,255}$/;

/** A scanned text that wraps the real one so a rule can see the key name. */
export interface KeyAnnotation {
  /** Whitespace kept in front of the value. */
  lead: string;
  /** `key: "` — the text put before the value for scanning. */
  prefix: string;
  /** `"` — the text put after the value for scanning. */
  suffix: string;
  /** Whitespace kept after the value (the trailing newline). */
  trail: string;
}

/**
 * The annotation for an output that is exactly one high-entropy token (20+
 * characters, Shannon entropy at least 3.5) when the input named a credential
 * key; undefined for anything else, which is scanned as it is.
 */
export function annotateBareValue(
  key: string | undefined,
  output: string,
): KeyAnnotation | undefined {
  if (key === undefined) return undefined;
  const core = output.trim();
  if (!BARE_TOKEN.test(core) || !isHighEntropy(core)) return undefined;
  const start = output.indexOf(core);
  return {
    lead: output.slice(0, start),
    prefix: `${key}: "`,
    suffix: '"',
    trail: output.slice(start + core.length),
  };
}

/** The text to scan for `text` under `annotation`. */
export function annotatedText(text: string, annotation: KeyAnnotation): string {
  const core = text.slice(annotation.lead.length, text.length - annotation.trail.length);
  return `${annotation.lead}${annotation.prefix}${core}${annotation.suffix}${annotation.trail}`;
}

/**
 * The scanned text mapped back to the shape of the original output, by taking
 * the key and quotes out again. A rewrite that no longer carries them (the
 * whole line replaced) is returned as it is: it holds no value to leak.
 */
export function unannotatedText(rewritten: string, annotation: KeyAnnotation): string {
  const head = annotation.lead + annotation.prefix;
  const tail = annotation.suffix + annotation.trail;
  if (!rewritten.startsWith(head) || !rewritten.endsWith(tail)) return rewritten;
  if (rewritten.length < head.length + tail.length) return rewritten;
  return (
    annotation.lead +
    rewritten.slice(head.length, rewritten.length - tail.length) +
    annotation.trail
  );
}
