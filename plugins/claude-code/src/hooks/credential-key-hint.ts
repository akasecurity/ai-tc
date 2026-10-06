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
const FILE_READER = /^\s*(?:cat|head|tail|less|more|bat)\b/;

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
// A chain of `.name` / `["name"]` steps that starts at a word edge (not inside
// a path, a file name or a flag value).
const LOOKUP_PATH =
  /(?<![A-Za-z0-9_$/\\.=-])((?:\.[A-Za-z_][A-Za-z0-9_-]*|\[["'][A-Za-z0-9_-]+["']\])+)/g;
const LOOKUP_STEP = /[A-Za-z0-9_-]+(?=["']?\]?$)/;
const GREP_PATTERN =
  /(?:^|[;&|]\s*)(?:grep|egrep|fgrep|rg)\s+(?:-\S+\s+)*(["']?)([A-Za-z0-9_-]+)\1(?=\s|$)/g;

function pathBasename(arg: string): string | undefined {
  const unquoted = arg.replace(/^["']|["']$/g, '');
  const base = unquoted.slice(Math.max(unquoted.lastIndexOf('/'), unquoted.lastIndexOf('\\')) + 1);
  // A `.suffix` (`secret_key.txt`) names a file of something else.
  return /^[A-Za-z0-9_-]+$/.test(base) ? base : undefined;
}

function nameInCommand(command: string): string | undefined {
  const found: Candidate[] = [];
  const add = (index: number, run: string | undefined): void => {
    if (run !== undefined && isCredentialName(run)) found.push({ index, name: clean(run) });
  };
  for (const m of command.matchAll(EXPANSION)) add(m.index, m[1]);
  for (const m of command.matchAll(PRINTENV)) add(m.index, m[1]);
  for (const m of command.matchAll(GREP_PATTERN)) add(m.index, m[2]);
  for (const m of command.matchAll(LOOKUP_PATH)) {
    add(m.index, LOOKUP_STEP.exec(m[1] ?? '')?.[0]);
  }
  if (FILE_READER.test(command)) {
    let at = 0;
    for (const arg of command.split(/\s+/)) {
      const index = command.indexOf(arg, at);
      at = index + arg.length;
      if (index > 0 && !arg.startsWith('-')) add(index, pathBasename(arg));
    }
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
