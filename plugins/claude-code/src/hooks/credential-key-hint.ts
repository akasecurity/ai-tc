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

// The credential vocabulary of secrets-infra/secret-config-value. A name
// counts only when it ENDS in one of these words, so `max_tokens`,
// `token_count` and `secret_name` are not credential names.
const CREDENTIAL_WORD =
  'secret(?:[_-]?key)?|token|passw(?:or)?d|credentials?|bearer|(?:api|private|access|auth|session|signing|encryption)[_-]?key';

// A name in a command or path: starts at a word edge, may carry a dotted or
// dashed prefix (`auth.secret_key`, `X-Auth-Token`), ends on the credential
// word with nothing identifier-like (or a `.suffix`) after it.
const KEY_IN_INPUT = new RegExp(
  String.raw`(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]{0,64}?(?:${CREDENTIAL_WORD})(?![A-Za-z0-9_-]|\.[A-Za-z])`,
  'i',
);

// Only a short input is searched: a long script names many things, and the
// output gate below is what keeps a stray match from mattering.
const MAX_INPUT_CHARS = 4_000;

// The tool inputs that name where the printed value came from. Bash: the
// command. Read: the file path.
const INPUT_FIELD: Record<string, string> = { Bash: 'command', Read: 'file_path' };

/** The credential-like name a tool call's input mentions, if any. */
export function credentialKeyFromInput(toolName: string, toolInput: unknown): string | undefined {
  const field = Object.hasOwn(INPUT_FIELD, toolName) ? INPUT_FIELD[toolName] : undefined;
  if (field === undefined || typeof toolInput !== 'object' || toolInput === null) return undefined;
  const text: unknown = (toolInput as Record<string, unknown>)[field];
  if (typeof text !== 'string' || text.length > MAX_INPUT_CHARS) return undefined;
  const match = KEY_IN_INPUT.exec(text);
  return match?.[0].replace(/^[.-]+/, '');
}

// One token: no whitespace or quotes, not starting like a path.
const BARE_TOKEN = /^[A-Za-z0-9+_=-][A-Za-z0-9+/_=.~-]{19,511}$/;

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
