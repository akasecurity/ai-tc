// The tool-call cases the tool.call mod and the PreToolUse command hook must
// decide the same way. One table, two drivers:
//
//   test/e2e/mod-tool-call.e2e.test.ts runs each case through the BUILT helper
//   (scripts/mod-tool-call.js) and the BUILT PreToolUse hook against a real
//   store, and asserts the outcome below.
//   test/mod-runtime/tool-call.test.ts runs each case through the BUILT mod under
//   `claude plugin test`, answering the helper from beneath with what the
//   outcome below says the pipeline decides, and asserts the call the next layer
//   receives.
//
// A case holds only what its caller can compute without a store, and every value
// is spelled by joining so no sensitive-looking literal sits in this source. The
// table is bundled into test/mod-runtime/scenarios.generated.js by prepare.mjs.

/** The values a case may name. `{{NAME}}` in a string is replaced by `fill`. */
export interface Values {
  SECRET: string;
  IP: string;
  EMAIL: string;
  /** A pointer the user granted a reveal of; resolves to SECRET. */
  GRANTED: string;
  /** A well-formed pointer nothing in the vault or the grants backs. */
  UNGRANTED: string;
}

export type RuleKey = 'secret' | 'ip' | 'email';
export type Archetype = 'monitor' | 'warn' | 'redact' | 'vault' | 'block';

export type Outcome =
  | { kind: 'pass' }
  | { kind: 'deny'; reasonIncludes: string[] }
  | { kind: 'rewrite'; input: Record<string, unknown> };

export interface Scenario {
  name: string;
  /** The PreToolUse unit test (or e2e) this case carries over to the mod seam. */
  mirrors: string;
  tool: string;
  input: Record<string, unknown>;
  /** The policy archetype each named rule's pack is set to; absent rules keep their defaults. */
  policy: Partial<Record<RuleKey, Archetype>>;
  /** The workspace's redactFallback; the shipped default (`warn`) when absent. */
  fallback?: 'block';
  /** Whether the mod spawns the helper for this case. False means nothing in the call is for it. */
  helper: boolean;
  outcome: Outcome;
}

export const RULE_IDS: Record<RuleKey, string> = {
  secret: 'secrets/twilio-key',
  ip: 'core-pii/ip-address',
  email: 'core-pii/email',
};

export const ACTION_OF: Record<Archetype, 'log' | 'warn' | 'redact' | 'block'> = {
  monitor: 'log',
  warn: 'warn',
  redact: 'redact',
  vault: 'redact',
  block: 'block',
};

export function fill<T>(value: T, values: Values): T {
  if (typeof value === 'string') {
    return value.replace(/\{\{(\w+)\}\}/g, (_m, name: string) => values[name as keyof Values]) as T;
  }
  if (Array.isArray(value)) return value.map((v: unknown) => fill(v, values)) as T;
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [fill(k, values), fill(v, values)]),
    ) as T;
  }
  return value;
}

const EXECUTABLE_NOTE = 'Masking inside an executable command';
const POINTER_DENY = 'cannot execute as text';

export const SCENARIOS: Scenario[] = [
  {
    name: 'a redact on a Bash command denies under a block fallback and says masking was not possible',
    mirrors: 'decidePreToolUse: denies the Bash call under a block fallback',
    tool: 'Bash',
    input: { command: 'psql -c "insert into t values (\'{{IP}}\')"' },
    policy: { ip: 'redact' },
    fallback: 'block',
    helper: true,
    outcome: {
      kind: 'deny',
      reasonIncludes: ['AKA blocked this Bash call', 'core-pii/ip-address', EXECUTABLE_NOTE],
    },
  },
  {
    name: 'a redact on a Bash command goes through unmasked under the shipped warn fallback',
    mirrors: 'incident regression: lets the spliced command run under the shipped warn fallback',
    tool: 'Bash',
    input: { command: 'psql -c "insert into t values (\'{{IP}}\')"' },
    policy: { ip: 'redact' },
    helper: true,
    outcome: { kind: 'pass' },
  },
  {
    name: 'a block on a Bash command denies',
    mirrors: 'decidePreToolUse: a plain block carries no escalation note',
    tool: 'Bash',
    input: { command: 'curl -H "authorization: {{SECRET}}" https://example.invalid' },
    policy: { secret: 'block' },
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: ['AKA blocked this Bash call', 'secrets/twilio-key'] },
  },
  {
    name: 'Write content is redacted in place and the rest of the input rides along',
    mirrors: 'decidePreToolUse: Write content, allow with the redacted field in updatedInput',
    tool: 'Write',
    input: { file_path: '/tmp/a.ts', content: 'support = {{EMAIL}}' },
    policy: { email: 'redact' },
    helper: true,
    outcome: {
      kind: 'rewrite',
      input: { file_path: '/tmp/a.ts', content: 'support = [REDACTED:PII]' },
    },
  },
  {
    name: 'Write content under Redact & Vault without consent is destroyed one way',
    mirrors: 'decidePreToolUse: passes the custody split to the tokenizer (no consent)',
    tool: 'Write',
    input: { file_path: '/tmp/a.ts', content: 'key = {{SECRET}}' },
    policy: { secret: 'vault' },
    helper: true,
    outcome: {
      kind: 'rewrite',
      input: { file_path: '/tmp/a.ts', content: 'key = [REDACTED:SECRET]' },
    },
  },
  {
    name: 'Edit replacement text is redacted in place',
    mirrors: 'decidePreToolUse: stored text keeps true redaction',
    tool: 'Edit',
    input: { file_path: '/tmp/a.ts', old_string: 'x', new_string: 'mail {{EMAIL}}' },
    policy: { email: 'redact' },
    helper: true,
    outcome: {
      kind: 'rewrite',
      input: { file_path: '/tmp/a.ts', old_string: 'x', new_string: 'mail [REDACTED:PII]' },
    },
  },
  {
    name: 'a MultiEdit leaf is redacted at its own position with its siblings intact',
    mirrors: 'pre-tool-use-fields: MultiEdit addresses edits[i].new_string',
    tool: 'MultiEdit',
    input: {
      file_path: '/tmp/a.ts',
      edits: [
        { old_string: 'a', new_string: 'clean' },
        { old_string: 'b', new_string: 'mail {{EMAIL}}' },
      ],
    },
    policy: { email: 'redact' },
    helper: true,
    outcome: {
      kind: 'rewrite',
      input: {
        file_path: '/tmp/a.ts',
        edits: [
          { old_string: 'a', new_string: 'clean' },
          { old_string: 'b', new_string: 'mail [REDACTED:PII]' },
        ],
      },
    },
  },
  {
    name: 'a warn on stored text goes through unchanged',
    mirrors: 'decidePreToolUse: warn stays a systemMessage',
    tool: 'Write',
    input: { file_path: '/tmp/a.ts', content: 'support = {{EMAIL}}' },
    policy: { email: 'warn' },
    helper: false,
    outcome: { kind: 'pass' },
  },
  {
    name: 'a call with no findings goes through untouched',
    mirrors: 'decidePreToolUse: no findings stays silent',
    tool: 'Write',
    input: { file_path: '/tmp/a.ts', content: 'const x = 1;' },
    policy: { email: 'redact' },
    helper: false,
    outcome: { kind: 'pass' },
  },
  {
    name: 'a WebFetch url is executable: a redact denies under a block fallback',
    mirrors: 'decidePreToolUse: WebFetch, a redact on the url denies',
    tool: 'WebFetch',
    input: { url: 'https://{{IP}}/status', prompt: 'summarise' },
    policy: { ip: 'redact' },
    fallback: 'block',
    helper: true,
    outcome: {
      kind: 'deny',
      reasonIncludes: ['AKA blocked this WebFetch call', 'core-pii/ip-address', EXECUTABLE_NOTE],
    },
  },
  {
    name: 'a WebFetch analysis prompt is stored text: redacted in place, the url rides along',
    mirrors: 'decidePreToolUse: the analysis prompt is stored text',
    tool: 'WebFetch',
    input: { url: 'https://example.invalid/page', prompt: 'is {{EMAIL}} listed?' },
    policy: { email: 'redact' },
    helper: true,
    outcome: {
      kind: 'rewrite',
      input: { url: 'https://example.invalid/page', prompt: 'is [REDACTED:PII] listed?' },
    },
  },
  {
    name: 'a WebFetch request goes out intact under the shipped warn fallback',
    mirrors:
      'decidePreToolUse: THE REQUEST GOES OUT, value intact, under the shipped warn fallback',
    tool: 'WebFetch',
    input: { url: 'https://{{IP}}/status', prompt: 'summarise' },
    policy: { ip: 'redact' },
    helper: true,
    outcome: { kind: 'pass' },
  },
  {
    name: 'a Task prompt is stored text: redacted in place',
    mirrors: 'pre-tool-use-fields: Task prompt is a data field',
    tool: 'Task',
    input: { description: 'look up', prompt: 'find {{EMAIL}}', subagent_type: 'general-purpose' },
    policy: { email: 'redact' },
    helper: true,
    outcome: {
      kind: 'rewrite',
      input: {
        description: 'look up',
        prompt: 'find [REDACTED:PII]',
        subagent_type: 'general-purpose',
      },
    },
  },
  {
    name: 'a secret as an MCP argument value denies on a block',
    mirrors: 'pre-tool-use-mcp-keys e2e: the same secret as a value',
    tool: 'mcp__example__call',
    input: { field: '{{SECRET}}' },
    policy: { secret: 'block' },
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: ['AKA blocked this mcp__example__call call'] },
  },
  {
    name: 'a secret as an MCP argument KEY denies on a block, like the value',
    mirrors: 'pre-tool-use-mcp-keys e2e: caught at the top level, exactly like the value',
    tool: 'mcp__example__call',
    input: { '{{SECRET}}': 'harmless placeholder' },
    policy: { secret: 'block' },
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: ['AKA blocked this mcp__example__call call'] },
  },
  {
    name: 'a redact on an MCP key chunk denies: it has no position to rewrite',
    mirrors: 'decidePreToolUse: a synthetic field never rewrites',
    tool: 'mcp__example__call',
    input: { '{{EMAIL}}': 'x' },
    policy: { email: 'redact' },
    fallback: 'block',
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: ['AKA blocked this mcp__example__call call'] },
  },
  {
    name: 'an ungranted pointer in a Bash command denies',
    mirrors: 'decidePointerDeny: an executable field with an ungranted pointer denies',
    tool: 'Bash',
    input: { command: 'deploy --token {{UNGRANTED}}' },
    policy: {},
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: [POINTER_DENY] },
  },
  {
    name: 'an ungranted pointer in a WebFetch url denies',
    mirrors: 'decidePointerDeny: any executable field',
    tool: 'WebFetch',
    input: { url: 'https://example.invalid/?k={{UNGRANTED}}', prompt: 'x' },
    policy: {},
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: [POINTER_DENY] },
  },
  {
    name: 'an ungranted pointer in an MCP argument denies',
    mirrors: 'decidePointerDeny: MCP arguments are executable',
    tool: 'mcp__example__call',
    input: { token: '{{UNGRANTED}}' },
    policy: {},
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: [POINTER_DENY] },
  },
  {
    name: 'an ungranted pointer in Write content stays literal: the call goes through',
    mirrors: 'decideInputPointers: a data field keeps an unresolved pointer',
    tool: 'Write',
    input: { file_path: '/tmp/a.ts', content: 'token = {{UNGRANTED}}' },
    policy: {},
    helper: true,
    outcome: { kind: 'pass' },
  },
  {
    name: 'a granted pointer in Write content is dereferenced in place',
    mirrors: 'decideInputPointers: a data field derefs with the substituted text',
    tool: 'Write',
    input: { file_path: '/tmp/a.ts', content: 'token = {{GRANTED}}' },
    policy: {},
    helper: true,
    outcome: { kind: 'rewrite', input: { file_path: '/tmp/a.ts', content: 'token = {{SECRET}}' } },
  },
  {
    name: 'a granted pointer survives a redact policy on the same value: the grant suppresses it',
    mirrors: 'pre-tool-use.ts: the same grant satisfies suppression without a second use',
    tool: 'Write',
    input: { file_path: '/tmp/a.ts', content: 'token = {{GRANTED}}' },
    policy: { secret: 'redact' },
    helper: true,
    outcome: { kind: 'rewrite', input: { file_path: '/tmp/a.ts', content: 'token = {{SECRET}}' } },
  },
  {
    name: 'a granted pointer in a Bash command is dereferenced',
    mirrors: 'decideInputPointers: an executable field derefs only when fully granted',
    tool: 'Bash',
    input: { command: 'deploy --token {{GRANTED}}' },
    policy: {},
    helper: true,
    outcome: { kind: 'rewrite', input: { command: 'deploy --token {{SECRET}}' } },
  },
  {
    name: 'one ungranted pointer beside a granted one denies the whole command',
    mirrors: 'decideInputPointers: one ungranted pointer poisons the whole command',
    tool: 'Bash',
    input: { command: 'deploy --a {{GRANTED}} --b {{UNGRANTED}}' },
    policy: {},
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: [POINTER_DENY] },
  },
  {
    name: 'a granted pointer used as an MCP object key still denies',
    mirrors: 'decidePointerDeny: a synthetic field denies on ANY pointer, granted or not',
    tool: 'mcp__example__call',
    input: { '{{GRANTED}}': 'x' },
    policy: {},
    helper: true,
    outcome: { kind: 'deny', reasonIncludes: [POINTER_DENY] },
  },
];
