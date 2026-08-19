import { createHash, createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { NATIVE_HOST_NAME } from '../src/constants.ts';
import { ADAPTER_HOSTNAMES, resolveAdapter } from '../src/providers/registry.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test -> plugins/browser-extension
const PACKAGE_ROOT = join(HERE, '..');
// test -> repo root
const REPO_ROOT = join(HERE, '..', '..', '..');

interface ExtensionManifest {
  key: string;
  content_scripts: { matches: string[] }[];
  host_permissions?: string[];
  permissions: string[];
}

const manifest = JSON.parse(
  readFileSync(join(PACKAGE_ROOT, 'manifest.json'), 'utf8'),
) as ExtensionManifest;

const CLI_EXTENSION_SOURCE = readFileSync(
  join(REPO_ROOT, 'cli', 'src', 'commands', 'extension.ts'),
  'utf8',
);

// Derived from the registry, NOT hand-written: a pinned list only fires when
// the author who added an adapter also remembered to update it, which is the
// same forgetting this guard exists to catch. Reading the adapters' own
// hostnames means a new provider that misses the manifest fails here.
const HOSTNAMES = [...ADAPTER_HOSTNAMES];

describe('manifest.json stays in sync with the provider registry', () => {
  it.each(HOSTNAMES)('%s resolves to an adapter', (hostname) => {
    expect(resolveAdapter(hostname)).not.toBeNull();
  });

  it.each(HOSTNAMES)('%s is granted in content_scripts matches', (hostname) => {
    expect(manifest.content_scripts[0]?.matches).toContain(`https://${hostname}/*`);
  });

  // The other direction: a granted origin with no adapter behind it injects
  // this script into a site it cannot read, widening the extension's reach
  // for nothing. Whole-set equality catches both drifts at once.
  it('grants exactly the origins the registry drives, and no others', () => {
    const granted = (manifest.content_scripts[0]?.matches ?? []).map((match) =>
      match.replace(/^https:\/\//, '').replace(/\/\*$/, ''),
    );
    expect([...granted].sort()).toEqual([...HOSTNAMES].sort());
  });

  it('grants no host_permissions — content-script injection needs only matches', () => {
    // host_permissions would additionally allow cross-origin fetch/XHR into
    // the matched sites, which nothing in this extension does. Keeping the
    // grant off means a compromised or buggy extension build cannot silently
    // gain a network read into the user's chat sessions.
    expect(manifest.host_permissions).toBeUndefined();
  });

  it('requests exactly the nativeMessaging permission', () => {
    expect(manifest.permissions).toEqual(['nativeMessaging']);
  });
});

describe('native host name stays in sync with the CLI installer', () => {
  it('NATIVE_HOST_NAME matches the name `aka extension install` writes into the host manifest', () => {
    // cli and plugins/* are sibling leaf packages, so the CLI duplicates the
    // constant rather than importing it (see the note in both files) — this
    // pins the two copies together.
    const match = /const NATIVE_HOST_NAME = '([^']+)'/.exec(CLI_EXTENSION_SOURCE);
    expect(match?.[1]).toBe(NATIVE_HOST_NAME);
  });
});

// Chrome derives an extension's id from the public key it was signed with:
// SHA-256 over the DER bytes, first 16 bytes, each nibble mapped 0-f -> a-p.
// Computing it here rather than restating the id means the manifest's "key" is
// the single source of truth for the identity the CLI has to grant.
//
// The input is checked rather than decoded best-effort. Buffer.from ignores
// non-base64 characters instead of failing, so a PEM-wrapped or truncated key
// still decodes — to DIFFERENT bytes — and derives an id that matches
// /^[a-p]{32}$/ like any other. Nothing downstream can tell the two apart, so
// this guard would name a plausible wrong id as the one to grant, and the
// obvious fix is to add it: an origin matching no extension, committed and
// green, while the real id is still missing. That is the silent connectNative
// failure this whole suite exists to prevent, reached through the guard.
//
// Both checks are load-bearing; measured against the committed key, neither
// catches what the other does. A PEM wrapper fails the round-trip. Line-wrapping
// alone also fails it while decoding to the RIGHT bytes — still rejected,
// because Chrome wants bare base64 too. And a truncated key round-trips TRUE,
// because a shorter string is still valid base64; only the SPKI parse rejects
// that one.
function extensionIdFromKey(key: string): string {
  const der = Buffer.from(key, 'base64');
  if (der.toString('base64') !== key) {
    throw new Error('manifest.json "key" is not bare base64 (PEM header or line breaks?)');
  }
  try {
    createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new Error('manifest.json "key" is not a valid SPKI public key (truncated or corrupt?)');
  }
  const digest = createHash('sha256').update(der).digest();
  return [...digest.subarray(0, 16)]
    .flatMap((byte) => [byte >> 4, byte & 0x0f])
    .map((nibble) => String.fromCharCode(97 + nibble))
    .join('');
}

describe('extensionIdFromKey requires a bare base64 SPKI key', () => {
  // Driven with derived fixtures rather than the committed value: every case
  // here is a way the NEXT key lands wrong, and the store's key is pasted by
  // hand. Each malformed input below derives a well-formed-looking id, so the
  // shape check downstream cannot stand in for any of this.
  const KEY = manifest.key;
  const wrapped = (KEY.match(/.{1,64}/g) ?? []).join('\n');

  it('accepts the committed key', () => {
    expect(() => extensionIdFromKey(KEY)).not.toThrow();
  });

  it('rejects a PEM-wrapped key', () => {
    const pem = `-----BEGIN PUBLIC KEY-----\n${wrapped}\n-----END PUBLIC KEY-----`;
    // The likeliest way this goes wrong: a public key copied out of a
    // certificate tool arrives in PEM form, and Buffer.from drops the headers.
    expect(() => extensionIdFromKey(pem)).toThrow(/bare base64/);
  });

  it('rejects a line-wrapped key even though it decodes to the right bytes', () => {
    expect(() => extensionIdFromKey(wrapped)).toThrow(/bare base64/);
  });

  it('rejects a truncated key, which round-trips as valid base64', () => {
    // The case the round-trip alone misses: still valid base64, so it decodes
    // and derives a plausible wrong id. Only the SPKI parse rejects it.
    const truncated = KEY.slice(0, -8);
    expect(Buffer.from(truncated, 'base64').toString('base64')).toBe(truncated);
    expect(() => extensionIdFromKey(truncated)).toThrow(/SPKI public key/);
  });

  it('rejects a key that is not a public key at all', () => {
    expect(() => extensionIdFromKey(Buffer.from('nonsense').toString('base64'))).toThrow(
      /SPKI public key/,
    );
  });
});

// The CLI's list is read as text, because cli and plugins/* are sibling leaf
// packages and importing across them is a package-wall crossing.
//
// Comments come off the WHOLE source before the array is located, not out of
// the body after it. The body regex stops at the first `];`, so a comment
// carrying one — `// mirrors allowed_origins: [chrome-extension://<id>/];`,
// exactly the note the next entry invites — ends the body early and drops
// every id below it; a block comment spanning the real `];` loses the list
// outright. Both redden this guard on a comment fragment while the CLI list is
// perfectly correct.
//
// Stripping first is only safe if the stripper knows a string from a comment,
// because this file writes `chrome-extension://${id}/` — a `//` a line-comment
// regex would read as the start of a comment, discarding the rest of that line
// and any `];` on it. So strings are walked over rather than matched.
//
// Matching the id SHAPE instead of quoted text would hide the opposite
// failure: every quoted entry is captured here, malformed ones included, so a
// typo'd id still reaches the well-formedness check rather than vanishing
// from it.
function stripComments(source: string): string {
  let out = '';
  let i = 0;
  while (i < source.length) {
    const pair = source.slice(i, i + 2);
    if (pair === '//') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (pair === '/*') {
      i += 2;
      while (i < source.length && source.slice(i, i + 2) !== '*/') i += 1;
      i += 2;
      continue;
    }
    const ch = source[i] ?? '';
    if (ch === "'" || ch === '"' || ch === '`') {
      out += ch;
      i += 1;
      while (i < source.length && source[i] !== ch) {
        // An escape takes the next character with it, so a \' never closes.
        const span = source[i] === '\\' ? 2 : 1;
        out += source.slice(i, i + span);
        i += span;
      }
      out += source[i] ?? '';
      i += 1;
      continue;
    }
    out += ch;
    i += 1;
  }
  return out;
}

function parseExtensionIds(source: string): string[] {
  const body = /const EXTENSION_IDS = \[([\s\S]*?)\];/.exec(stripComments(source))?.[1];
  if (body === undefined) return [];
  return [...body.matchAll(/'([^']*)'/g)]
    .map((m) => m[1])
    .filter((id): id is string => id !== undefined);
}

describe('the EXTENSION_IDS tokenizer', () => {
  // Driven with fixture sources rather than the committed file: these are the
  // shapes the NEXT edit to that list introduces, so they have to be pinned
  // before someone writes one for real.
  it('captures every entry in a multi-id list', () => {
    const source = `const EXTENSION_IDS = [\n  'mdoiaiemcnjnaokmcmgbikcdhgiemdof',\n  'aaaabbbbccccddddeeeeffffgggghhhh',\n];`;
    expect(parseExtensionIds(source)).toEqual([
      'mdoiaiemcnjnaokmcmgbikcdhgiemdof',
      'aaaabbbbccccddddeeeeffffgggghhhh',
    ]);
  });

  it('is not fooled by an apostrophe in a comment', () => {
    const source = `const EXTENSION_IDS = [
  // Derived from the "key" in plugins/browser-extension/manifest.json.
  'mdoiaiemcnjnaokmcmgbikcdhgiemdof',
  // The Chrome Web Store's own id.
  'aaaabbbbccccddddeeeeffffgggghhhh',
];`;
    expect(parseExtensionIds(source)).toEqual([
      'mdoiaiemcnjnaokmcmgbikcdhgiemdof',
      'aaaabbbbccccddddeeeeffffgggghhhh',
    ]);
  });

  it('is not fooled by an apostrophe in a block comment', () => {
    const source = `const EXTENSION_IDS = [
  /* The store's own id. */
  'aaaabbbbccccddddeeeeffffgggghhhh',
];`;
    expect(parseExtensionIds(source)).toEqual(['aaaabbbbccccddddeeeeffffgggghhhh']);
  });

  // The two below are why comments come off before the array is located.
  // Locating first ended the body at the first `];` in the RAW text, so a
  // comment carrying one truncated the list — and each of these is a note a
  // maintainer has an obvious reason to write next to the entry it explains.
  it('is not truncated by a line comment carrying the array terminator', () => {
    const source = `const EXTENSION_IDS = [
  'mdoiaiemcnjnaokmcmgbikcdhgiemdof',
  // mirrors allowed_origins: [chrome-extension://<store-id>/];
  'aaaabbbbccccddddeeeeffffgggghhhh',
];`;
    expect(parseExtensionIds(source)).toEqual([
      'mdoiaiemcnjnaokmcmgbikcdhgiemdof',
      'aaaabbbbccccddddeeeeffffgggghhhh',
    ]);
  });

  it('is not emptied by a block comment spanning the array terminator', () => {
    const source = `const EXTENSION_IDS = [
  /* was allowed_origins: ['chrome-extension://legacy/']; before the split */
  'aaaabbbbccccddddeeeeffffgggghhhh',
];`;
    expect(parseExtensionIds(source)).toEqual(['aaaabbbbccccddddeeeeffffgggghhhh']);
  });

  // The two below are why the stripper walks over strings instead of matching
  // comments with a regex. Stripping first is what fixes the cases above, and
  // a string-blind stripper is how stripping first breaks something else.
  it('does not read a "/*" inside a string as the start of a block comment', () => {
    // The wider of the two hazards, because a block comment is not bounded by
    // its line: with no `*/` after it, a string-blind stripper discards the
    // rest of the FILE, and the array with it. A path glob is all it takes.
    const source = `const GLOB = 'plugins/*';
const EXTENSION_IDS = ['aaaabbbbccccddddeeeeffffgggghhhh'];`;
    expect(parseExtensionIds(source)).toEqual(['aaaabbbbccccddddeeeeffffgggghhhh']);
  });

  it('does not read a "//" inside a string as the start of a line comment', () => {
    // This file really does write `chrome-extension://${id}/`. The damage is
    // bounded by the line, so it costs the array only when the two share one —
    // which is why the fixture puts them there rather than as prettier would.
    const source = `const ORIGIN = \`chrome-extension://x/\`; const EXTENSION_IDS = ['aaaabbbbccccddddeeeeffffgggghhhh'];`;
    expect(parseExtensionIds(source)).toEqual(['aaaabbbbccccddddeeeeffffgggghhhh']);
  });

  it('captures a malformed entry rather than skipping it', () => {
    // What a shape-matching tokenizer would lose: a typo'd id would simply not
    // be captured, and the well-formedness check below would pass over a list
    // that grants nothing usable.
    const source = `const EXTENSION_IDS = [\n  'NOT-AN-ID',\n];`;
    expect(parseExtensionIds(source)).toEqual(['NOT-AN-ID']);
  });

  it('returns nothing when the constant is renamed', () => {
    const source = `const OTHER_IDS = [\n  'mdoiaiemcnjnaokmcmgbikcdhgiemdof',\n];`;
    expect(parseExtensionIds(source)).toEqual([]);
  });
});

describe('the CLI grants the id this manifest key derives', () => {
  // `aka extension install` writes allowed_origins into the native-host
  // manifest, and Chrome refuses connectNative for any origin missing from it.
  // So a key swap that never reaches the CLI's list is not a build failure —
  // it is an extension that installs cleanly and silently cannot reach the
  // host. Replacing the committed key (as publishing to the Chrome Web Store
  // does, since the store signs with its own) fails here until the CLI lists
  // the new id.
  const listed = parseExtensionIds(CLI_EXTENSION_SOURCE);

  it('parses a non-empty EXTENSION_IDS list out of the CLI source', () => {
    // Asserted on its own so a renamed constant reports THAT, rather than
    // arriving at the grant check below as an empty list and reading as a
    // missing id.
    expect(listed.length).toBeGreaterThan(0);
  });

  it.each(listed)('%s is a well-formed extension id', (id) => {
    // A typo'd id is accepted by every other check here and by Chrome's
    // manifest parser — it just never matches the extension asking to connect.
    expect(id).toMatch(/^[a-p]{32}$/);
  });

  it('lists the id derived from manifest.json\'s "key"', () => {
    expect(listed).toContain(extensionIdFromKey(manifest.key));
  });
});

describe('turbo hashes the CLI source these guards read', () => {
  // Everything above reads cli/src/commands/extension.ts, and this package does
  // not depend on cli — so nothing under cli/ is in this task's default hash. A
  // follow-up touching only the CLI would leave the hash untouched, turbo would
  // replay a cached pass, and the guards would not execute at exactly the moment
  // they exist to fire. Measured before the inputs were declared: swapping the
  // CLI's id for a different well-formed one left the hash byte-identical, and
  // ci.yml restores .turbo/cache with restore-keys that fall back across
  // commits, so the stale hit is reachable in CI and not just locally.
  //
  // Read as text with a scoped regex rather than parsed: turbo.json is JSONC and
  // carries comments throughout, which is how the rest of this repo reads it.
  const TURBO_JSON = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
  const task = /"@akasecurity\/plugin-browser-extension#test"\s*:\s*\{([\s\S]*?)\n {4}\}/.exec(
    TURBO_JSON,
  );

  it('declares a task entry for this package', () => {
    expect(
      task,
      'turbo.json declares no @akasecurity/plugin-browser-extension#test task, so this suite ' +
        'falls back to the root `test` task and stops hashing the CLI source it reads',
    ).not.toBeNull();
  });

  it('names the CLI source in its inputs', () => {
    expect(
      task?.[1],
      'the task must hash cli/src/commands/extension.ts, or a CLI-only change replays a cached pass',
    ).toContain('$TURBO_ROOT$/cli/src/commands/extension.ts');
  });

  it('names turbo.json in its inputs, so removing them re-runs this suite', () => {
    // Self-coverage: without this, deleting the input above is invisible here
    // for the same reason the CLI source was — the config that silences the
    // guard is not itself hashed by it.
    expect(task?.[1]).toContain('$TURBO_ROOT$/turbo.json');
  });
});
