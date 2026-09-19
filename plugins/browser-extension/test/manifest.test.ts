import { createHash, createPublicKey } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { NATIVE_HOST_NAME } from '../src/constants.ts';
import { isLegalChromeVersion, manifestVersionFields } from '../src/packaging/store-zip.ts';
import { ADAPTER_HOSTNAMES, resolveAdapter } from '../src/providers/registry.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test -> plugins/browser-extension
const PACKAGE_ROOT = join(HERE, '..');
// test -> repo root
const REPO_ROOT = join(HERE, '..', '..', '..');

interface ExtensionManifest {
  key: string;
  version: string;
  content_scripts: { matches: string[]; js: string[]; run_at?: string; world?: string }[];
  host_permissions?: string[];
  permissions: string[];
}

/** Any of the three files below this suite reads a version out of. */
interface Versioned {
  version: string;
  version_name?: string;
}

const readVersioned = (...segments: string[]): Versioned =>
  JSON.parse(readFileSync(join(...segments), 'utf8')) as Versioned;

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

  it.each(HOSTNAMES)('%s is granted in every content_scripts entry', (hostname) => {
    expect(manifest.content_scripts.length).toBeGreaterThan(0);
    for (const entry of manifest.content_scripts) {
      expect(entry.matches, `${entry.js.join(',')} is not granted ${hostname}`).toContain(
        `https://${hostname}/*`,
      );
    }
  });

  // The other direction: a granted origin with no adapter behind it injects
  // this script into a site it cannot read, widening the extension's reach
  // for nothing. Whole-set equality catches both drifts at once.
  //
  // Entry-wise, not content_scripts[0]: the tap and the DOM script are separate
  // entries, and an origin granted to one and not the other is a page where
  // half the extension runs.
  it('grants exactly the origins the registry drives in EVERY content-script entry', () => {
    expect(manifest.content_scripts.length).toBeGreaterThan(0);
    for (const entry of manifest.content_scripts) {
      const granted = entry.matches.map((match) =>
        match.replace(/^https:\/\//, '').replace(/\/\*$/, ''),
      );
      expect([...granted].sort()).toEqual([...HOSTNAMES].sort());
    }
  });

  it('runs exactly one script in the page-s own world, at document_start', () => {
    // A MAIN-world script has the page's own authority — it is the page, for
    // every purpose a site can observe. Exactly one file may have it, it must
    // be the tap, and it must run before any page script: injected later, it
    // cannot see a reference the page has already captured, and the site's own
    // traffic goes past unobserved while the extension reports itself healthy.
    const main = manifest.content_scripts.filter((entry) => entry.world === 'MAIN');
    expect(main).toHaveLength(1);
    expect(main[0]?.js).toEqual(['tap.js']);
    expect(main[0]?.run_at).toBe('document_start');
  });

  it('runs the bridge in the isolated world, at document_start, before the tap', () => {
    // The bridge takes the tap's port off a single window.postMessage the tap
    // sends as it installs. A listener registered after that handshake has gone
    // by never hears it, and the tap — which reads nothing from the port — has
    // no way to be asked again: the tab then reports a healthy patch and
    // forwards every exchange into a port nobody drains.
    //
    // Isolated is stated by the ABSENCE of a world key, not by naming the
    // default: the MAIN-world guard above counts entries carrying one, and a
    // "world": "ISOLATED" here would read as a second page-context script to
    // anything scanning for the key.
    const bridgeAt = manifest.content_scripts.findIndex((entry) => entry.js.includes('bridge.js'));
    const tapAt = manifest.content_scripts.findIndex((entry) => entry.js.includes('tap.js'));
    expect(bridgeAt).toBeGreaterThanOrEqual(0);
    expect(tapAt).toBeGreaterThanOrEqual(0);
    expect(bridgeAt).toBeLessThan(tapAt);
    const bridge = manifest.content_scripts[bridgeAt];
    expect(bridge?.world).toBeUndefined();
    expect(bridge?.run_at).toBe('document_start');
    // Its own file: bundling it with the tap would put the whole bridge into
    // the page's own context, and with the DOM script it would load too late.
    expect(bridge?.js).toEqual(['bridge.js']);
  });

  it('ships a real bundle for every content script it declares', () => {
    // Derived from the manifest rather than listed, so a fourth entry is
    // covered without an edit here. The manifest is the only thing naming
    // these files: an entry dropped from BROWSER_ENTRIES leaves the manifest
    // pointing at a file the build no longer emits, and the shape assertions
    // above — which read the manifest alone — all stay green.
    const declared = manifest.content_scripts.flatMap((entry) => entry.js);
    expect(declared.length).toBeGreaterThan(0);
    for (const file of declared) {
      const built = join(PACKAGE_ROOT, 'dist', file);
      expect(existsSync(built), `${file} is declared but dist/${file} was not built`).toBe(true);
      // Not merely present: an emit that produced an empty file loads as a
      // content script that does nothing, which is the same invisible failure.
      expect(statSync(built).size, `dist/${file} is empty`).toBeGreaterThan(0);
    }
  });

  it('keeps every other content script in the isolated world', () => {
    // The isolated world is the default, so these entries carry no `world` key
    // at all. Asserting the complement is non-empty keeps the case above from
    // passing on a manifest where everything became MAIN-world but the tap.
    const isolated = manifest.content_scripts.filter((entry) => entry.world !== 'MAIN');
    expect(isolated.length).toBeGreaterThan(0);
    for (const entry of isolated) expect(entry.js).not.toContain('tap.js');
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

describe('the extension version has ONE source of truth', () => {
  // package.json is it. src/native-host/host.ts stamps that field into
  // meta.pluginBuild on every session, scripts/build.mjs stamps it into
  // dist/manifest.json, and cli/scripts/bundle-extension.mjs refuses to bundle a
  // built manifest whose version is not the CLI's — so the three numbers a user
  // can see (chrome://extensions, the recorded build, the CLI they installed it
  // from) are one number or the pack step fails.
  const self = readVersioned(PACKAGE_ROOT, 'package.json');

  it('the committed manifest carries a version Chrome rejects', () => {
    // All-zero is documented as invalid, so an UNSTAMPED tree cannot be loaded
    // unpacked or uploaded — which is what makes a missing stamping step
    // detectable rather than shipping whatever placeholder was committed.
    expect(isLegalChromeVersion(manifest.version)).toBe(false);
  });

  it('the built manifest carries the package version, and Chrome accepts it', () => {
    // globalSetup has run `pnpm build`, so dist/ is present and current. Both
    // fields are read, because a pre-release package version is split across
    // them: `version` holds the numeric core and `version_name` the whole string.
    const built = readVersioned(PACKAGE_ROOT, 'dist', 'manifest.json');
    const expected = manifestVersionFields(self.version);
    expect(built.version).toBe(expected.version);
    expect(built.version_name).toBe(expected.version_name);
    expect(built.version_name ?? built.version).toBe(self.version);
    expect(isLegalChromeVersion(built.version)).toBe(true);
  });

  it('the package sits on the CLI shared version line', () => {
    // The pack-time refusal in cli/scripts/bundle-extension.mjs runs on every
    // PR (ci.yml's packaged-artifact job packs the CLI, which runs its prepack),
    // so a drift here reddens the whole tree rather than one release run. This
    // says so where the number is, instead of in a pack log.
    expect(self.version).toBe(readVersioned(REPO_ROOT, 'cli', 'package.json').version);
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
  // Located with a scoped regex rather than JSON.parse: turbo.json is JSONC and
  // carries comments throughout, which is how the rest of this repo reads it.
  const TURBO_JSON = readFileSync(join(REPO_ROOT, 'turbo.json'), 'utf8');
  const task = /"@akasecurity\/plugin-browser-extension#test"\s*:\s*\{([\s\S]*?)\n {4}\}/.exec(
    TURBO_JSON,
  );

  /**
   * The elements of the task's `inputs` array, with `//` lines dropped first.
   *
   * The array rather than the task body as text, because a substring match over
   * the body is satisfied by two things turbo hashes nothing for: a
   * commented-out entry, and a longer path that merely CONTAINS the one named —
   * `$TURBO_ROOT$/cli/package.json.disabled` reads as covered and hashes no file
   * that exists. Both were observed passing a text match.
   */
  function declaredInputs(body: string): string[] {
    const array = /"inputs"\s*:\s*\[([\s\S]*?)\]/.exec(body.replace(/^[ \t]*\/\/.*$/gm, ''));
    const list = array?.[1];
    if (list === undefined) return [];
    const out: string[] = [];
    for (const [, value] of list.matchAll(/"([^"]*)"/g)) {
      if (value !== undefined) out.push(value);
    }
    return out;
  }

  const inputs = declaredInputs(task?.[1] ?? '');

  it('declares a task entry for this package', () => {
    expect(
      task,
      'turbo.json declares no @akasecurity/plugin-browser-extension#test task, so this suite ' +
        'falls back to the root `test` task and stops hashing the CLI source it reads',
    ).not.toBeNull();
  });

  it('declares a non-empty inputs array', () => {
    // Asserted on its own so a moved or reshaped `inputs` reports THAT, rather
    // than arriving at the three membership checks below as an empty list and
    // reading as three missing files.
    expect(inputs.length).toBeGreaterThan(0);
    // $TURBO_DEFAULT$ keeps the package's own files in the hash: naming inputs
    // REPLACES the default set, so dropping it would leave the task hashing the
    // three cross-package files and nothing of this package at all.
    expect(inputs).toContain('$TURBO_DEFAULT$');
  });

  it('names the CLI source in its inputs', () => {
    expect(
      inputs,
      'the task must hash cli/src/commands/extension.ts, or a CLI-only change replays a cached pass',
    ).toContain('$TURBO_ROOT$/cli/src/commands/extension.ts');
  });

  it('names the CLI manifest in its inputs', () => {
    expect(
      inputs,
      'the task must hash cli/package.json, or a CLI-only version bump replays a cached pass ' +
        'at exactly the moment the shared-version-line guard exists to fire',
    ).toContain('$TURBO_ROOT$/cli/package.json');
  });

  it('names turbo.json in its inputs, so removing them re-runs this suite', () => {
    // Self-coverage: without this, deleting the input above is invisible here
    // for the same reason the CLI source was — the config that silences the
    // guard is not itself hashed by it.
    expect(inputs).toContain('$TURBO_ROOT$/turbo.json');
  });
});
