import { createHash } from 'node:crypto';
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
function extensionIdFromKey(key: string): string {
  const digest = createHash('sha256').update(Buffer.from(key, 'base64')).digest();
  return [...digest.subarray(0, 16)]
    .flatMap((byte) => [byte >> 4, byte & 0x0f])
    .map((nibble) => String.fromCharCode(97 + nibble))
    .join('');
}

describe('the CLI grants the id this manifest key derives', () => {
  // `aka extension install` writes allowed_origins into the native-host
  // manifest, and Chrome refuses connectNative for any origin missing from it.
  // So a key swap that never reaches the CLI's list is not a build failure —
  // it is an extension that installs cleanly and silently cannot reach the
  // host. Replacing the committed key (as publishing to the Chrome Web Store
  // does, since the store signs with its own) fails here until the CLI lists
  // the new id.
  const listed = (() => {
    const block = /const EXTENSION_IDS = \[([\s\S]*?)\];/.exec(CLI_EXTENSION_SOURCE);
    return [...(block?.[1] ?? '').matchAll(/'([^']*)'/g)].map((m) => m[1]);
  })();

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
