import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { NATIVE_HOST_NAME } from '../src/constants.ts';
import { resolveAdapter } from '../src/providers/registry.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test -> plugins/browser-extension
const PACKAGE_ROOT = join(HERE, '..');
// test -> repo root
const REPO_ROOT = join(HERE, '..', '..', '..');

interface ExtensionManifest {
  content_scripts: { matches: string[] }[];
  host_permissions?: string[];
  permissions: string[];
}

const manifest = JSON.parse(
  readFileSync(join(PACKAGE_ROOT, 'manifest.json'), 'utf8'),
) as ExtensionManifest;

// Every hostname the provider registry resolves — each must also be granted
// in the manifest, or the content script never loads on that host and the
// adapter is dead code.
const ADAPTER_HOSTNAMES = ['chatgpt.com', 'chat.openai.com', 'claude.ai'];

describe('manifest.json stays in sync with the provider registry', () => {
  it.each(ADAPTER_HOSTNAMES)('%s resolves to an adapter', (hostname) => {
    expect(resolveAdapter(hostname)).not.toBeNull();
  });

  it.each(ADAPTER_HOSTNAMES)('%s is granted in content_scripts matches', (hostname) => {
    expect(manifest.content_scripts[0]?.matches).toContain(`https://${hostname}/*`);
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
    const cliSource = readFileSync(
      join(REPO_ROOT, 'cli', 'src', 'commands', 'extension.ts'),
      'utf8',
    );
    const match = /const NATIVE_HOST_NAME = '([^']+)'/.exec(cliSource);
    expect(match?.[1]).toBe(NATIVE_HOST_NAME);
  });
});
