import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { SourceFile } from '../../../test/helpers/sighting-sender-guard.ts';
import {
  readSources,
  transportsOutsideTheGate,
  ungatedSightingSenders,
} from '../../../test/helpers/sighting-sender-guard.ts';

const ROOT = fileURLToPath(new URL('../../../', import.meta.url));

// Every product source tree in the workspace except the transport's own
// package, with paths prefixed by the tree they came from.
function workspaceSources(): SourceFile[] {
  const trees = [
    ...readdirSync(join(ROOT, 'packages'))
      .filter((name) => name !== 'remote')
      .map((name) => join('packages', name, 'src')),
    ...readdirSync(join(ROOT, 'plugins')).map((name) => join('plugins', name, 'src')),
    'cli/src',
    'web-ui/app',
    'web-ui/lib',
  ].filter((tree) => existsSync(join(ROOT, tree)));
  return trees.flatMap((tree) =>
    readSources(join(ROOT, tree)).map((s) => ({ ...s, path: `${tree}/${s.path}` })),
  );
}

describe('the credential-sightings send path', () => {
  it('has the forwarder every send goes through consult the sharing gate', () => {
    const sources = readSources(fileURLToPath(new URL('../src/', import.meta.url)));
    expect(ungatedSightingSenders(sources, ['credential-sightings.ts'])).toEqual([]);
  });

  it('reads the trees it guards', () => {
    const sources = workspaceSources();
    expect(sources.some((s) => s.path.startsWith('cli/src/'))).toBe(true);
    expect(sources.some((s) => s.path.startsWith('web-ui/app/'))).toBe(true);
  });

  it('hands the sightings transport only to a forwarder that reads the gate', () => {
    expect(transportsOutsideTheGate(workspaceSources())).toEqual([]);
  });

  it('flags a module that builds the transport and sends through it directly', () => {
    const direct = {
      path: 'direct.ts',
      text: 'const send = createCredentialSightingsSender();\nawait send(target, request);',
    };
    const handedOn = {
      path: 'handed-on.ts',
      text: 'await forwardScanSightings(base, target, result, { send: createCredentialSightingsSender() });',
    };
    expect(transportsOutsideTheGate([direct, handedOn])).toEqual(['direct.ts']);
  });
});
