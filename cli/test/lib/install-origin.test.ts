import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { detectInstallChannel } from '@akasecurity/local-ops';
import { describe, expect, it } from 'vitest';

import { cliInstallOrigin } from '../../src/lib/install-origin.ts';

// The CLI half of the install-origin split, and the mirror image of web-ui's
// test/install-origin.test.ts. That one asserts its module never READS
// `import.meta.url`, because a Next build replaces it with the build machine's
// source path; this one asserts the opposite, because tsup leaves it live and
// it is the only value that points inside the running install.
//
// Nothing else covers this file. `@akasecurity/local-ops` deliberately refuses
// to resolve an origin itself, so if this one silently answered `undefined` the
// classifier would report `unknown` and `aka update` would print advice instead
// of updating — a failure with no exception and no failing assertion anywhere.

const moduleDir = dirname(
  fileURLToPath(new URL('../../src/lib/install-origin.ts', import.meta.url)),
);

describe('cliInstallOrigin', () => {
  it('states the directory the running module was loaded from', () => {
    // Under vitest that is the source directory; in the published bundle it is
    // `<install>/dist`. Either way it is a path INSIDE the install, which is
    // the property the classifier needs and the one a bundler can break.
    expect(cliInstallOrigin()).toStrictEqual({ moduleDir });
  });

  it('reads import.meta.url — the value this side of the split depends on', () => {
    // The inverse of the web-ui guard. Resolving the origin any other way here
    // (cwd, argv[1], a constant) points outside the install as soon as the user
    // runs `aka` from another directory.
    const source = readFileSync(
      fileURLToPath(new URL('../../src/lib/install-origin.ts', import.meta.url)),
      'utf8',
    );
    const code = source
      .split('\n')
      .filter((line) => !line.trimStart().startsWith('//') && !line.trimStart().startsWith('*'))
      .join('\n');
    expect(code).toContain('import.meta.url');
  });

  it('walks up to this checkout, so the origin and the classifier agree', () => {
    // End to end: the origin is only useful if the walk from it meets the CLI's
    // own package.json. Run from a checkout that is a `dev` tree, which refuses
    // to install rather than proposing one.
    const channel = detectInstallChannel(cliInstallOrigin());
    expect(channel).toMatchObject({ kind: 'dev' });
  });
});
