import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { InstallOrigin } from '@akasecurity/local-ops';

// Where THIS `aka` says its own code lives, for install-channel classification.
//
// `@akasecurity/local-ops` deliberately refuses to answer that question itself:
// the value has to come from `import.meta.url`, and whether that survives
// bundling depends on the bundler. Here it does. tsup/esbuild emits ESM and
// leaves `import.meta.url` as a live expression, so in the published
// `cli/dist/cli.js` it resolves to that file at runtime — inside the install,
// which is exactly what the classifier needs to walk up from. (The dashboard is
// the other caller and the other answer; see web-ui/app/lib/install-origin.ts.)
//
// Under a SEA build the classifier never consults this — a Single Executable
// Application is identified from `node:sea` and its own `execPath` — but the
// value is still computed, so it must not throw.

/**
 * The directory the running CLI was loaded from, or `undefined` when this
 * runtime cannot say. `undefined` classifies as an unrecognised install, which
 * prints advice instead of running a package manager — the safe answer.
 */
export function cliInstallOrigin(): InstallOrigin {
  try {
    return { moduleDir: dirname(fileURLToPath(import.meta.url)) };
  } catch {
    return { moduleDir: undefined };
  }
}
