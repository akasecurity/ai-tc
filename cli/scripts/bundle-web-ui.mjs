#!/usr/bin/env node
// Build the OSS web-ui as a Next "standalone" server and bundle it into
// cli/web-ui, so the published CLI's `aka dashboard` runs with no build step.
//
// This is wired to the package `prepack` script (and re-used by release-cli.yml),
// so ANY `pnpm pack` / `pnpm publish` — inside the release workflow or not — ships
// a fresh, complete web-ui. (Previously the bundling lived only in the workflow
// shell, so packing outside it shipped a CLI with a missing/stale dashboard.)
//
// Path-independent: all paths derive from this script's location, so it works
// whether invoked from cli (prepack) or the repo root (workflow).
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const cliDir = resolve(dirname(fileURLToPath(import.meta.url)), '..'); // cli
const repoRoot = resolve(cliDir, '..');
const webUiDir = join(repoRoot, 'web-ui');
const standalone = join(webUiDir, '.next', 'standalone');
const staticDir = join(webUiDir, '.next', 'static');
const dest = join(cliDir, 'web-ui');

const log = (m) => process.stdout.write(`bundle-web-ui: ${m}\n`);

// 1. Build the web-ui standalone (Turbo-cached, so this is cheap when unchanged).
//    Always rebuild so the bundle is fresh regardless of how prepack was invoked.
log('building @akasecurity/web-ui (output: standalone)…');
execFileSync('pnpm', ['turbo', 'run', 'build', '--filter=@akasecurity/web-ui'], {
  cwd: repoRoot,
  stdio: 'inherit',
});
if (!existsSync(standalone)) {
  throw new Error(
    `standalone build not found at ${standalone} — is next.config output:'standalone' set?`,
  );
}

// 2. Copy the standalone app code (server.js, .next, package.json) into cli/web-ui,
//    EXCLUDING its node_modules. The standalone's node_modules is pnpm's symlinked store
//    (.pnpm + absolute symlinks) which (a) doesn't survive `npm pack`/`install` — they
//    drop symlinks — and (b) can't be naively flattened without breaking pnpm's
//    transitive resolution (a copied `next` can't find its sibling deps in `.pnpm`).
//    Next externalizes only next/react/react-dom; the OSS workspace deps are bundled
//    INTO `.next`. So `@akasecurity/cli` declares next/react/react-dom as runtime
//    deps, `npm i -g` installs them FLAT, and server.js resolves them via Node's upward
//    node_modules walk. Static assets + public/ are copied next to the app, as Next needs.
rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(standalone, dest, {
  recursive: true,
  filter: (src) => !src.split(sep).includes('node_modules'),
});

const appNext = join(dest, 'web-ui', '.next');
mkdirSync(appNext, { recursive: true });
cpSync(staticDir, join(appNext, 'static'), { recursive: true });

const publicDir = join(webUiDir, 'public');
if (existsSync(publicDir)) {
  cpSync(publicDir, join(dest, 'web-ui', 'public'), { recursive: true });
}

// 3. Assert the server entry the CLI launches actually exists.
const server = join(dest, 'web-ui', 'server.js');
if (!existsSync(server)) {
  throw new Error(`server.js missing after bundle at ${server}`);
}
log(`bundled standalone web-ui → ${server}`);
