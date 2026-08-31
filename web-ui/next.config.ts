import { fileURLToPath } from 'node:url';

import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Pin the standalone file-tracing root to the repo root. Without this, Next infers the
  // root from the nearest lockfile and can climb above the repo (e.g. a lockfile in the
  // developer's home dir), nesting server.js under an absolute path and breaking the
  // bundle into cli/web-ui. Pinning keeps the standalone layout (web-ui/server.js)
  // deterministic across checkouts and CI.
  outputFileTracingRoot: fileURLToPath(new URL('..', import.meta.url)),
  // The workspace packages export raw .ts source (no build step), so Next must
  // compile them. node:sqlite / node:path inside @akasecurity/persistence stay external
  // as Node builtins on the server. (If @akasecurity/persistence ever emits built JS,
  // move it to serverExternalPackages instead.)
  transpilePackages: [
    '@akasecurity/ui-kit',
    '@akasecurity/dashboard-ui',
    '@akasecurity/schema',
    '@akasecurity/persistence',
    '@akasecurity/detections',
    '@akasecurity/local-ops',
    '@akasecurity/plugin-sdk',
    // Raw .ts like every entry above it ("exports": { ".": "./src/index.ts" },
    // no build step), which is the rule this list states.
    //
    // Listed for that consistency, NOT because the build currently needs it: it
    // is reached only from a Server Action, and `next build` was verified to
    // pass with this line removed. It is here so the list keeps meaning "every
    // workspace package we import", which is what makes the next addition a
    // one-line question rather than a bisect.
    '@akasecurity/remote',
  ],
  // Self-contained server bundle (.next/standalone/.../server.js) so `aka dashboard`
  // — and the packaged @akasecurity/cli — can launch the web-ui without a full
  // node_modules. node:sqlite is traced in as a Node builtin.
  output: 'standalone',
  // The scan page's ReDoS-bounding worker thread. Nothing IMPORTS it — it is
  // started by path with `new Worker(…)` — so Next's tracer cannot discover it
  // and the standalone build would ship without it, leaving the folder scan to
  // drop every unreviewed rule it cannot bound. The path must stay in step with
  // SCAN_WORKER_RELATIVE_PATH in app/lib/scan-worker.ts, which is what resolves
  // it at runtime, and with tsup.config.ts, which emits it.
  outputFileTracingIncludes: {
    '/scan': ['./dist/scan-worker.js'],
  },
  // Server Actions carry the dashboard's write surface. Next's built-in CSRF
  // check requires Origin == Host; this list only ever WIDENS that check (it is
  // consulted when the two differ), so it is pinned to loopback spellings of
  // the default `aka dashboard` port — an origin/host pair that mixes loopback
  // names still works, nothing else is added. The DNS-rebinding gate — under
  // rebinding Origin and Host agree, so the built-in check passes — is the
  // loopback Host check in middleware.ts, which covers any port.
  experimental: {
    serverActions: {
      allowedOrigins: ['localhost:4319', '127.0.0.1:4319', '[::1]:4319'],
    },
  },
  // Lint is run by the monorepo's own eslint (pnpm lint), not by `next build`.
  eslint: { ignoreDuringBuilds: true },
};

export default nextConfig;
