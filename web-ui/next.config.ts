import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
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
  ],
  // Self-contained server bundle (.next/standalone/.../server.js) so `aka dashboard`
  // — and the packaged @akasecurity/cli — can launch the web-ui without a full
  // node_modules. node:sqlite is traced in as a Node builtin.
  output: 'standalone',
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
