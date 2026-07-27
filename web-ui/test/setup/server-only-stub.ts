// Empty stand-in for the `server-only` package under vitest.
//
// The real package throws at import time unless it is loaded through a React
// Server bundler (Next). The Server Actions under test import it transitively
// via app/lib/db, so vitest aliases the specifier here to let the real store
// logic run in a plain Node test process. See vitest.config.ts.
export {};
