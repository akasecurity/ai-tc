import { installRemovingTeardown } from './helper.ts';

// NEVER RUN — see helper.ts. Written the way a suite calls a helper that
// registers its own teardown, so the guard can prove the scan resolves and reads
// a helper module from disk rather than only from an in-memory map.
installRemovingTeardown('/never/removed');
