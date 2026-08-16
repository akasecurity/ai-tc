// A throwaway HTTP server over one fixture directory, bound to 127.0.0.1 on an
// ephemeral port. Its URL is what the suite hands the installers as
// AKA_DOWNLOAD_BASE — the seam both scripts document and nothing else in the
// tree consumed.
//
// WHY HTTP AND NOT A file:// BASE. install.sh would take either (curl speaks
// FILE), but PowerShell's Invoke-WebRequest does not — a file:// URI is rejected
// outright on PowerShell 7. Serving over loopback is the only base BOTH scripts
// accept, so the two halves of this suite exercise the same download path
// instead of diverging on the one step that is common to them.
//
// Loopback is not egress: test/setup/no-network.ts permits it, and the Linux
// `No-network` job brings `lo` up inside its namespace before running the suite,
// so this works there too — with everything else, for every process in the tree,
// still unreachable.
//
// The node:http import is a documented, file-scoped opt-out from the workspace
// network ban; see tools/installer/eslint.config.mjs and CLAUDE.md §4.
import { once } from 'node:events';
import { createReadStream, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { basename, join } from 'node:path';

export interface ReleaseServer {
  /** The base URL to pass as AKA_DOWNLOAD_BASE. */
  readonly base: string;
  close(): Promise<void>;
}

/** Serve the files directly inside `dir` over loopback. */
export async function serveRelease(dir: string): Promise<ReleaseServer> {
  const server = createServer((req, res) => {
    // Only ever a file sitting directly in `dir`. Joining the request path would
    // let a `..` climb out of the fixture; taking the basename cannot.
    //
    // decodeURIComponent THROWS on a malformed escape (`/%zz`), and a throw here
    // is an uncaughtException that takes the worker down instead of answering
    // 404 — so the decode is the one step that has to be guarded rather than
    // trusted.
    const requested = (req.url ?? '/').split('?')[0] ?? '';
    let name: string;
    try {
      name = basename(decodeURIComponent(requested));
    } catch {
      res.writeHead(400).end();
      return;
    }
    const file = join(dir, name);
    // One stat, not an existsSync/statSync pair: two calls are two syscalls with
    // a window between them, and a file removed inside that window makes the
    // second one throw where the first said it was safe.
    const stat = name === '' ? undefined : statSync(file, { throwIfNoEntry: false });
    if (stat?.isFile() !== true) {
      res.writeHead(404).end();
      return;
    }
    // Streamed rather than read whole: build-binaries.yml serves the real SEA
    // archive through this, and buffering ~46 MB per request into the vitest
    // worker buys nothing over piping it.
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-length': String(stat.size),
    });
    createReadStream(file).pipe(res);
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the fixture release server did not bind a TCP port');
  }

  return {
    base: `http://127.0.0.1:${String(address.port)}`,
    async close() {
      // A keep-alive connection the client has not closed keeps `close()`
      // pending, and a pending teardown reads as a hung suite rather than a
      // leaked socket.
      server.closeAllConnections();
      server.close();
      await once(server, 'close');
    },
  };
}
