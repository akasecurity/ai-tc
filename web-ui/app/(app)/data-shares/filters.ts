// Pure URL ⇄ query helpers for the Data Shares page, shared by the Server
// Component (parse) and the client shell (build). Kept dependency-free so both
// the server and browser bundles can import them. Selection (dest/ep) and the
// search term live in the URL so the Server Component re-reads the local store on
// every change — the OSS store is server-only.

export interface DataSharesSearchParams {
  q?: string;
  dest?: string;
  ep?: string;
}

/** The active search term (empty string = no filter). */
export function parseQuery(sp: DataSharesSearchParams): string {
  return typeof sp.q === 'string' ? sp.q : '';
}

/** The open destination + endpoint selection, if any. An `ep` is only valid with a `dest`. */
export function parseSelection(sp: DataSharesSearchParams): {
  dest: string | null;
  ep: string | null;
} {
  const dest = typeof sp.dest === 'string' && sp.dest !== '' ? sp.dest : null;
  const ep = dest && typeof sp.ep === 'string' && sp.ep !== '' ? sp.ep : null;
  return { dest, ep };
}

/** Build the URLSearchParams for a Data Shares navigation. */
export function buildDataSharesParams(opts: {
  q?: string;
  dest?: string | null;
  ep?: string | null;
}): URLSearchParams {
  const params = new URLSearchParams();
  const q = opts.q?.trim();
  if (q) params.set('q', q);
  if (opts.dest) {
    params.set('dest', opts.dest);
    // An endpoint selection is only meaningful inside a destination.
    if (opts.ep) params.set('ep', opts.ep);
  }
  return params;
}
