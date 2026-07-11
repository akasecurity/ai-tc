import type { InventorySelection as Selection } from '@akasecurity/dashboard-ui';
import { AssetType } from '@akasecurity/schema';

// Pure URL ⇄ state helpers for the Inventory page. The server-relevant state —
// the selected node (st/si), the file-browser path (path), the in-project search
// (fq) and the open file drawer (file) — lives in the URL so the Server Component
// re-reads the local store on each change. The nav's own view mode / type filter /
// expanded rows / nav search are pure client state and stay out of the URL.

export interface InventorySearchParams {
  st?: string;
  si?: string;
  path?: string;
  fq?: string;
  file?: string;
}

const SEL_TYPES = new Set<string>(['harness', 'project', ...AssetType.options]);

/** The selected node, when the URL carries a valid (type,id) pair. */
export function parseSelection(sp: InventorySearchParams): Selection | null {
  if (sp.st && sp.si && SEL_TYPES.has(sp.st)) {
    return { type: sp.st, id: sp.si } as Selection;
  }
  return null;
}

export function parsePath(sp: InventorySearchParams): string[] {
  return typeof sp.path === 'string' && sp.path !== '' ? sp.path.split('/') : [];
}

export function parseFileQuery(sp: InventorySearchParams): string {
  return typeof sp.fq === 'string' ? sp.fq : '';
}

export function parseDrawer(sp: InventorySearchParams): string | null {
  return typeof sp.file === 'string' && sp.file !== '' ? sp.file : null;
}

/** Build the URLSearchParams for an Inventory navigation. */
export function buildInventoryParams(opts: {
  sel?: Selection | null;
  path?: string[];
  fq?: string;
  file?: string | null;
}): URLSearchParams {
  const params = new URLSearchParams();
  if (opts.sel) {
    params.set('st', opts.sel.type);
    params.set('si', opts.sel.id);
  }
  if (opts.path && opts.path.length > 0) params.set('path', opts.path.join('/'));
  const fq = opts.fq?.trim();
  if (fq) params.set('fq', fq);
  if (opts.file) params.set('file', opts.file);
  return params;
}
