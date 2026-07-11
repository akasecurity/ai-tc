'use client';

import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Owns a search box that drives a URL query param on the OSS dashboard's
 * server-rendered pages. One home for the subtle invariants every list page
 * shared as hand-copied machinery (Detections/Findings/Data Shares/Inventory):
 *
 *  - debounce typing before it becomes a `router.push` (so the Server Component
 *    isn't re-queried on every keystroke),
 *  - resync the box when the URL term changes from *outside* our own push
 *    (browser back/forward), told apart via the `lastPushed` ref,
 *  - let an explicit navigation (selection, filter) cancel any in-flight debounce
 *    so its stale closure can't clobber the new URL — and sync the box to the term
 *    the target URL carries, which also fixes the "selection keeps the previous
 *    search" edge (clear the box by navigating with an empty term).
 *
 * `buildSearchUrl(term)` returns the URL a *debounced search* navigates to, built
 * from whatever other params (filter, selection…) are current. It is read through
 * a ref, so it always sees the latest state without resetting the debounce timer.
 */
export function useDebouncedUrlQuery(
  urlQuery: string,
  buildSearchUrl: (term: string) => string,
  delayMs = 300,
): {
  query: string;
  setQuery: (value: string) => void;
  onNavigate: (term: string) => void;
} {
  const router = useRouter();
  const [query, setQuery] = useState(urlQuery);

  const lastPushed = useRef(urlQuery);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Keep the latest URL builder in a ref (updated in an effect, not during
  // render) so the debounce effect always calls the current one without listing
  // it as a dependency — depending on it directly would reset the timer every
  // render, since callers pass a fresh closure over their current params.
  const buildRef = useRef(buildSearchUrl);
  useEffect(() => {
    buildRef.current = buildSearchUrl;
  }, [buildSearchUrl]);

  const cancelDebounce = useCallback(() => {
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
      debounceRef.current = null;
    }
  }, []);

  // Call immediately before an explicit (non-search) navigation, with the search
  // term the target URL carries. Cancels any pending debounce, records the term so
  // neither the resync effect nor the debounce re-fires against it, and syncs the
  // box (so navigating with '' visibly clears the search).
  const onNavigate = useCallback(
    (term: string) => {
      cancelDebounce();
      lastPushed.current = term.trim();
      setQuery(term);
    },
    [cancelDebounce],
  );

  // Resync the box when the URL term changes from outside our own push.
  useEffect(() => {
    if (urlQuery !== lastPushed.current) {
      lastPushed.current = urlQuery;
      setQuery(urlQuery);
    }
  }, [urlQuery]);

  // Debounce typing into a URL push. The lastPushed guard closes the window where
  // an explicit navigation has synced the box but the URL term hasn't caught up
  // yet, so the debounce can't fire a stale second push.
  useEffect(() => {
    const term = query.trim();
    if (term === urlQuery || term === lastPushed.current) return undefined;
    const handle = setTimeout(() => {
      lastPushed.current = term;
      debounceRef.current = null;
      router.push(buildRef.current(query));
    }, delayMs);
    debounceRef.current = handle;
    return () => {
      clearTimeout(handle);
      debounceRef.current = null;
    };
  }, [query, urlQuery, delayMs, router]);

  return { query, setQuery, onNavigate };
}
