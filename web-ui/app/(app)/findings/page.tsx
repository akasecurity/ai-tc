import { rangeToFromIso } from '@akasecurity/dashboard-ui';

import { db } from '../../lib/db';
import { renderInstant } from '../../lib/rendered-at';
import {
  type FindingsScope,
  type FindingsSearchParams,
  parseFile,
  parseFindingsFilters,
  parseQuery,
  parseRange,
  parseRepo,
  parseSelectedFinding,
  parseSession,
  parseTools,
  parseView,
  toGroupedQuery,
  toInstancesQuery,
  toLocationsQuery,
} from './filters';
import { FindingsClient } from './FindingsClient';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export const metadata = { title: 'Findings' };

// Reads the local store's findings for the URL's view + filters, then hands off
// to the client shell for the interactive table + detail sheet. Everything lives
// in the URL so this re-runs (server-side) on every change. The Activity page
// deep-links here with ?session=… (scopes the list), ?finding=… (opens the
// detail sheet) and ?tool=/?range= (carries its own scope).
//
// The three views are three different reads, not one read shaped three ways —
// they page by different units and their status filter means different things
// (see the store's FindingInstancesView).
export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<FindingsSearchParams>;
}) {
  const sp = await searchParams;
  const filters = parseFindingsFilters(sp);
  const query = parseQuery(sp);
  const session = parseSession(sp);
  const selectedId = parseSelectedFinding(sp);
  const view = parseView(sp);
  const range = parseRange(sp);
  const tools = parseTools(sp);
  const repo = parseRepo(sp);
  const file = parseFile(sp);

  // One instant for the whole route: every relative label below is measured
  // against it during the server render and again during hydration — captured
  // before `from` below so the query window derives from the same instant
  // rather than a clock read apart from the labels it scopes.
  const renderedAt = renderInstant();
  // An absent/unknown range means all time — this list has never had a default
  // window, and applying one silently would hide findings.
  const from = range ? rangeToFromIso(range, renderedAt) : null;
  const scope: FindingsScope = {
    ...(from ? { from } : {}),
    ...(tools.length ? { tools } : {}),
    ...(repo ? { repo } : {}),
    ...(file ? { file } : {}),
  };

  if (view === 'flat') {
    const data = await db().findings.listFindingInstances(
      toInstancesQuery(filters, query, session, scope),
    );
    return (
      <FindingsClient
        view="flat"
        flat={data}
        filters={filters}
        query={query}
        session={session}
        selectedId={selectedId}
        range={range}
        from={from}
        tools={tools}
        repo={repo}
        file={file}
        renderedAt={renderedAt}
      />
    );
  }

  if (view === 'files') {
    const data = await db().findings.listFindingLocations(
      toLocationsQuery(filters, query, session, scope),
    );
    return (
      <FindingsClient
        view="files"
        locations={data}
        filters={filters}
        query={query}
        session={session}
        selectedId={selectedId}
        range={range}
        from={from}
        tools={tools}
        repo={repo}
        file={file}
        renderedAt={renderedAt}
      />
    );
  }

  const data = await db().findings.listGroupedFindings({
    ...toGroupedQuery(filters, query, session, scope),
    // Resolve the one-shot deep link even when it sorts past the first page.
    ...(selectedId ? { includeId: selectedId } : {}),
  });

  return (
    <FindingsClient
      view="grouped"
      data={data}
      filters={filters}
      query={query}
      session={session}
      selectedId={selectedId}
      range={range}
      from={from}
      tools={tools}
      repo={repo}
      file={file}
      renderedAt={renderedAt}
    />
  );
}
