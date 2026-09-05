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
  parseSelectedRule,
  parseSession,
  parseTools,
  parseView,
  toFindingTypesQuery,
  toInstancesQuery,
  toLocationsQuery,
  toTypeInstancesQuery,
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
// The three views are different reads, not one read shaped three ways — they
// page by different units and their status filter means different things (see
// the store's FindingInstancesView). The default By-type view is a master/detail
// pair: a keyset-paged list of TYPES and, beside it, a keyset-paged list of the
// selected type's FINDINGS. Neither bounds the other, so no per-type cap exists
// and both sides page as far as the store goes.
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
        range={range}
        from={from}
        tools={tools}
        repo={repo}
        file={file}
        renderedAt={renderedAt}
      />
    );
  }

  // ─── The By-type view: two reads, and the selection resolved between them ──
  //
  // The type list and the findings panel are separate keyset-paged reads, so
  // neither bounds the other — which is the whole point of the split. Resolving
  // which type is selected happens HERE rather than in the client so the two
  // panels can never disagree about it.
  const requestedRule = parseSelectedRule(sp);

  // A `?finding=` id may name a type or a single finding, and the Activity page
  // emits the latter. One primary-key seek settles it: `groupId` IS the rule id,
  // so this both selects the left row and supplies the drawer — without it, a
  // finding older than the panel's first page could be resolved by nothing.
  const deepLinkedInstance = selectedId ? await db().findings.findingInstance(selectedId) : null;

  const types = await db().findings.listFindingTypes({
    ...toFindingTypesQuery(filters, query, session, scope),
    // Keep the selected type present in the list however far it sorts, so
    // selecting one from a later page does not make it vanish from the list
    // that is showing it as selected.
    ...(deepLinkedInstance
      ? { includeId: deepLinkedInstance.groupId }
      : requestedRule
        ? { includeId: requestedRule }
        : {}),
  });

  // Fall back to the first listed type when nothing is pinned, or when what is
  // pinned did not survive the type-level filters — a selection the list does
  // not contain would render a panel beside a list that disowns it.
  // A pinned type is honoured only when the list actually contains it. That
  // applies to the deep-linked one too: `includeId` appends it when it survives
  // the type filters, but when it does not, `findDeepLinked` finds nothing to
  // append and selecting it anyway renders a panel beside a list that disowns
  // it — the client's `instances && selectedType` guard then falls through to
  // "Select a type" and the deep link resolves to nothing at all.
  const pinnedRule = deepLinkedInstance?.groupId ?? requestedRule;
  const selectedRule =
    pinnedRule && types.items.some((t) => t.id === pinnedRule)
      ? pinnedRule
      : (types.items[0]?.id ?? '');

  // The drawer opens only on the type that is actually selected; a deep link
  // whose type the filters excluded selects the first listed type instead, and
  // opening its drawer over a different type's findings would be a lie.
  const drawerInstance = deepLinkedInstance?.groupId === selectedRule ? deepLinkedInstance : null;

  const instances = selectedRule
    ? await db().findings.listFindingInstances(
        toTypeInstancesQuery(filters, selectedRule, session, scope),
      )
    : null;

  return (
    <FindingsClient
      view="grouped"
      types={types}
      instances={instances}
      selectedRule={selectedRule}
      deepLinkedInstance={drawerInstance}
      filters={filters}
      query={query}
      session={session}
      range={range}
      from={from}
      tools={tools}
      repo={repo}
      file={file}
      renderedAt={renderedAt}
    />
  );
}
