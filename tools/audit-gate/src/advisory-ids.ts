#!/usr/bin/env node
// Prints every advisory id carried by the rendered reports (or issue bodies)
// named on argv, one per line, sorted and deduped. Absent files contribute
// nothing — the artifact report does not exist when that audit never ran.
//
// This exists because audit.yml's "has this advisory already been posted?"
// comparison used to be a shell `grep -o 'GHSA-[a-z0-9-]*'` on both sides, and
// an advisory the registry gives no GHSA id renders into the report under its
// NUMERIC id instead. Such an advisory produced an empty id list, `comm -23`
// emitted nothing, and no comment was ever posted onto the tracking issue. The
// extraction is one tested function in lib.ts rather than a regex in YAML for
// exactly that reason: nothing executes the YAML until the day it matters.

import { advisoryIdsFromReport, readIfPresent } from './lib.ts';

// One reader, shared with the pnpm-config check rather than re-rolled here.
// Both encode the same rule and it is a rule worth having in one place: absent
// means ENOENT and nothing else, so a file that exists but cannot be read is
// refused rather than reported as empty. Empty here would read as "every one of
// these was already posted" and would suppress the comment this path exists to
// send — the same shape of silent-pass the pnpm-config check refuses.
const ids = advisoryIdsFromReport(
  process.argv
    .slice(2)
    .map((path) => readIfPresent(path) ?? '')
    .join('\n'),
);
if (ids.length > 0) process.stdout.write(`${ids.join('\n')}\n`);
