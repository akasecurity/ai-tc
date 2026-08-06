import type { VaultInventoryEntry } from '@akasecurity/schema';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@akasecurity/ui-kit';

import { ScrubbedValue } from '../shared/ScrubbedValue.tsx';

export interface VaultReuseViewProps {
  entries: VaultInventoryEntry[];
}

// A value counts as reused when it was detected more than once or sighted in
// more than one place. The claim is scoped to this machine's store: the vault
// only sees what the local plugin captured.
function isReused(entry: VaultInventoryEntry): boolean {
  return entry.occurrences > 1 || entry.sightings.length > 1;
}

/**
 * The same-machine reuse signal: values detected in more than one place, ranked
 * by how often they recur. Reuse widens the blast radius of a single leak — one
 * exposed value unlocks every location listed here.
 */
export function VaultReuseView({ entries }: VaultReuseViewProps) {
  const reused = entries.filter(isReused).sort((a, b) => b.occurrences - a.occurrences);
  if (reused.length === 0) {
    return (
      <div className="rounded-xl border border-border bg-surface py-10 text-center text-sm text-text-3">
        No reused values detected on this machine.
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded-xl border border-border bg-surface p-4">
      <p className="mb-3 text-xs text-text-3">
        Values detected more than once on this machine, most-reused first.
      </p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Value</TableHead>
            <TableHead>Occurrences</TableHead>
            <TableHead>Seen in</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {reused.map((entry) => {
            const locations = [...new Set(entry.sightings.map((s) => s.location))];
            return (
              <TableRow key={entry.pointerId}>
                <TableCell>
                  <ScrubbedValue value={null} descriptor={entry} />
                </TableCell>
                <TableCell className="text-xs text-text-2">{String(entry.occurrences)}</TableCell>
                <TableCell>
                  <ul className="space-y-0.5 pl-3">
                    {locations.map((location) => (
                      <li key={location} className="font-mono text-xs text-text-2 list-disc py-1">
                        {location}
                      </li>
                    ))}
                  </ul>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
