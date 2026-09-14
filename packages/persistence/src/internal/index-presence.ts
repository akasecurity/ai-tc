import type { DatabaseSync } from 'node:sqlite';

/**
 * The statement a probe runs to ask whether one index exists. NOCASE because
 * SQLite resolves an identifier, the name in `INDEXED BY` included, without
 * regard to ASCII case.
 */
export const INDEX_PRESENCE_SQL =
  "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ? COLLATE NOCASE";

/** The statement a probe runs on each call outside a transaction, to learn whether the schema changed. */
export const SCHEMA_VERSION_SQL = 'PRAGMA schema_version';

/**
 * A per-connection answer to "does the index named `name` exist right now?",
 * for a read that pins its plan with `INDEXED BY` and must fall back when it
 * cannot.
 *
 * `INDEXED BY` naming an absent index fails at prepare (`no such index`), and a
 * statement prepared while the index existed fails the same way once another
 * connection drops it. So the answer follows the schema in BOTH directions,
 * including changes other processes commit.
 *
 * Outside a transaction, every call reads `PRAGMA schema_version`, which SQLite
 * bumps whenever a schema change commits on any connection. Answers are cached
 * per name for as long as that version holds: a steady schema costs one pragma
 * read per call plus one `sqlite_master` lookup per name, and any committed
 * CREATE or DROP discards the whole cache.
 *
 * Inside a transaction, the probe looks the name up directly and caches nothing.
 * An uncommitted schema change bumps the version as well, and a ROLLBACK (or a
 * ROLLBACK TO a savepoint) puts it back, so a later commit can land on the same
 * number; an answer cached under it would describe a schema that never
 * committed. The committed version only rises.
 *
 * The answer describes the schema this connection sees at the call. Inside an
 * open transaction that is the transaction's snapshot. Outside one, another
 * connection can still commit a change between this call and a later prepare,
 * so a caller preparing a pinned statement must still handle `no such index`.
 */
export function createIndexProbe(db: DatabaseSync): (name: string) => boolean {
  const lookup = db.prepare(INDEX_PRESENCE_SQL);
  const version = db.prepare(SCHEMA_VERSION_SQL);
  const known = new Map<string, boolean>();
  let knownAt: number | undefined;
  return (name) => {
    if (db.isTransaction) return lookup.get(name) !== undefined;
    const row = version.get() as { schema_version: number };
    if (row.schema_version !== knownAt) {
      known.clear();
      knownAt = row.schema_version;
    }
    let present = known.get(name);
    if (present === undefined) {
      present = lookup.get(name) !== undefined;
      known.set(name, present);
    }
    return present;
  };
}
