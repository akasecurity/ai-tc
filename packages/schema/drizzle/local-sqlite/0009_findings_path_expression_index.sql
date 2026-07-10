-- Custom migration: partial expression index for the resolver's per-path reads.
--
-- openAtRestKeysForPath / resolvedAtRestKeysForPath (and the scanner's tier-3
-- open-key probe) filter at-rest events by
--   e.kind = 'code_change' AND json_extract(e.metadata, '$.filePath') = :path
-- once per changed/deleted file on every scan — previously a full events scan
-- per file. json_extract is deterministic, so SQLite allows it in an index;
-- the WHERE kind = 'code_change' keeps the index to exactly the rows those
-- queries can match (in-flight events are never path-addressed).
CREATE INDEX `idx_events_code_change_path` ON `events` (json_extract(`metadata`, '$.filePath')) WHERE `kind` = 'code_change';
