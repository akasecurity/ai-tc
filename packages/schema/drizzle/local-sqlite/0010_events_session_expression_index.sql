-- Custom migration: partial expression index for session-scoped finding reads.
--
-- sessionFindingsCount, the session-scoped listGroupedFindings paths, and the
-- insert-time session dedup all filter live-capture events by
--   json_extract(e.metadata, '$.sessionId') = :sessionId
-- — previously a full findings-join scan with a JSON parse per row. The
-- IS NOT NULL predicate keeps the index to session-stamped events only (an
-- equality probe implies non-null, so SQLite still uses it).
CREATE INDEX `idx_events_session_id` ON `events` (json_extract(`metadata`, '$.sessionId')) WHERE json_extract(`metadata`, '$.sessionId') IS NOT NULL;
