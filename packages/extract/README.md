# @akasecurity/extract

Pure, dependency-free content extraction for bulk formats. Currently: RFC-4180-ish
CSV parsing (`extractCsv`) — quoted fields, embedded delimiters/newlines, doubled-quote
escapes, CRLF/LF.

The detections engine (`@akasecurity/detections`) only scans strings, so this package
flattens tabular data into a normalized, header-prefixed rendering that places each
column name adjacent to its value. That lets the proximity engine (`requiresNearby`)
corroborate values against their header (e.g. a `dob` cell sits next to the literal
"dob").

## Status

This is a library-level capability: `extractCsv` pairs with `scanTabular` from
`@akasecurity/detections` to scan parsed tables cell-by-cell, but no CLI command or
plugin hook invokes it. It is exercised end-to-end by the `scanTabular` test suite.
Consumers embedding the engine can use it directly.

Note that `TabularMatch.match` (from `scanTabular`) carries the raw, unredacted
matched value — mask it before displaying or persisting.
