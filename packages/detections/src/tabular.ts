import type { DetectionCategory, Rule } from '@akasecurity/schema';

import { scan } from './engine.ts';

// A parsed tabular dataset — the structural shape produced by @akasecurity/extract
// (columns + rows). Declared here so @akasecurity/detections keeps NO runtime dependency
// on the extractor; any producer of this shape can be scanned.
export interface TabularTable {
  columns: string[];
  rows: string[][];
}

export interface TabularMatch {
  column: string;
  columnIndex: number;
  rowIndex: number;
  category: DetectionCategory;
  // A value-rule id (e.g. 'core-pii/ssn'), or 'header-cue' when the cell was
  // flagged solely because its column header names a sensitive field.
  ruleId: string;
  // The RAW matched value (or the whole cell for header cues) — NOT redacted.
  // Callers must mask this before displaying or persisting it.
  match: string;
  viaHeaderCue: boolean;
}

// Sensitive column-header cues. A header is normalized (lowercased, non-alnum
// collapsed to single spaces) then tested. When a column's header matches, its
// non-empty cells are treated as sensitive even if no value rule fires — this is
// how bulk PII in named columns (a "first_name" or "dob" column) is caught even
// when the value alone (e.g. "Alice") matches no pattern.
const HEADER_CUES: { pattern: RegExp; category: DetectionCategory }[] = [
  { pattern: /\b(ssn|social security)\b/, category: 'pii' },
  { pattern: /\b(dob|date of birth|birthdate|birth date)\b/, category: 'pii' },
  { pattern: /\b(first name|last name|full name|surname|name)\b/, category: 'pii' },
  { pattern: /\b(address|street|city|zip|zipcode|postal)\b/, category: 'pii' },
  { pattern: /\b(email|e mail)\b/, category: 'pii' },
  { pattern: /\b(phone|mobile|telephone)\b/, category: 'pii' },
  { pattern: /\b(mrn|medical record|member id|group id|diagnosis|icd)\b/, category: 'phi' },
  { pattern: /\b(card number|credit card|ccn|iban|account number)\b/, category: 'financial' },
];

function headerCategory(header: string): DetectionCategory | undefined {
  const norm = header
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
  if (norm.length === 0) return undefined;
  for (const cue of HEADER_CUES) {
    if (cue.pattern.test(norm)) return cue.category;
  }
  return undefined;
}

/**
 * Scan a parsed table cell-by-cell, mapping findings back to (column, row)
 * coordinates. Two signals are combined:
 *
 *  1. Value rules — each cell is scanned as `"<header>: <value>"` so the column
 *     header acts as the nearby label/context that gated rules (requiresNearby)
 *     need to corroborate (e.g. a `dob` column lets the gated DOB rule fire,
 *     while the same date in an unrelated column does not).
 *  2. Header cues — if the column header names a sensitive field, every non-empty
 *     cell in that column is flagged (only when no value rule already matched it),
 *     catching values that have no recognizable pattern of their own (names, etc.).
 *
 * Pure: takes data in, returns matches out. Pass the ruleset explicitly (e.g. a
 * custom pack's rules); falls back to the globally registered packs.
 */
export function scanTabular(table: TabularTable, rules?: Rule[]): TabularMatch[] {
  const out: TabularMatch[] = [];
  const columnCue = table.columns.map(headerCategory);

  table.rows.forEach((row, rowIndex) => {
    row.forEach((cell, columnIndex) => {
      if (cell.trim().length === 0) return;
      const column = table.columns[columnIndex] ?? `col${String(columnIndex + 1)}`;

      // Prefix the value with its header so gated rules get nearby context.
      const headerForScan = column.replace(/[^A-Za-z0-9]+/g, ' ').trim() || column;
      const valueMatches = scan(`${headerForScan}: ${cell}`, rules);
      for (const m of valueMatches) {
        out.push({
          column,
          columnIndex,
          rowIndex,
          category: m.category,
          ruleId: m.ruleId,
          match: m.rawMatch,
          viaHeaderCue: false,
        });
      }

      const cue = columnCue[columnIndex];
      if (cue && valueMatches.length === 0) {
        out.push({
          column,
          columnIndex,
          rowIndex,
          category: cue,
          ruleId: 'header-cue',
          match: cell,
          viaHeaderCue: true,
        });
      }
    });
  });

  return out;
}
