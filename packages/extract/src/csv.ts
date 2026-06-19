/**
 * CSV content extraction.
 *
 * Pure, dependency-free, RFC-4180-ish CSV parsing. No I/O, no Node-API deps.
 * The detections engine ({@link @aka/detections}) only scans strings, so bulk
 * tabular formats are flattened here into a normalized, header-prefixed `text`
 * rendering that places each column name adjacent to its value. This lets the
 * proximity engine (`requiresNearby`) corroborate values against their header
 * (e.g. a `dob` cell value sits next to the literal "dob").
 */

export interface ExtractResult {
  /** Header row values (first row), or positional `col1,col2,...` if headerless. */
  columns: string[];
  /** Data rows as string arrays. */
  rows: string[][];
  /**
   * Normalized, header-prefixed rendering. For each data row, `"<column>: <cell>"`
   * pairs are joined with `" | "`, and rows are joined with `"\n"`.
   */
  text: string;
}

export interface ExtractCsvOptions {
  /** Field delimiter. Defaults to `","`. */
  delimiter?: string;
}

/**
 * Parse a CSV string into a fully-tokenized grid of rows/fields.
 *
 * Handles quoted fields, delimiters and newlines inside quotes, doubled-quote
 * (`""`) escapes, and both CRLF and LF line endings.
 */
function parseGrid(input: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  let field = '';
  let row: string[] = [];
  let inQuotes = false;
  let sawAnyChar = false;

  const pushField = (): void => {
    row.push(field);
    field = '';
  };
  const pushRow = (): void => {
    pushField();
    rows.push(row);
    row = [];
  };

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (char === undefined) {
      continue;
    }
    sawAnyChar = true;

    if (inQuotes) {
      if (char === '"') {
        if (input[i + 1] === '"') {
          // Escaped quote inside a quoted field.
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      inQuotes = true;
    } else if (char === delimiter) {
      pushField();
    } else if (char === '\n') {
      pushRow();
    } else if (char === '\r') {
      // Swallow CR; the following LF (if any) terminates the row.
      if (input[i + 1] === '\n') {
        i++;
      }
      pushRow();
    } else {
      field += char;
    }
  }

  // Flush a trailing field/row unless the input ended exactly on a newline
  // (in which case there is no dangling record to emit).
  if (sawAnyChar && (field !== '' || row.length > 0)) {
    pushRow();
  }

  return rows;
}

/**
 * Extract structured content from a CSV string.
 *
 * The first row is treated as the header. A single-line input is treated as
 * headerless data with positional columns (`col1`, `col2`, ...).
 */
export function extractCsv(input: string, opts?: ExtractCsvOptions): ExtractResult {
  const delimiter = opts?.delimiter ?? ',';

  if (input === '') {
    return { columns: [], rows: [], text: '' };
  }

  const grid = parseGrid(input, delimiter);
  if (grid.length === 0) {
    return { columns: [], rows: [], text: '' };
  }

  let columns: string[];
  let dataRows: string[][];

  if (grid.length === 1) {
    // No header row: synthesize positional column names.
    const onlyRow = grid[0] ?? [];
    columns = onlyRow.map((_, idx) => `col${String(idx + 1)}`);
    dataRows = [onlyRow];
  } else {
    columns = grid[0] ?? [];
    dataRows = grid.slice(1);
  }

  const text = dataRows
    .map((cells) =>
      cells.map((cell, idx) => `${columns[idx] ?? `col${String(idx + 1)}`}: ${cell}`).join(' | '),
    )
    .join('\n');

  return { columns, rows: dataRows, text };
}
