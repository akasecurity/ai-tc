import { describe, expect, it } from 'vitest';

import { bashWrittenPayloads } from '../../src/hooks/bash-payloads.ts';

describe('bashWrittenPayloads', () => {
  it('takes a heredoc written to a file, either redirect order', () => {
    const a = "cat > app.py <<'EOF'\nx = 1\nEOF\n";
    const b = "cat <<EOF >> out.sql\nSELECT 1\nEOF";
    expect(bashWrittenPayloads(a)).toEqual([{ path: 'app.py', text: 'x = 1' }]);
    expect(bashWrittenPayloads(b)).toEqual([{ path: 'out.sql', text: 'SELECT 1' }]);
  });

  it('takes a heredoc piped into tee, and a <<- body with tab-indented end', () => {
    expect(bashWrittenPayloads("tee -a notes.md <<EOF\nhi\nEOF")).toEqual([
      { path: 'notes.md', text: 'hi' },
    ]);
    expect(bashWrittenPayloads('cat > a.sh <<-EOF\n\tbody\n\tEOF')).toEqual([
      { path: 'a.sh', text: '\tbody' },
    ]);
  });

  it('takes a quoted echo or printf written to a file', () => {
    expect(bashWrittenPayloads(`echo 'select * from t where a = ' + x > q.py`)).toEqual([]);
    expect(bashWrittenPayloads(`echo "a = 1" > conf.py`)).toEqual([{ path: 'conf.py', text: 'a = 1' }]);
    expect(bashWrittenPayloads(`printf '%s\\n' > x.txt`)).toEqual([{ path: 'x.txt', text: '%s\\n' }]);
  });

  it('ignores a heredoc fed to a command, and writes to devices or fds', () => {
    expect(bashWrittenPayloads("psql <<'EOF'\nselect * from t where id = '%s'\nEOF")).toEqual([]);
    expect(bashWrittenPayloads('python - <<EOF\nprint(1)\nEOF')).toEqual([]);
    expect(bashWrittenPayloads('echo "x" > /dev/null')).toEqual([]);
    expect(bashWrittenPayloads('echo "x" 2>&1')).toEqual([]);
    expect(bashWrittenPayloads('grep "select * from t" file.txt')).toEqual([]);
  });
});
