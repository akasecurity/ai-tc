import { describe, expect, it } from 'vitest';

import { bashWrittenPayloads } from '../../src/hooks/bash-payloads.ts';

// path and text only; the span is checked on its own.
const read = (command: string) => {
  const { payloads, incomplete } = bashWrittenPayloads(command);
  return { incomplete, payloads: payloads.map(({ path, text }) => ({ path, text })) };
};
const paths = (command: string) => bashWrittenPayloads(command).payloads.map((p) => p.path);

describe('bashWrittenPayloads', () => {
  it('takes a heredoc written to a file, either redirect order, and says where it sits', () => {
    const a = "cat > app.py <<'EOF'\nx = 1\nEOF\n";
    const b = 'cat <<EOF >> out.sql\nSELECT 1\nEOF';
    expect(read(a).payloads).toEqual([{ path: 'app.py', text: 'x = 1' }]);
    expect(read(b).payloads).toEqual([{ path: 'out.sql', text: 'SELECT 1' }]);
    const p = bashWrittenPayloads(a).payloads[0];
    expect(a.slice(p?.start, p?.end)).toBe('x = 1');
  });

  it('takes a heredoc piped into tee, and a <<- body with tab-indented end', () => {
    expect(read('tee -a notes.md <<EOF\nhi\nEOF').payloads).toEqual([
      { path: 'notes.md', text: 'hi' },
    ]);
    expect(read('cat > a.sh <<-EOF\n\tbody\n\tEOF').payloads).toEqual([
      { path: 'a.sh', text: 'body' },
    ]);
    // The shell strips the leading tabs of every line; the region stays raw.
    const cmd = "cat > a.sh <<-'EOF'\n\tone\n\t\ttwo\nthree\n\tEOF";
    const p = bashWrittenPayloads(cmd).payloads[0];
    expect(p?.text).toBe('one\ntwo\nthree');
    expect(cmd.slice(p?.start, p?.end)).toBe('\tone\n\t\ttwo\nthree');
  });

  it('takes a quoted echo or printf written to a file', () => {
    expect(read(`echo 'select * from t where a = ' + x > q.py`).payloads).toEqual([]);
    expect(read(`echo "a = 1" > conf.py`).payloads).toEqual([{ path: 'conf.py', text: 'a = 1' }]);
    expect(read(`printf 'a = 1' > conf.py`).payloads).toEqual([{ path: 'conf.py', text: 'a = 1' }]);
    const cmd = `cd d && echo "a = 1" > conf.py\n`;
    const p = bashWrittenPayloads(cmd).payloads[0];
    expect(cmd.slice(p?.start, p?.end)).toBe('a = 1');
    const single = "printf 'x = 2' > debug:true";
    const q = bashWrittenPayloads(single).payloads[0];
    expect(single.slice(q?.start, q?.end)).toBe('x = 2');
  });

  it('does not read a printf format as the text written', () => {
    expect(read(`printf '%s\\n' > x.txt`).payloads).toEqual([]);
    expect(read(`printf '%s\\n' 'eval(request.body)' > f.py`).payloads).toEqual([]);
    expect(read(`printf '100%%' > pct.txt`).payloads).toEqual([]);
  });

  it('reads the redirect outside quotes, never from inside a quoted string', () => {
    expect(paths("cat <<EOF > 'my file.py'\nx = 1\nEOF")).toEqual(['my file.py']);
    expect(paths("cat <<EOF > 'a > b.py'\nx = 1\nEOF")).toEqual(['a > b.py']);
    expect(paths("tee 'x > y.py' <<EOF\nx = 1\nEOF")).toEqual(['x > y.py']);
    expect(paths('cat <<EOF # > c.py\nx = 1\nEOF')).toEqual([]);
  });

  it('takes nothing from a CRLF command, whose carriage returns bash keeps in its words', () => {
    const cmd = 'cat > f.py <<EOF\r\nEVIL1\r\nEOF\r\ncat > g.py <<EOF\r\nEVIL2\r\nEOF';
    expect(read(cmd).payloads).toEqual([]);
  });

  it('does not take a decoded body as code, but a file named base64.py is not a decoder', () => {
    expect(read('base64 -d > f.py <<EOF\nZXZhbCh4KQ==\nEOF').payloads).toEqual([]);
    expect(read('cat <<EOF > base64.py\nx = 1\nEOF').payloads).toEqual([
      { path: 'base64.py', text: 'x = 1' },
    ]);
  });

  it('leaves a heredoc fed to a command unextracted, whatever its stdout goes to', () => {
    expect(read("psql <<'EOF'\nselect * from t where id = '%s'\nEOF")).toEqual({
      incomplete: true,
      payloads: [],
    });
    expect(read('python - <<EOF\nprint(1)\nEOF').payloads).toEqual([]);
    expect(read('python - <<EOF > out.txt\nimport pickle\nEOF').payloads).toEqual([]);
    expect(read('sudo -u root python3 <<EOF > out.txt\nx\nEOF').payloads).toEqual([]);
    expect(read('echo "x" > /dev/null').payloads).toEqual([]);
    expect(read('echo "x" 2>&1').payloads).toEqual([]);
    expect(read('grep "select * from t" file.txt').payloads).toEqual([]);
  });

  it('reads a heredoc marker inside a body as text, not a second heredoc', () => {
    const cmd = 'cat > a.txt <<A\ncat <<B > b.txt\nB\nA\n';
    expect(read(cmd).payloads).toEqual([{ path: 'a.txt', text: 'cat <<B > b.txt\nB' }]);
  });

  it('takes nothing from two heredocs opened on one line, or from a list of writers', () => {
    expect(paths('cat <<A > a.txt; cat <<B > b.py\nbody a\nA\nbody b\nB\n')).toEqual([]);
    expect(paths('cat <<A > a.txt && cat <<B | tee b.py\nbody a\nA\nbody b\nB\n')).toEqual([]);
    expect(paths('cat <<A <<B > a.txt\nbody a\nA\nbody b\nB\n')).toEqual([]);
  });

  it('skips stderr, fd and /dev/null redirects when naming the file', () => {
    expect(paths('cat <<EOF 2>/dev/null > app.py\nx = 1\nEOF')).toEqual(['app.py']);
    expect(paths('cat <<EOF 2>err.log >out.py\nx = 1\nEOF')).toEqual([]);
    expect(paths('cat <<EOF >&2\nx = 1\nEOF')).toEqual([]);
    expect(paths('cat <<EOF > /dev/null\nx = 1\nEOF')).toEqual([]);
    expect(paths('cat <<EOF &> both.py\nx = 1\nEOF')).toEqual(['both.py']);
  });

  it('takes a body written to a name it cannot resolve as code with no path', () => {
    const r = bashWrittenPayloads('cat > "$F" <<EOF\nx = 1\nEOF');
    expect(r.incomplete).toBe(false);
    expect(r.payloads).toHaveLength(1);
    expect(r.payloads[0]?.path).toBeUndefined();
    expect(r.payloads[0]?.text).toBe('x = 1');
    expect(bashWrittenPayloads('cat <<EOF > out/$(date).py\nx\nEOF').payloads[0]?.path).toBe(
      undefined,
    );
  });

  it('reads delimiter forms: escaped, hyphen, dot, and ignores here-strings and quoted markers', () => {
    expect(paths('cat <<\\EOF > a.py\nx\nEOF')).toEqual(['a.py']);
    expect(paths('cat <<MY-END > a.py\nx\nMY-END')).toEqual(['a.py']);
    expect(paths('cat <<END.1 > a.py\nx\nEND.1')).toEqual(['a.py']);
    expect(paths('cat <<<x > f.py')).toEqual([]);
    expect(paths('cat <<<x > f.py\ncat <<EOF > g.py\ny\nEOF')).toEqual([]);
    expect(read(`echo "<<EOF" > a.py`).payloads).toEqual([{ path: 'a.py', text: '<<EOF' }]);
    expect(paths("true '<<EOF' && cat <<EOF > b.py\nz\nEOF")).toEqual([]);
    expect(paths("cat '<<X' <<EOF > b.py\nz\nEOF")).toEqual([]);
  });

  it('is incomplete when the delimiter word does not end at a boundary', () => {
    expect(read("cat <<EOF'bar' > a.txt\nx\nEOF'bar'\n")).toEqual({
      incomplete: true,
      payloads: [],
    });
    expect(read('cat <<EOF\\bar > a.txt\nx\nEOF\n')).toEqual({ incomplete: true, payloads: [] });
    expect(read('cat <<EOF$x > a.txt\nx\nEOF\n')).toEqual({ incomplete: true, payloads: [] });
  });

  it('is not misled by a quoted word that spans lines before the marker', () => {
    const cmd =
      "python3 -c 'import time, runpy; runpy.run_path(\"notes.txt\")' '\n>' | 2>/tmp/\\'a cat <<'EOF' > notes.txt\nimport pickle\nobj = pickle.loads(blob)\nEOF";
    expect(read(cmd)).toEqual({ incomplete: true, payloads: [] });
    expect(read("echo 'a\nb' > f.txt").payloads).toEqual([{ path: 'f.txt', text: 'a\nb' }]);
    expect(read("cat '>\n' <<'EOF' > f.txt\nx\nEOF")).toEqual({ incomplete: true, payloads: [] });
    expect(paths("cat >'foo'bar <<'EOF'\nx\nEOF")).toEqual([]);
    expect(paths("cat >>>foo <<'EOF'\nx\nEOF")).toEqual([]);
  });

  it('leaves an unquoted body with command substitution unextracted, a quoted one extracted', () => {
    expect(paths('cat <<EOF > a.py\nx = $(id)\nEOF')).toEqual([]);
    expect(paths('cat <<EOF > a.py\nx = `id`\nEOF')).toEqual([]);
    expect(paths("cat <<'EOF' > a.py\nx = $(id)\nEOF")).toEqual(['a.py']);
    expect(paths('cat <<\\EOF > a.py\nx = $(id)\nEOF')).toEqual(['a.py']);
  });

  it('is incomplete, with nothing returned, when a heredoc cannot be followed or ends unterminated', () => {
    expect(read('cat <<$D > a.py\nx\n$D')).toEqual({ incomplete: true, payloads: [] });
    expect(read('cat > a.py <<EOF\nx = 1\n')).toEqual({ incomplete: true, payloads: [] });
  });

  it('is incomplete past each cap, and complete just under it', () => {
    const echoed = (n: number) => `echo '${'x'.repeat(n)}' > f.py`;
    expect(read(echoed(1000)).incomplete).toBe(false);
    expect(read(echoed(270_000))).toEqual({ incomplete: true, payloads: [] });
    const marker = (pad: number) => `cat <<A > f.py${' '.repeat(pad)}\nbody\nA\n`;
    expect(read(marker(100)).incomplete).toBe(false);
    expect(read(marker(5000))).toEqual({ incomplete: true, payloads: [] });
  });

  it('takes the text the shell writes: no backslash in echo or an unquoted heredoc body', () => {
    expect(paths("echo 'a\\nb' > f.txt")).toEqual([]);
    expect(paths('echo "a\\nb" > f.txt')).toEqual([]);
    expect(paths("printf 'a\\nb' > f.txt")).toEqual([]);
    expect(paths('cat <<EOF > f.txt\na\\\\b\nEOF')).toEqual([]);
    expect(paths('cat <<EOF > f.txt\na\\x6cb\nEOF')).toEqual([]);
    expect(paths("cat <<'EOF' > f.txt\na\\\\b\nEOF")).toEqual(['f.txt']);
    expect(paths("echo 'a b' > f.txt")).toEqual(['f.txt']);
    expect(paths('echo "a b" > f.txt')).toEqual(['f.txt']);
  });

  it('does not take a body whose stdout a later pipeline stage reads', () => {
    expect(paths("cat <<'EOF' | sh > out.txt\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' | tee f.txt | sh\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' > f.txt | sh\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' > f.txt | tee g.txt | sh\nx\nEOF")).toEqual([]);
    expect(paths("tee f.txt <<'EOF' | sh\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' | tee f.txt\nx\nEOF")).toEqual(['f.txt']);
    expect(paths("cat <<'EOF' | tee -a f.txt > /dev/null\nx\nEOF")).toEqual(['f.txt']);
  });

  it('does not take a heredoc from a stage it cannot positively read as a writer', () => {
    expect(paths("<<'EOF' > f.py\nx\nEOF")).toEqual([]);
    expect(paths("python3 <<'EOF' > f.py\nx\nEOF")).toEqual([]);
    expect(paths("> f.py cat <<'EOF'\nx\nEOF")).toEqual(['f.py']);
  });

  it('does not take a heredoc under an assignment, substitution or subshell', () => {
    expect(paths("X=$(python3 <<'EOF' > out.txt\nx\nEOF\n)")).toEqual([]);
    expect(paths("X=`python3 <<'EOF' > out.txt\nx\nEOF\n`")).toEqual([]);
    expect(paths("(python3 <<'EOF' > out.txt\nx\nEOF\n)")).toEqual([]);
    expect(paths("cat <<'EOF' > $(echo f.py)\nx\nEOF")).toEqual([]);
  });

  it('is incomplete across a line continuation, ANSI-C quoting, or a heredoc with no line end', () => {
    expect(read("python3 - <<'EOF' \\\n> out.txt\nx\nEOF")).toEqual({
      incomplete: true,
      payloads: [],
    });
    expect(bashWrittenPayloads('echo hi \\\n && echo "a" > f.txt').incomplete).toBe(true);
    expect(bashWrittenPayloads("echo $'a\\x27b' > f.txt").incomplete).toBe(true);
    expect(bashWrittenPayloads('cat <<EOF > a.py').incomplete).toBe(true);
  });

  it('does not take a double-quoted echo that runs a substitution', () => {
    expect(paths('echo "$(python3 -c x)" > f.txt')).toEqual([]);
    expect(paths('echo "`id`" > f.txt')).toEqual([]);
    expect(paths("echo '$(id)' > f.txt")).toEqual(['f.txt']);
  });

  it("takes a quoted write only as the whole command, never inside another command's string", () => {
    expect(paths(`sh -c "echo 'X' > f.txt"`)).toEqual([]);
    expect(paths(`bash -c 'echo "X" > f.txt'`)).toEqual([]);
    expect(paths(`python -c "import os; os.system('echo \\"X\\" > f.txt')"`)).toEqual([]);
    expect(paths(`eval "echo 'X' > f.txt"`)).toEqual([]);
    expect(paths(`echo hi # echo "a" > f.txt`)).toEqual([]);
    expect(paths(`cat <<'EOF' > g.txt\necho "a" > f.txt\nEOF`)).toEqual(['g.txt']);
    expect(paths(`echo "a"\n> f.txt`)).toEqual([]);
    expect(paths(`echo "a" > f.txt <<'EOF'\nx\nEOF`)).toEqual([]);
    expect(paths(`cd d; echo "a" > f.txt && echo 'b' >> g.txt`)).toEqual([]);
    expect(paths(`cd d\necho "a" > f.txt`)).toEqual([]);
    expect(paths(`echo "a" > f.txt\necho "b" > g.txt`)).toEqual([]);
    expect(paths(`cd d && echo "a" > f.txt`)).toEqual(['f.txt']);
  });

  it('does not take a heredoc whose command word follows the operator', () => {
    expect(paths("> o.txt <<'EOF' python3\nx\nEOF")).toEqual([]);
    expect(paths("2>/dev/null <<'EOF' python3 > o.txt\nx\nEOF")).toEqual([]);
    expect(paths("<<'EOF' python3 > o.txt\nx\nEOF")).toEqual([]);
    expect(paths("> o.txt <<'EOF'\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' python3 > o.txt\nx\nEOF")).toEqual([]);
    expect(paths("cat <<<'x' python3 > o.txt")).toEqual([]);
    expect(paths("cat <<'EOF' > o.txt 2>&1\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' > o.txt 2>/dev/null\nx\nEOF")).toEqual(['o.txt']);
    expect(paths("cat <<'EOF' >o.txt 1>&2\nx\nEOF")).toEqual([]);
  });

  it('does not take a quoted write that a later redirect or process substitution overrides', () => {
    expect(paths("echo '<code>' > o.txt &> >(python3)")).toEqual([]);
    expect(paths("echo '<code>' > o.txt &>>(python3)")).toEqual([]);
    expect(paths("echo '<code>' > o.txt &> p.txt")).toEqual([]);
    expect(paths("echo '<code>' > o.txt 1>&2")).toEqual([]);
    expect(paths("echo '<code>' >| o.txt")).toEqual([]);
    expect(paths("echo '<code>' > o.txt <<<x")).toEqual([]);
    expect(paths("echo '<code>' > o.txt & ls")).toEqual([]);
    expect(paths("echo '<code>' > o.txt && cd d")).toEqual([]);
  });

  it.each([
    ["{\ncat <<'EOF' | tee f1.txt\nx\nEOF\n} | sh"],
    ["eval $(\ncat <<'EOF' | tee f2.txt\nx\nEOF\n)"],
    ["sh <(\ncat <<'EOF' > f3.txt\nx\nEOF\n)"],
    ["while true; do\ntee f7.txt <<'EOF'\nx\nEOF\nbreak; done | sh"],
    ["(\ncat <<'EOF' > f8.txt\nx\nEOF\n) | bash"],
    ["if true; then\ncat <<'EOF' > f9.txt\nx\nEOF\nfi"],
    ["for i in 1; do\ncat <<'EOF' > f10.txt\nx\nEOF\ndone"],
    ["f() {\ncat <<'EOF' > f11.txt\nx\nEOF\n}\nf"],
    ["cat(){ sh; }\ncat <<'EOF' > f4.txt\nx\nEOF"],
    ['echo(){ sh -c "$1"; }; echo \'<payload>\' > f5.txt'],
    ["alias cat=sh\ncat <<'EOF' > f.txt\nx\nEOF"],
    ["shopt -s expand_aliases; alias echo=sh; echo '<payload>' > f.txt"],
    ["export BASH_ENV=/tmp/e\ncat <<'EOF' > f.txt\nx\nEOF"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nsh f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\n. f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nsource f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nbash f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nchmod +x f6.txt; ./f6.txt"],
    ["cat <<'EOF' > f6.txt\nx\nEOF\nexec f6.txt"],
    ["echo '<payload>' > f6.txt; sh f6.txt"],
    ["true || cat <<'EOF' > f.txt\nx\nEOF"],
    ["cat <<'EOF' > f.txt &\nx\nEOF"],
    ["cat <<'EOF' > f.txt\nx\nEOF\nls"],
    ['cat <<\'EOF\' > ok.txt\nx\nEOF\necho "a" > f$IFS.txt'],
    ['cat <<\'EOF\' > ok.txt\nx\nEOF\necho "a" > `id`.txt'],
    ["cat <<'EOF' > ok.txt\nx\nEOF\necho 'a' > \"$(id).txt\""],
    ["cat <<'EOF' > ok.txt\nx\nEOF\necho 'a' > \"${HOME}/f.txt\""],
    ["cat <<'EOF' > ok.txt\nx\nEOF\necho 'a' > *.txt"],
    ["cat <<'EOF' > ok.txt\nx\nEOF\necho 'a' > o.txt | sh"],
    ["cat <<'EOF' > ok.txt\nx\nEOF\necho 'a' > o.txt & sh"],
    ["echo 'a' > a.txt\ncat <<EOF > b.txt\nv=$(id)\nEOF\n"],
    ["echo 'a' > a.txt\ncat <<EOF > b.txt\nv=`id`\nEOF\n"],
  ])('takes nothing when the command is more than writers and inert statements: %s', (command) => {
    expect(read(command)).toEqual({ incomplete: true, payloads: [] });
  });

  it('keeps regions for one writer behind at most one cd or mkdir -p', () => {
    expect(read("cd d && mkdir -p out\ncat <<'EOF' > out/a.txt\nx\nEOF\n")).toEqual({
      incomplete: true,
      payloads: [],
    });
    expect(read("mkdir -p out sub && cat <<'EOF' > out/a.txt\nx\nEOF\n")).toEqual({
      incomplete: false,
      payloads: [{ path: 'out/a.txt', text: 'x' }],
    });
    expect(read("cd d && cat <<'EOF' > a.txt\nx\nEOF")).toEqual({
      incomplete: false,
      payloads: [{ path: 'a.txt', text: 'x' }],
    });
    expect(paths("cd 'x y' && cat <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
    expect(paths("touch b && cat <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
    expect(paths("cd d && cd e && cat <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' > a.txt\nx\nEOF\ntouch b\n")).toEqual([]);
  });

  it.each([
    ['cat <<EOF > a.txt\nhello\nEO\\\nF\necho RAN\nEOF\n'],
    ['cat <<EOF > b.txt\nv=$\\\n(echo RAN)\nEOF\n'],
    ['cat <<EOF > b.txt\nv=$\\\r\n(echo RAN)\nEOF\n'],
    ["bash -c 'sleep 1; python3 x.py' | cat <<'EOF' > x.py\n<payload>\nEOF\n"],
    ["true | cat <<'EOF' > x.py\n<payload>\nEOF\n"],
    ["true | echo '<payload>' > x.py"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\v#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\f#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\u00a0#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\u2003#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ntrue\r#; python3 c.py\n"],
    ["cat <<'EOF' > c.py\nprint('RAN')\nEOF\ncd café\n"],
  ])('takes nothing from a command bash reads differently: %j', (command) => {
    expect(bashWrittenPayloads(command).payloads).toEqual([]);
  });

  it('still takes a quoted-delimiter body with a backslash-newline', () => {
    expect(paths("cat <<'EOF' > a.txt\nline \\\nmore\nEOF\n")).toEqual(['a.txt']);
    expect(paths("cat <<'EOF' | tee a.txt\nx\nEOF")).toEqual(['a.txt']);
    expect(paths('cat <<EOF > a.txt\nplain\nEOF\ntrue # note\n')).toEqual([]);
  });

  it.each([
    ["tee a.txt a.py <<'EOF'\nx\nEOF"],
    ["tee a.py > a.txt <<'EOF'\nx\nEOF"],
    ["tee a.py <<'EOF' > a.txt\nx\nEOF"],
    ["cat <<'EOF' | tee a.py > a.txt\nx\nEOF"],
    ["cat <<'EOF' > a.py > a.txt\nx\nEOF"],
    ["cat <<'EOF' > a.txt 2>a.py\nx\nEOF"],
    ["cat <<'EOF' > a.py | tee a.txt\nx\nEOF"],
    ["cat f.py - <<'EOF' > a.txt\nx\nEOF"],
    ["cat -n <<'EOF' > a.txt\nx\nEOF"],
    ["tee -p a.txt <<'EOF'\nx\nEOF"],
    ["tee <<'EOF'\nx\nEOF"],
    ["true x <<'EOF' > a.txt\nx\nEOF"],
    ["sponge a.txt <<'EOF'\nx\nEOF"],
  ])('takes no path from a writer with more than one file or unread arguments: %j', (command) => {
    expect(paths(command)).toEqual([]);
  });

  it.each([
    ["tee notes.txt <<'EOF' > /dev/../tmp/e.py\nx\nEOF"],
    ["cat <<'EOF' | tee notes.txt > /dev/../x/e.py\nx\nEOF"],
    ["cat <<'EOF' > /dev/shm/e.py > notes.txt\nx\nEOF"],
    ["cat <<'EOF' > ../e.py\nx\nEOF"],
    ["cat <<'EOF' > a/../e.py\nx\nEOF"],
    ['cat > "notes.txt".py <<\'EOF\'\nx\nEOF'],
    ['tee "notes.txt".py <<\'EOF\'\nx\nEOF'],
    ["cat > 'notes.txt'.py <<'EOF'\nx\nEOF"],
    ["cat <<'EOF' > a.py>b.txt\nx\nEOF"],
    ["echo 'a' > 'notes.txt'#.py"],
    ["echo 'a' > notes.txt#.py"],
  ])('takes no path from a target that is not exactly one word: %j', (command) => {
    expect(paths(command)).toEqual([]);
  });

  it('takes a path it cannot spell plainly with no name, and a comment only before the writer ends', () => {
    expect(bashWrittenPayloads("cat > a.p\\y <<'EOF'\nx\nEOF").incomplete).toBe(true);
    expect(paths("echo 'a' > notes.txt # .py")).toEqual([]);
    expect(paths("cat <<'EOF' > /dev/null\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' | tee n.txt >/dev/stderr\nx\nEOF")).toEqual(['n.txt']);
  });

  it.each([
    ['cat <<EOF > a.txt\nobj = pickle.${x:-loads}(blob)\nEOF'],
    ['cat <<EOF > a.txt\nv=$HOME\nEOF'],
    ['cat <<EOF > a.txt\nv=$((1+2))\nEOF'],
    ['echo "pickle.${x:-loads}(blob)" > a.txt'],
    ['echo "v=$HOME" > a.txt'],
    ['echo "v=\\x" > a.txt'],
    ["printf 'a\\x6cb' > a.txt"],
    ["printf '100%d' > a.txt"],
    ["echo -e 'a\\x6cb' > a.txt"],
    ["echo -n 'a' > a.txt"],
    ["echo -E 'a' > a.txt"],
    ["cat <<'EOF' > a.txt >&2\nx\nEOF"],
    ["cat <<'EOF' > a.txt 1>&2\nx\nEOF"],
    ["cat <<'EOF' > a.txt 2>&1\nx\nEOF"],
    ["cat <<'EOF' <&3 > a.txt\nx\nEOF"],
  ])(
    'takes no payload from text the shell would change, or output sent elsewhere: %j',
    (command) => {
      expect(bashWrittenPayloads(command).payloads).toEqual([]);
    },
  );

  it('takes the literal forms: single-quoted echo and printf, quoted-delimiter bodies', () => {
    expect(paths("echo 'v=$HOME' > a.txt")).toEqual(['a.txt']);
    expect(paths("printf 'v=$HOME' > a.txt")).toEqual(['a.txt']);
    expect(paths("cat <<'EOF' > a.txt\nv=$HOME ${x:-y}\nEOF")).toEqual(['a.txt']);
    expect(paths('cat <<EOF > a.txt\nplain\nEOF')).toEqual(['a.txt']);
  });

  it('counts an empty-body heredoc as a plain writer only when it is one', () => {
    expect(read("cat <<'EOF' > e.txt\nEOF\n")).toEqual({ incomplete: false, payloads: [] });
    expect(read("python3 <<'EOF' > e.txt\nEOF\n")).toEqual({ incomplete: true, payloads: [] });
    expect(read("cat <<'EOF' > e.txt 1>&2\nEOF\n")).toEqual({ incomplete: true, payloads: [] });
    expect(read("cat <<'EOF' > e.txt\nEOF\ncat <<'EOF' > f.txt\nx\nEOF\n")).toEqual({
      incomplete: true,
      payloads: [],
    });
  });

  it.each([
    ["cat > notes.txt>e.py <<'EOF'\nx\nEOF"],
    ["tee notes.txt>e.py <<'EOF'\nx\nEOF"],
    ["cat <<'EOF' | tee notes.txt>e.py\nx\nEOF"],
    ["tee notes.txt&>e.py <<'EOF'\nx\nEOF"],
    ["cat > a.py>b.txt <<'EOF'\nx\nEOF"],
    ["cat <<'EOF' > a.txt>b.py\nx\nEOF"],
    ["cat <<'EOF' > a.py>>b.txt\nx\nEOF"],
    ["cat 2>err.py>b.txt <<'EOF'\nx\nEOF"],
    ["cat >b.txt>c.py <<'EOF'\nx\nEOF"],
    ["echo 'x' > notes.txt>e.py"],
    ["echo 'x' > notes.txt&>e.py"],
    ["echo 'x' > ~/a.py"],
  ])('takes no path when a redirect is glued to a word or the path expands: %j', (command) => {
    expect(bashWrittenPayloads(command).payloads).toEqual([]);
  });

  it('scans a body written under a tilde path with no extension scope', () => {
    const r = bashWrittenPayloads("cat <<'EOF' > ~/a.py\nx\nEOF");
    expect(r.payloads).toHaveLength(1);
    expect(r.payloads[0]?.path).toBeUndefined();
  });

  it('names the tee file from the word tee is given, not a digit of a glued redirect', () => {
    expect(paths("tee 2>/dev/null app.py <<'EOF'\nx\nEOF")).toEqual(['app.py']);
    expect(paths("tee -a 1>/dev/null app.py <<'EOF'\nx\nEOF")).toEqual(['app.py']);
    expect(paths("cat <<'EOF' | tee 2>/dev/null app.py\nx\nEOF")).toEqual(['app.py']);
    expect(paths("tee -a f.py 2>/dev/null <<'EOF'\nx\nEOF")).toEqual(['f.py']);
    expect(paths("tee 2>&1 f.py <<'EOF'\nx\nEOF")).toEqual([]);
    expect(paths("tee 2>err.py f.txt <<'EOF'\nx\nEOF")).toEqual([]);
    expect(paths("tee 3>/dev/null <<'EOF'\nx\nEOF")).toEqual([]);
    expect(paths("tee 'a b.py' <<'EOF'\nx\nEOF")).toEqual(['a b.py']);
  });

  it('takes mkdir only with -p, and words that do not start with a dash', () => {
    expect(paths("mkdir -p d e && cat <<'EOF' > a.txt\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("mkdir d && cat <<'EOF' > a.txt\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("mkdir -m 777 d && cat <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
    expect(paths("mkdir -p -m 777 d && cat <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
    expect(paths("cd -P d && cat <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
    expect(paths("cd - && cat <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
  });

  it.each([
    ['cat <<"A\\$" > notes.txt\nharmless\nA$\npython3 -c "import pickle; pickle.loads(b)"\nA\\$\n'],
    ['cat <<"A\\`" > notes.txt\nharmless\nA`\npython3 -c "x"\nA\\`\n'],
    ["cat <<'A$' > notes.txt\nx\nA$\n"],
    ['cat <<"A$B" > notes.txt\nx\nA$B\n'],
    ['cat <<"A B" > notes.txt\nx\nA B\n'],
  ])('takes nothing when a quoted delimiter is not plain characters: %j', (command) => {
    expect(read(command)).toEqual({ incomplete: true, payloads: [] });
  });

  it('still takes quoted and bare plain delimiters', () => {
    expect(paths('cat <<"A-1.b" > notes.txt\nx\nA-1.b\n')).toEqual(['notes.txt']);
    expect(paths("cat <<'A_1' > notes.txt\nx\nA_1\n")).toEqual(['notes.txt']);
    expect(paths('cat <<\\A > notes.txt\nx\nA\n')).toEqual(['notes.txt']);
  });

  it('reads tee -a only before the file word', () => {
    expect(paths("tee -a f.py <<'EOF'\nx\nEOF")).toEqual(['f.py']);
    expect(paths("tee f.py -a <<'EOF'\nx\nEOF")).toEqual([]);
    expect(paths("tee -a -a f.py <<'EOF'\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' | tee f.py -a\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' | tee -a f.py\nx\nEOF")).toEqual(['f.py']);
  });

  it('still reads a leading redirect before the operator, and a spaced one', () => {
    expect(paths("cat > a.txt <<'EOF'\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("> a.txt cat <<'EOF'\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("cat 2>/dev/null > a.txt <<'EOF'\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("cat <<'EOF' >a.txt\nx\nEOF")).toEqual(['a.txt']);
  });

  it('still takes the one file of a plain cat or tee', () => {
    expect(paths("cat - <<'EOF' > a.txt\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("tee -a a.txt <<'EOF'\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("tee a.txt <<'EOF' >/dev/null\nx\nEOF")).toEqual(['a.txt']);
    expect(paths("true <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
    expect(paths(": <<'EOF' > a.txt\nx\nEOF")).toEqual([]);
    expect(paths("cat <<'EOF' | tee -a a.txt 2>/dev/null\nx\nEOF")).toEqual(['a.txt']);
  });

  it('does not take a writer behind an assignment or wrapper word', () => {
    expect(paths("PATH=/tmp/d cat <<'EOF' > f.txt\nx\nEOF")).toEqual([]);
    expect(paths("BASH_ENV=/tmp/e cat <<'EOF' > f.txt\nx\nEOF")).toEqual([]);
    expect(paths("env cat <<'EOF' > f.txt\nx\nEOF")).toEqual([]);
    expect(paths("/tmp/d/cat <<'EOF' > f.txt\nx\nEOF")).toEqual([]);
  });

  it('stays linear and bounded on hostile whitespace and repetition, for every pattern', () => {
    const inputs = [
      'cat <<EOF >f\n'.repeat(20_000),
      'echo "x'.repeat(40_000),
      `tee${' '.repeat(100_000)}`,
      `cat <<EOF | tee${' '.repeat(100_000)}\nx\nEOF`,
      `cat <<EOF >${' '.repeat(100_000)}\nx\nEOF`,
      `echo${' '.repeat(100_000)}"a" > f`,
      `echo "a"${' '.repeat(100_000)}> f`,
      `echo "a" >${' '.repeat(100_000)}`,
      `echo ${'-a '.repeat(30_000)}"a"`,
      '> '.repeat(50_000),
      `cat <<EOF ${'1'.repeat(100_000)}\nx\nEOF`,
      `cat <<EOF ${'& '.repeat(50_000)}\nx\nEOF`,
      `cat <<EOF ${'|'.repeat(100_000)}\nx\nEOF`,
      `${' '.repeat(100_000)}<<${' '.repeat(100_000)}EOF`,
      `cat <<EOF >f\n${'\t'.repeat(100_000)}x\nEOF`,
      `cat <<A > f.txt ${'1'.repeat(4000)}\nx\nA\n`.repeat(60),
      `cat <<A > f.txt ${'> | '.repeat(1000)}\nx\nA\n`,
      `cat <<A ${'| '.repeat(1900)}> f\nx\nA\n`,
      `cat <<A > f ${'1 '.repeat(1900)}\nx\nA\n`.repeat(60),
      `cat <<A > f ${'&>x '.repeat(900)}\nx\nA\n`.repeat(60),
      `cat <<A ${'>a'.repeat(1900)}\nx\nA\n`.repeat(60),
      `echo '${'x'.repeat(250_000)}' > f.txt`,
      `echo "${'a '.repeat(120_000)}" > f.txt`,
      `echo ${'-a '.repeat(80_000)}'x' > f.txt`,
      `echo 'x' >${' '.repeat(200_000)}f.txt`,
    ];
    for (const input of inputs) {
      const start = performance.now();
      const out = bashWrittenPayloads(input);
      expect(performance.now() - start).toBeLessThan(500);
      expect(out.payloads.length).toBeLessThanOrEqual(1);
    }
  });
});
