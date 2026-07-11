// `aka completion <shell>` — emit a tab-completion script for the user's shell.
// The CLI is a hand-rolled dispatcher (no commander/yargs), so completion is a
// static script. Both scripts (and cli.ts's USAGE) are generated from the single
// COMMAND_SPECS manifest, so a new command auto-appears in completion — no
// hand-synced list to forget (which is how `completion` first shipped missing from
// its own completion).
import { COMMAND_SPECS, GLOBAL_FLAGS } from '../command-manifest.ts';

const topNames = COMMAND_SPECS.map((s) => s.name);

function zshScript(): string {
  const describe = COMMAND_SPECS.map((s) => `    '${s.name}:${s.summary}'`).join('\n');
  const argArms = COMMAND_SPECS.flatMap((s) =>
    s.args ? [`      ${s.name}) _values '${s.name}' ${s.args.join(' ')} ;;`] : [],
  );
  const fileArms = COMMAND_SPECS.flatMap((s) =>
    s.completesFiles ? [`      ${s.name}) _files ;;`] : [],
  );
  const thirdArms = [...argArms, ...fileArms].join('\n');
  const trailingArms = fileArms.join('\n');
  return `#compdef aka
# This is an aka <TAB>-completion script for zsh. Your shell loads it — you do
# not need to read or edit it. To turn completion on:
#   permanently:   echo 'source <(aka completion zsh)' >> ~/.zshrc   # then open a new terminal
#   this session:  source <(aka completion zsh)
_aka() {
  local -a _aka_cmds
  _aka_cmds=(
${describe}
  )

  if (( CURRENT == 2 )); then
    _describe -t commands 'aka command' _aka_cmds
    return
  fi

  # Flags may follow any command; complete them whenever the current word starts
  # with '-'. Checked BEFORE the positional switch so a command with no arg case
  # (e.g. \`aka stats --\`) still offers them — matching the bash script.
  if [[ $words[CURRENT] == -* ]]; then
    compadd -- ${GLOBAL_FLAGS.join(' ')}
    return
  fi

  if (( CURRENT == 3 )); then
    case $words[2] in
${thirdArms}
    esac
    return
  fi

  case $words[2] in
${trailingArms}
  esac
}

# On a stock zsh where compinit was never run (macOS default, no oh-my-zsh),
# \`compdef\` is undefined and sourcing this would print "command not found: compdef"
# and silently not register. Load the completion system first so it always works.
if ! (( $+functions[compdef] )); then
  autoload -Uz compinit && compinit
fi
compdef _aka aka
`;
}

function bashScript(): string {
  const argArms = COMMAND_SPECS.flatMap((s) =>
    s.args
      ? [`      ${s.name}) COMPREPLY=( $(compgen -W "${s.args.join(' ')}" -- "$cur") ); return ;;`]
      : [],
  ).join('\n');
  return `# This is an aka <TAB>-completion script for bash. Your shell loads it — you
# do not need to read or edit it. To turn completion on:
#   permanently:   echo 'source <(aka completion bash)' >> ~/.bashrc   # then open a new terminal
#   this session:  source <(aka completion bash)
_aka() {
  local cur cmd
  cur="\${COMP_WORDS[COMP_CWORD]}"
  cmd="\${COMP_WORDS[1]}"

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${topNames.join(' ')}" -- "$cur") )
    return
  fi

  # Flags may follow any command — checked before the positional switch so every
  # command offers them (matches the zsh script).
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "${GLOBAL_FLAGS.join(' ')}" -- "$cur") )
    return
  fi

  if [[ $COMP_CWORD -eq 2 ]]; then
    case "$cmd" in
${argArms}
    esac
  fi

  # \`scan\` (and any other unmatched position) falls through with an empty
  # COMPREPLY; \`complete -o default\` then lets readline do proper filename
  # completion — which handles spaces in names and adds a trailing slash for
  # directories, neither of which the earlier hand-rolled file branch did.
}
complete -o default -F _aka aka
`;
}

const COMPLETION_HELP = `Usage: aka completion <shell>          (shell: zsh or bash)

Turns on <TAB> completion for aka: type "aka exc" then press TAB and your
shell fills in "aka exception". This command prints a small script that your
shell loads to make that work — you don't read the script, you load it.

Turn it on for good (run once, then open a new terminal):
  zsh    echo 'source <(aka completion zsh)' >> ~/.zshrc
  bash   echo 'source <(aka completion bash)' >> ~/.bashrc

Just this terminal:
  zsh    source <(aka completion zsh)
  bash   source <(aka completion bash)

Not sure which shell you have? Run:  echo $SHELL
`;

// Pure builder so tests can assert the emitted scripts without touching stdout.
export function completionScript(shell: string): string | undefined {
  if (shell === 'zsh') return zshScript();
  if (shell === 'bash') return bashScript();
  return undefined;
}

// A plain-language nudge, shown only when the script is printed to a terminal (see
// runCompletion). Kept as its own pure function so it can be tested and so the
// wording stays in step with COMPLETION_HELP.
export function completionHint(shell: 'zsh' | 'bash'): string {
  const rc = shell === 'zsh' ? '~/.zshrc' : '~/.bashrc';
  return (
    `\n` +
    `# ─────────────────────────────────────────────────────────────────────\n` +
    `# The lines above are a completion script — they do nothing until your\n` +
    `# shell loads them. To turn on <TAB> completion, run this once, then open\n` +
    `# a new terminal:\n` +
    `#\n` +
    `#     echo 'source <(aka completion ${shell})' >> ${rc}\n`
  );
}

export function runCompletion(argv: string[]): void {
  const shell = argv[0];
  if (shell === undefined || shell === '-h' || shell === '--help') {
    process.stdout.write(COMPLETION_HELP);
    return;
  }
  if (shell !== 'zsh' && shell !== 'bash') {
    process.stderr.write(`aka completion: unsupported shell '${shell}' (try: zsh, bash)\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(completionScript(shell) ?? '');
  // When the script is dumped to an interactive terminal the user is reading it,
  // not loading it — nudge them. Gated on isTTY and written to stderr so it can
  // never contaminate `source <(…)`, `> file`, or `| pipe` (all non-TTY stdout).
  if (process.stdout.isTTY) {
    process.stderr.write(completionHint(shell));
  }
}
