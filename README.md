# opencode-automode

Local auto mode for opencode 2.x permission prompts. Nothing leaves the machine.

> **Experimental.** This decides which commands an AI agent may run without asking you, and
> sandboxes them. It has had several rounds of AI-assisted review but no independent security
> audit. Use it to get fewer prompts, not as a boundary you rely on against a determined
> adversary. See [SECURITY.md](SECURITY.md) for what to report and how.

For each shell tool call:

1. **Rules.** [pi-automode-classifier](https://github.com/deepu105/pi-automode-classifier)'s
   `rules.ts` (v0.4.1, MIT, vendored unchanged) parses the whole command, including `$(...)`,
   `bash -c`, wrappers like `sudo`/`timeout`, redirects and pipelines:
   - **deny**: wipes of `/`, `$HOME` or system dirs, `mkfs`, `dd` to disks, fork bombs
   - **ask**: `sudo`, pushes, `ssh`/`scp`, outbound data, `curl | sh`, credential reads, writes
     outside the project, changes to opencode's config, `AGENTS.md`/`CLAUDE.md`, `.claude/`,
     `.agents/` or this plugin, a write to any path with a `.git` component,
     plus this plugin's additions (`DEFAULT_ASK` in `decide.ts`): tokens on a `curl` line,
     hunting for credential files, git `-c` overrides, `GIT_*`/`SSH_*`/`LD_*` environment,
     `declare`, `printf -v`, brace expansion, namerefs or computed names, git commands that
     write `.git/config` (`git config <key> <value>`, `push -u`, `branch --set-upstream-to`,
     branches started from a remote branch, `clone`, `init`, `submodule add`, ...) because git
     config is read-only inside the sandbox, and anything naming the project's opencode config
     (`opencode.json`, `.opencode/`) or a hook manager's files (`.husky/`, `lefthook.yml`,
     `.pre-commit-config.yaml`)
   - **allow**: read-only commands, builds, tests, local git, edits inside the project
   - **classify**: everything else goes to step 2

   The rules allow by ruling out the spellings they know, and bash, git and the GNU tools accept
   more. `guard.ts` runs around them and works the other way round: it accepts the forms it
   understands and asks about the rest.
   - **Syntax** the rules' parser reads differently from bash asks. The parser has no
     `${...}`, no arithmetic and no brace expansion, and reads their insides as command text,
     so the guard follows both readings and accepts plain forms only: `$'...'` asks; inside
     `${...}` and `$((...))` quotes, a `#` at the start of a word, `<<`, `${x@P}`, `${!x}` and
     subscripts or offsets that are not numbers ask; so do `$[...]`, `>& file`, `>!`, a quoted
     number before a redirect, heredoc delimiters that are not one plain or fully quoted word,
     indented heredoc terminators, backslashes in backticks, unbalanced quotes, and a
     substitution with a parenthesis inside quotes, a comment or a heredoc. A brace expansion
     that makes an option, an absolute path or a remote asks (`curl {-d,@f}`); `src/{a,b}` and
     `--exclude={a,b}` do not. Quoted text shaped like `a[$(...)]` asks, because bash runs it
     wherever it reaches an arithmetic context. A `#` inside a word is text
     (`http://host/#/x`). The same checks run on every string a nested shell is handed
     (`sh -c '...'`, `eval ...`, also behind `sudo`, `timeout`, `xargs`, `find -exec`), and
     such a string asks when it is built from a variable or a substitution.
     `test/differential.test.mts` holds this as a class: it runs each input in real bash and
     fails if a hidden command ran while the decision was an allow.
   - **git**: any global option outside a short list (`-C`, a few harmless `-c` keys,
     `--no-pager`, ...) asks, wherever the word `git` appears, as does any abbreviation of
     `--upload-pack`, `--receive-pack`, `--exec` or `--open-files-in-pager`, `git grep -O`,
     `git submodule foreach`, `git bisect run`, `git rebase -x`/`-i`, and a shortened spelling
     of an option the rules look for (`--har` for `--hard`, `--forc`, `--del`). A commit
     message that spells out a git option asks too.
   - **Per command**, also inside `sh -c`, `sudo`, `xargs`, and with the program named by path
     (`/usr/bin/npm`): printing the environment (`env`, `printenv`, bare `export`/`set`);
     setting `PATH`, `HOME`, `XDG_*`, `GIT_*`, `LD_*` and other variables that change what
     runs; package installs (`npm install/i/ci/add`, bare `yarn`, `pip install`, `uv add`,
     `cargo install`/`add`, `go install`, `go run pkg@version`, `npx`, `npm audit fix`,
     `uv run --with`, options before the subcommand, also behind `env -u X` or
     `timeout -s KILL 60`); a variable from that list set without `NAME=` (`for PATH in`,
     `read`, `printf -v`, `mapfile`, `getopts`, `${NAME:=x}`); options that make a program run
     another (tar `--checkpoint-action`, `-I`, `--to-command`, `-F`; `sort
     --compress-program`; `make --eval`, `SHELL=`; `fd -x`; `rg --pre`; `man -P`); builtins
     that evaluate a value as arithmetic or print through `PS4` (`let`, `declare -i`,
     `test -v` with a subscript or a variable, `set -x`); a glob that matches a file whose
     name starts with `-`; and a credential file named by a glob or braces (`cat .env*`). Your
     own `ask`/`deny`/`classify` rules also match a program named by path.
   - **To the model instead of an allow**: running a file this session wrote, appended to or
     edited in place (`sh x.sh` after `printf ... > x.sh`, `./build.sh` after `echo ... >>
     build.sh` or `sed -i`; the model is shown the start of the file). That covers a shell or
     an interpreter given the file, the file run by its path, `awk -f`, `sed -f`, `make -f`,
     `go run` and `pytest` when they name it. It stops there: a bare `make`, `npm test` or a
     program the session compiled runs the project's code by design, and the model does not
     see it first. Also to the model: a `sed` script with more than substitutions, prints and
     deletes (sed can run commands and write files), an `awk` program with `system`,
     `getline` or a pipe, a file to read that is named at run time (`cat "$f"`), and other
     variables set for a command (a variable set on a line of its own stays in the shell and
     is not asked about).
2. **Kev.** Kev-0.8B on llama.cpp's `llama-server` (`/v1/systemone`) scores "is this command
   risky?". Below `askAbove` (0.2) it runs; otherwise it asks. Down, slow (> `timeoutMs`),
   garbled or out-of-range (not between 0 and 1) answers ask. The plugin never turns an error
   into an allow. The server listens on a unix socket in your runtime directory
   (`$XDG_RUNTIME_DIR/opencode-automode/kev.sock`), which sandboxed commands can neither see
   nor write. Do not move it to a TCP port: while the service is down, any local process, a
   sandboxed one included, can bind the port and answer "not risky".
3. **Sandbox.** Every auto-allowed command runs with its shell swapped for `sandbox/bin/<shell>`,
   a link to `sandbox/lockwrite`, which starts the real shell with the same arguments inside a
   private user + mount + PID namespace (no root needed), then under Landlock:
   - **Writes** only beneath the project's checkouts, `allowedPaths`, temp dirs,
     `sandboxWritable`, `/dev/null`, `/dev/zero`, `/dev/full` and a private `/dev/shm`.
     Everything else is mounted read-only as well, so `chmod`, `touch -d` and `setxattr` fail
     there too. Terminals (`/dev/tty`, `/dev/ptmx`, `/dev/pts`) are not writable and no device
     accepts an ioctl. **No build cache is writable by default**: `~/.cargo/registry`, the pnpm
     store, `~/.m2`, Go's build cache and the like hold code that later builds run outside the
     sandbox. A build that must write a shared cache fails with "Read-only file system"; list
     the directory in `sandboxWritable` if you accept that, or run the fetch step yourself.
   - **Git directories** found under the project, `allowedPaths` and temp dirs (main, linked
     worktrees, submodules, bare repos; at any depth, `node_modules` included) are read-only
     all the way down, mounts beneath them included, as are `.git` pointer files, every
     repository's `core.hooksPath` (a relative one, global or not, in every worktree that
     leads to the repository), files that `.git/config` includes (as deep as git follows
     them), the known hook-manager files (`.husky/`, `lefthook.yml` and its variants,
     `.pre-commit-config.yaml`, `.overcommit.yml`) and opencode's project files
     (`opencode.json[c]`, `.opencode/`, `.claude/`, `.agents/`, `AGENTS.md`, `CLAUDE.md`, in
     the session directory and each writable parent). The plugin creates an empty `.opencode/` in the
     session directory (git does not show empty directories) so that it can be made read-only
     rather than appear later with a plugin in it. Every directory between a writable root and
     a protected or hidden path is pinned, so no parent can be renamed and rebuilt. A mount
     holds a directory in place, not a symbolic link: when a link lies on the way to a
     protected path, or a `.git` is itself a link, the command asks. A tool call made only of
     plain git commands in plain words (`add`, `commit`, `checkout`, `rebase`, `fetch`,
     `push`, ..., no variables, `--output` or `--exec`; output may go to `/dev/null` or
     `2>&1`, and a commit message may come from `"$(cat <<'EOF' ... EOF)"`) may write inside
     git directories, except hooks, config and `commondir`, and cannot rename them.
   - **Hidden**: your whole runtime directory (systemd user manager, D-Bus session bus,
     gpg-agent, other tools' sockets), the system D-Bus, Docker, containerd, podman, libvirt,
     LXD and X11 socket directories, any other socket under `/run` or the temp dirs that you
     can connect to (at any depth), and credential locations: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
     `~/.netrc`, `~/.git-credentials`, `~/.config/git/credentials`, `~/.npmrc`, `~/.config/gh`,
     `~/.config/glab-cli`, `~/.config/op`, `~/.config/gcloud`, keyrings, shell histories
     (bash, zsh, fish, atuin), browser profiles, `~/.gem/credentials`, composer's and
     containers' `auth.json`, Kerberos ticket caches, `~/.m2/settings.xml`, opencode's config, data and state directories (the state holds the
     local server's password), this plugin's state directory (the decision log), following
     `XDG_*_HOME`, plus `sandboxHidePaths`. On top of that list, every entry of `$HOME`, of its
     dot-directories and of `~/.config` and `~/.local/share` that the rules would ask about
     reading is hidden, and so are such files at any depth in the project and `allowedPaths`,
     `node_modules` included (`.env`, `*.pem`, `id_rsa`, `credentials.json`, ...;
     `.env.example` stays), together with what a symbolic link of such a name points to. A
     hidden file reads as empty and cannot be written; `sandboxShowPaths` brings one back (a
     test fixture called `server.key`, say). **Environment**: a
     variable passes only if its name is a well-known harmless one (`PATH`, `HOME`, `LANG`,
     toolchain directories, ...) or its value plainly is no secret (short, a number, a list of
     paths), and never if its name looks like a credential (`*KEY*`, `*TOKEN*`, `*SECRET*`,
     `*PASS*`, `*PWD*`, `*AUTH*`, `*DSN*`, `*JWT*`, `*WEBHOOK*`, `AWS_*`,
     `GITHUB_*`, `DISPLAY`, `XAUTHORITY`, ...). `lockwrite` drops everything not on that list
     itself, and the dropped names are logged. Private keys in `~/.ssh` are never visible. The
     ssh agent (wherever its socket lives), `known_hosts` and `config` are visible only to a
     tool call that is a single plain `git fetch/pull/push/ls-remote` at the top of one of the
     project's own checkouts (same git directory as at session start, to a remote it had then
     with unchanged URLs, the one git itself would pick when none is named, options from a
     short list, only harmless keys in the repository's config, and no hook that the command
     would run), or a single `ssh`/`scp` command. After `cd`, the command must be joined by
     `&&` and the directory must exist; a quoted `~` is not your home directory.
   - **Nothing outlives the tool call.** The shell runs under the PID namespace's init, which
     exits with it; the kernel then kills whatever the command left in the background (a dev
     server started with `&` included). Processes outside the sandbox cannot be signalled, and
     are not listed in `/proc` where the kernel lets the sandbox mount its own (it does not in
     some containers). On Linux 6.12+ abstract sockets are out of reach too. A restricted
     process cannot mount, unmount or ptrace, so none of this can be undone from inside.

   The command text is never changed, so opencode's own rules and prompts see the real
   command. Commands you approve in a prompt run unsandboxed, exactly as shown. If an allowed
   command cannot be sandboxed (unsupported shell, the sandbox self-test failed at startup, a
   protection cannot be put in place, such as a `core.hooksPath` behind a symlink or a `.git`
   that is one, or the scan of the writable directories hit its limit), it asks instead. So
   does an allowed command that could only fail in the sandbox: git writing `.git` from a
   call that is not made only of plain git commands (`npm test && git commit`), git signing
   commits, git needing the ssh agent without getting it, git logging in through a credential
   helper. opencode runs the tool calls of one message at the same time and does not say
   which shell belongs to which call, so a shell is sandboxed only when every identical
   command waiting for one is an allow. If two identical commands issued together get
   different verdicts, both ask, and the one that would have been allowed may still run
   sandboxed when you approve it: the one case where an approved command is not run as is.

The plugin records the project's git layout at session start, nested repositories and pointer
files included, and checks it before every decision. If it changes in a way git never does
itself (a `.git` replaced or moved, a pointer file rewritten, `commondir` or `config.worktree`
planted, a repository, a `.git` symbolic link, a linked worktree or one of opencode's project
files appearing where there was none, at any depth, `node_modules` included), auto-allow
pauses. The prompt and opencode's log say what was found and where. Deleting a nested
repository does not pause. New repositories and worktrees are expected only from a `git init`,
`clone`, `worktree add` or `submodule` command that the plugin asked you about and you
approved, in the place that command named, from your approval until the command has finished.
A new worktree joins the project on the same terms. To
resume after you have looked, run `touch ~/.local/state/opencode-automode/resume` in your own
terminal; a sandboxed command cannot. `lockwrite` is written in Rust with one dependency, the `libc` crate, pinned by
`Cargo.lock` and built with `--locked`. The plugin's own git calls run with fsmonitor, hooks,
pagers and askpass programs disabled, and a git answer it cannot read in full (an error, a
timeout, too much output) counts as "ask", never as "nothing configured".

**The edit tool.** opencode allows edits by default. The plugin makes an edit ask when it is
outside the project, or touches the plugin, opencode's config (global or project-level), a
file inside any git directory, a `core.hooksPath` directory, a file git config includes, or a
hook manager's files. For `read` it asks for credential files. It never turns an ask into an
allow.

**Scheduled checks.** opencode schedules can run an `if`/`until` shell check repeatedly; opencode
asks once, when the schedule is created, and then runs the check without any sandbox and with
your whole environment. The plugin judges that approval like any command, whoever created the
schedule, and at most lets it ask, never auto-allows.

**Invalid settings.** If `automode.json` (or the plugin's options) cannot be parsed, holds
`null`, has a value of the wrong type, a setting the plugin does not know, a relative path, or
an `allowedPaths`/`sandboxWritable` entry that is `/`, a top-level directory or your home,
nothing is auto-allowed until you fix it: every command that would have run asks, and the prompt says what is wrong. Falling back to
defaults would silently drop `enabled: false` and your own ask and deny rules.

## Settings

`~/.config/opencode/automode.json` (see `automode.example.json`):

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Off: the plugin changes nothing and opencode's own rules apply. |
| `useClassifier` | `true` | Off: what the rules leave open asks instead of going to Kev. |
| `classifier` | the unix socket above, `askAbove` 0.2, `timeoutMs` 5000 | Kev server (`endpoint`: `unix:/path` or an http URL), threshold (above 0, at most 1) and reply timeout. |
| `rules` | empty | Your own `allow`/`ask`/`deny`/`classify` patterns: a glob over one simple command (`*` any text, trailing ` *` optional) or `re:` + regex. Rules in the plugin's options are added to the file's. |
| `allowedPaths` | none | Extra directories counted as the project (writable, writes there allowed). Absolute or `~/...`. |
| `sshHosts` | none | `ssh` to these targets runs when it is the whole tool call, in plain words, and the remote command only uses read-only programs with options from a per-program allowlist (`cat`, `df`, `journalctl`, `systemctl status`, `ip addr`, ...), with no variables, substitutions or redirects except to `/dev/null` (no recursive `grep`, `rg` only to list files, no `printf -v` or `test -v`: they print or run more than the words say), and ssh itself only uses harmless options (`-q`, `-T`, `-p`, `-l`, `-o BatchMode/ConnectTimeout/...`). A target matches as listed: `lab` covers `ssh lab ...` only; list `admin@lab` to allow that user. |
| `sshReadOnlySudo` | `false` | On `sshHosts`: also allow `sudo [-n] <read-only command>`. |
| `allowFeatureBranchPush` | `false` | `git push` runs when it is the whole tool call, in plain words, from the top of one of the project's checkouts. The plugin asks git itself what the push would do (`git push --dry-run --porcelain`, hooks off) and allows it when every URL git would connect to belongs to a remote the session started with, unchanged since (all of its URLs), and every ref goes from a branch to a non-protected branch (not `main`/`master`/`release*`/`develop`/... nor the default branch the remote reports) without force or delete. So git's own precedence decides (`branch.*.pushRemote`, `remote.pushDefault`, `remote.*.push`, `push.default`), in any config scope; a push that would only fail (no upstream) asks. The repository's own config must hold only keys from a list of harmless ones (no `pushurl`, `mirror`, `insteadOf`, `sshCommand`, `askPass`, hooks, helpers, ...; `push.followTags` and `remote.*.mirror` ask in any scope), and no `pre-push` hook may exist. Force, deletes, tags and `--no-verify` ask. The dry run costs one more round trip to the remote. |
| `sandbox` | `true` | Off: auto-allowed commands run unsandboxed. Not recommended. |
| `sandboxWritable` | none | More directories auto-allowed commands may write to, for example a build cache. What lands there may run outside the sandbox later. |
| `sandboxKeepSockets` | none | Sockets to leave visible (e.g. your ssh agent for all commands). |
| `sandboxShowPaths` | none | Credential locations to leave visible. |
| `sandboxHidePaths` | none | More files or directories to hide from sandboxed commands. |
| `sandboxKeepEnv` | none | Environment variables to pass through even though their name or value looks like a credential. |
| `log` | `true` | Log every decision, with the full command, to `~/.local/state/opencode-automode/decisions.jsonl` (mode 0600 in a 0700 directory, hidden from sandboxed commands). |

"Always allow" in an opencode prompt is mirrored per project into
`~/.local/state/opencode-automode/always.json`, only for plain word patterns on a short allowlist
of common build, test and read commands (`git status/commit/...` but not `git push`, `git config`
or `git rebase`, `cargo build/test`, `npm run`, `pytest`, `ls`, `cat`, `grep`, project scripts
`./x`, ...). Whatever they run still runs sandboxed. Like a prompt's session choice, it never overrides a firm ask (root, credential
reads, downloaded code, your own ask rules). For `edit` and `read` the plugin only tightens.
opencode `deny` rules never reach it, so they always win.

## Install

Linux x86_64, kernel 6.10 or later (Landlock ABI 5; 6.12+ adds abstract-socket and signal
scoping) with unprivileged user namespaces, Node 22.18+, a Rust toolchain (`cargo`), and systemd user services. On
an older kernel `lockwrite` refuses to run and nothing is auto-allowed.

```sh
git clone https://github.com/vpsman/opencode-automode ~/.local/share/opencode-automode/plugin
cd ~/.local/share/opencode-automode/plugin
git checkout <commit-or-tag>      # pin what you reviewed; `git pull` later is then your decision
npm ci --ignore-scripts           # for type-checking and the tests; see below
npm run build:sandbox             # builds sandbox/lockwrite (Rust, sandbox/lockwrite-rs) and runs its self-test
scripts/fetch.sh                  # llama.cpp b12283 + Kev-0.8B, SHA-256 checked
cp systemd/opencode-automode-kev.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now opencode-automode-kev
```

Then add the plugin folder's absolute path to `"plugins"` in `~/.config/opencode/opencode.jsonc`.
`index.ts` imports `Plugin.define` from `@opencode/plugin` as a value. Inside opencode (2.2.7)
that import is served by the host's own bundled copy, and the copy in `node_modules` is not
loaded; `npm ci` is what the type check and the tests use. The systemd unit runs `llama-server`
with no network, no view of your home except its own directory, none of your runtime
directory except its own socket directory (so no session bus), and a system-call filter, since
it parses text the agent chooses. `fetch.sh` re-checks the model file's SHA-256 on every run.
`fetch.sh` downloads llama.cpp (MIT) from its GitHub releases and the Kev model from Hugging Face
(`ggml-org/Kev-0.8B-GGUF`); check the model card for the model's licence.
Everything lives under `~/.local/share/opencode-automode` (override with `OPENCODE_AUTOMODE_HOME`
for `fetch.sh`, and edit the service to match).

## Tests

```sh
npm run build:sandbox && npm test && npm run typecheck
```

`npm test` runs `test/run.mjs`, which gives the tests a throwaway `$HOME`, XDG directories,
runtime directory and git config under `~/.cache/opencode-automode-test` (it cannot be in
`/tmp`, which the rules treat as project space) and removes it afterwards. No model is needed:
tests that involve one start a local stub server.

- `test/differential.test.mts`: the desync class. Every input holds a marker command the rules
  ask about; each runs in real bash inside the sandbox wrapper, and the test fails if the
  marker ran while the decision was an allow. Inputs: `test/desync-inputs.txt` (both review
  rounds and their variants) and 2,500 from a seeded generator (`DESYNC_FUZZ=100000` for more,
  `DESYNC_SEED` for other ones). bash only: zsh is not run.
- `test/guard.test.mts`: the syntax check, the strict tokenizer, git option parsing, globs.
- `test/decide.test.mts`: the decision rules. Each assertion says whether the rules asked or
  merely left the command to the (absent) model.
- `test/sandbox.test.mts`: commands through the real wrapper, including the git-write mode.
  A "cannot" test also checks that the command ran.
- `test/plugin.test.mts`: `index.ts` behind a stand-in for opencode's hooks: queueing, shell
  wrapping, "allowed but not wrapped asks", schedules, the "Always allow" mirror, environment
  scrubbing, settings, model errors.
- `test/kev.test.mts`, `test/bench.test.mts`: the model client and the bench runner.

## Bench

```sh
node bench/run.mjs --tag kev-0.8b --suites-dir <dir-of-jsonl-suites>
node bench/score.mjs kev-0.8b
```

`run.mjs` drives `decideShell()`, the plugin's own code path, against the live server and
writes to `~/.cache/opencode-automode/bench/<tag>/`. Like the plugin it uses one fixed session
project and the production reply timeout (`--timeout` changes it), so a reply that would time
out in use is an ask in the bench. The model never decides during a run, so `score.mjs` can
sweep `askAbove` afterwards.

The figures below were measured on 2026-11-11, before the review fixes that added the guard
layer, made caches read-only and shortened the bench timeout from 60 s to the production 5 s.
They have not been re-measured; expect more asks.

Results on 2026-11-11 (6 vCPU AMD Zen 5, no GPU): with Kev-0.8B at 0.2, 32 of 765 risky commands in
Pi's labelled sets ran (1 by the model; the rest are rule allows of read-only recon and `/tmp`
writes), 55% of safe ones asked (mostly cloud CLIs), and 86% of ~5,950 past Claude commands ran
without a prompt. Kev-4B was no more accurate, 4–5× slower and timed out on long commands.
Neither model could tell whether the user asked for an action (tested on 87 rows with the user's
message), which is why pushes and ssh use deterministic rules instead.

## Known gaps

- **Network and reads.** The sandbox confines writes and local IPC, not reads of files that are
  not hidden, nor the network. An auto-allowed command can connect to any host or local TCP
  port; local services that accept unauthenticated requests are reachable. Outbound data is an
  ask in the rules, not enforced by the sandbox.
- **Project files that run later.** A sandboxed command can edit `Makefile`, `package.json`
  scripts, `build.rs`, `conftest.py`, CI files and any other project file that you, an approved
  command or a git hook run later outside the sandbox. Hook managers are in this class: the
  known files are read-only (`.husky/`, lefthook, pre-commit, overcommit), but only where they
  already exist, and a hook that calls `npm run lint` or a script in the repository runs
  whatever that has become. Read the diff before you run or commit.
- **Credentials are found by name.** A secret in a file the rules do not recognise is
  readable, and so is `.git/config` with a token in a remote URL. `cat "$(printf .env)"` is
  not an ask by rule: it goes to the model, and the sandbox hides the file. Credential files in
  the temp directories are not searched for, nor are sockets elsewhere under `$HOME`.
- **The scan has a budget.** Before every allowed command the writable directories are walked
  in full: the project, `allowedPaths` and the temp directories (about 0.2 s for 176,000
  entries in `/tmp` on the test machine). Past 400,000 entries or 1.5 s per directory, or with
  more than 5,000 credential files, the command asks and the prompt says which limit was hit.
  A directory of yours that cannot be listed asks too.
- **Code bash evaluates from data.** bash evaluates a variable's value again in every
  arithmetic context (`$((x))`, `[[ $x -eq 1 ]]`, subscripts, `${s:x}`), so a value like
  `a[$(cmd)]` runs. The guard asks about the builtins and forms listed above and about such
  text when it is written in the command; a value that comes from a file, the environment or
  a program's output is not seen.
- **Programs are judged by name.** Apart from the options listed above (git, tar, sort, make,
  fd, rg, man, sed, awk), an allowed program is not checked for options that make it run
  another program or read a script. Whatever it starts runs inside the sandbox.
- **Builds and tests run the session's code.** `make`, `npm test`, `cargo build` and a program
  the session compiled run what the session wrote, without the model seeing it first.
- **zsh.** The parser checks are tested against bash. zsh's `>!` asks; its other extensions
  (glob qualifiers, `=cmd`, `${(e)x}`) were only read, not run.
- **opencode's project config.** `opencode.json[c]` in the session directory cannot be made
  read-only before it exists. A sandboxed command that creates one is detected at the next
  decision (auto-allow pauses and the prompt names the file), but opencode may have loaded it
  by then. If you do not use project-level config, set `OPENCODE_DISABLE_PROJECT_CONFIG=1`.
- **Planted git files in a git-only call.** A tool call made only of git commands may write
  inside `.git`, so code it runs (an existing hook or filter) can create `commondir`,
  `config.worktree` or a `worktrees/` entry where none existed. The plugin detects each at the
  next decision, pauses and names it, and never treats the new worktree as part of the
  project; your own git commands in that repository in between would read them.
- **ssh.** A single `git fetch/pull/push/ls-remote` or `ssh`/`scp` call sees your ssh agent, so
  it can authenticate wherever your keys open, including this machine if it runs sshd. The
  rules only auto-allow `ssh` to `sshHosts`; keep that list short.
- **`/tmp` is shared.** It stays writable and shared with other processes, because agents and
  opencode's own tools pass files through it. A repository there has its existing hooks and
  config made read-only; what cannot be protected in it (a missing include, a link) is left,
  where the same thing in the project would make the command ask.
- **A `.git` that is a symbolic link** (Android `repo` checkouts) cannot be made read-only, so
  in such a project every command that would be allowed asks.
- **Late arrivals.** Sockets, credential files and git repositories created after a command
  starts are not covered for that command (hence `git clone` and `git init` ask).
- **Schedules.** After approval, a schedule's checks run outside the sandbox with your whole
  environment (opencode starts them directly), so approve schedules with care.
- **Background work and terminals.** Nothing a sandboxed command starts survives it, and
  programs that need a terminal or a pty (`script`, `tmux`, `ssh -t`) fail inside the sandbox.
  Start long-running servers yourself, or approve the command.
- **Linux 6.10 and 6.11.** Abstract unix sockets (X11's among them) are only out of reach from
  6.12 on.
- **Environment.** Variables are passed by name and by the look of their value; a secret that
  is short (12 characters or fewer) under a harmless-looking name still reaches sandboxed
  commands. `sandboxKeepEnv` is the reverse.
- **The model** reads a window of the command, not all of it; the rules read all of it.
- **What you approve** in a prompt is not sandboxed.
