# opencode-automode: deferred council items (project review 5)

Items the review 5 council raised that were left for later sessions: hard to close precisely,
non-blocking by CONTRIBUTING.md "Reviewing the rules", or over-asks worth relief. Each was probed
on main 927aa35 unless marked. Fix by asking on what the check cannot read; do not read one more
spelling.

## Possible gaps (allow where a sibling spelling asks)

- Read tool: `decideRead` does not ask for files only sandbox.ts `DEFAULT_SECRET_PATHS` hides
  (`~/.local/share/opencode/auth.json`, `~/.config/git/credentials`, `~/.claude/.credentials.json`);
  cheap fix: ask on `isSecretPath` of the sandbox list too (Opus r1).
- `cd .. && make`, `cd / && make`, `cd .. && go test ./...` allow while `make -C ..` asks (Opus r6;
  same class as `npm --prefix ..`).
- `gh auth token` goes to the model while `gh auth status -t` is a firm ask (Opus r6).
- `gh attestation download` writes a file but is not in `unseenWriter` (sandbox off; Opus r6).
- `gh api -X GET --input f` sends a file as a GET body; `gh api --field=q=@.env` misses the
  credential name (`secretIn` strips one `key=`) (Opus r3, r5).
- `patch -p1 --directory=.claude` allows while `-d .claude` asks (Mythos r6).
- Readers in no list: `shellcheck "$f"`, `shfmt -d "$f"`, eslint/tsc/prettier/yamllint/hadolint/
  markdownlint/tokei with a name built at run time; `dmesg -F "$(…)"`, `gcc -E -x c "./$(…)"`,
  `tree --fromfile`, `tldr --render "$(…)"`, `black --diff`, `rustfmt --emit stdout` (Mythos r3, r4, r6).
- `less "--$x" a`, `bat "--$x" a` in a session with no writes (Mythos r6).
- `clang -gcc-toolchain /tmp/x` (single dash) allows; `--gcc-toolchain` asks (Mythos r3, not reproduced).
- `go run -mod=mod pkg`, `go tool -modfile=x.mod y`, `uv run -p /tmp/x/python`, `cargo run
  --manifest-path /other/Cargo.toml`, `go run -C /other .` (Mythos r3, not reproduced).
- `ss -D AGENTS.md` (dump-to-file not read) (Mythos r4).
- `rm -rf ?*`, `rm -rf **`, `rm -rf [!.]*`, `rm -rf ./?*` allow while `rm -rf *` asks (Mythos r4;
  the project-wipe ask is for the common spelling; README promises only the root/home deny).
- `journalctl --vacuum-time=1s`, `--rotate`, `--flush`, `--setup-keys`; `hostname foo` (need root).
- `go env -w GOFLAGS=-toolexec=x` persists a program for later builds (Mythos r2, r3).
- `fastfetch --command-text`, `bat --pager '…' --paging=always` (README: programs judged by name).
- Committed credentials read from git history behind `--` (`git log -p -- "$f"`): README Known gap.

## Over-asks introduced by review 5 (to the model; relief only if common and small)

`git add "src/$f"`, `git checkout "feature/$n"`, `git diff "origin/$b"`, `git show "HEAD~$n"`,
`git tag -a "v$v" -m …`, `git log "-n$n"`, `git diff HEAD~1 -- "$a" "$b"`; `npm run --silent test --
"$p"`, `npm test "tests/$f"`, `npm run build -w "$w"`, `pnpm --filter "$pkg" test`; `cargo build -p
"$c"`, `--features "$f"`, `cargo test "name_$x"`; `go test "./$d/..."`, `go build "./cmd/$n"`;
`make -j "$n" all`, `make "build-$x"`, `make -kC "build/$d"`; `cmake -DCMAKE_BUILD_TYPE="$t"`;
`gcc -I"$d"`; unquoted `head -n$N a`, `tail -n+$start`, `cut -d: -f$n`, `chown -R $USER:$USER d`;
`n=5; head -n$n a` (name equal to the option letter); `nm -C "$f"` in a glob loop;
`journalctl -fu "$svc"`; `man "git-$x"`; `gh auth status --json hosts`; `ls -- *` beside `-rf`.

## Council notes

- Rounds and scores: see the description of PR #14.
- Most review 5 findings were one class: a word whose meaning bash fixes at run time (an option,
  a subcommand, a name a check reads, several words from one) read by its literal text. Closing it
  per program does not end; the blunt rule is "the check cannot tell what bash makes of it → ask".

## Left open by the round 6 fix (deliberately)

- A one-dash letter followed by a quoted expansion, for programs with no option table, still
  allows (`diff -q"$x" a b`; less, bat, od, strings, tee, touch, mkdir, rm, cat, cut, tail, nl,
  cmp, comm, column, sha256sum, tac, paste, join, fold, truncate, shred, seq). No dangerous letter
  found among these; closing it bluntly costs `head -n"$n" a` (asserted allow in round 5).
- `set -- x -delete; find . -name "$*"` and `find . -name "$(echo "$@")"` allow (one word in bash).
- Round 8 over-ask: a long flag right before `--` makes the end soft, so `wc --lines -- "$f"`,
  `du --summarize -- "$dir"`, `git grep --line-number -- "$p"` go to the model (short clusters of
  known flags do not). Relief: a list of long flags per program.
- Same cause, git: `git restore --staged -- "$f"`, `git rm --cached -- "$f"`, `git grep --cached
  -- "$p"` go to the model (git subcommands outside the revision family read options after a `--`
  that was a value; a long flag before `--` cannot be told from one that takes it).
- Round 8 blunt git close: after a `--` that follows a long option or an unknown cluster, a word
  made only of an expansion goes to the model for every git subcommand: `git log --oneline --
  "$f"`, `git diff --cached -- "$f"`, `git diff --stat -- "$x"`, `git restore --staged -- "$f"`.
  Relief needs git's per-subcommand option parsing (log/diff cut at `--` first; grep,
  format-patch, shortlog and log's `--decorate-refs`/`-L` do not) — read precisely only with tests
  against real git.
- Also from the blunt soft-`--` rule (a long flag before `--`, then `"$f"`): `go test -v -- "$x"`,
  `journalctl --no-pager -- "$x"`, `git log --follow -- "$f"`, `git add --all -- "$f"`,
  `git stash push --keep-index -- "$f"`, `git ls-files --others -- "$f"`, `git status --short --
  "$f"`, `pytest -x -- "$x"`, `git diff --name-only -- "$f"`.
- git's output options are now read past a `--` (round 8): a pathspec literally named
  `--output…` or `-o…` (format-patch/archive) is read as an output and may ask.

## From the closing round (round 10, Mythos notes)

- `nm @opts.txt a.o` reads options from a file (`--plugin=./p.so` loads code) while `nm --plugin`
  goes to the model; same mechanism as the declined `gcc @file`. Fix: an nm word beginning with
  `@` to the model.
- `buildToolProblem` cuts every build tool's options at the first `--`: `ctest -R -- -S x.cmake`,
  `just --dotenv-path -- --shell ./evil recipe` allow (not reproduced; clap/ctest may refuse `--`
  as a value).
- `meson -- "$x"` allows (subs not applied behind `--`), like `tox -- "e$u"`.
- `rustfmt --files-with-diff` is listed as a value option but is a flag (table error only).
- The three `--` readers (`behindDashDash`, `riskyWord`, `listOptions`) judge the word before a
  `--` slightly differently (Opus r10 note): a count, and expansions in that word. No allow
  results; worth unifying if they are ever merged.
