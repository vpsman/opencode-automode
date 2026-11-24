# opencode-automode: deferred council items (project reviews 5 and 6)

Items the review 5 council raised that were left for later sessions: hard to close precisely,
non-blocking by CONTRIBUTING.md "Reviewing the rules", or over-asks worth relief. Each was probed
on main 927aa35 unless marked. Fix by asking on what the check cannot read; do not read one more
spelling.

## Possible gaps (allow where a sibling spelling asks)

Review 6 (rounds 1 to 11, see the description of its pull request) probed every item below.

Closed by review 6:

- Read tool and the sandbox's hidden credentials: `SECRET_PATHS` moved to rules.ts and asked on
  for every read (Read tool and shell).
- `cd .. && make`, `cd / && make`, `cd .. && go test ./...`: a build tool run outside the project
  goes to the decider, in a subshell, a background job or a command substitution too.
- `gh auth token` (and `gh auth git-credential`, `git credential*`, `gh config ... token`): firm asks.
- `gh attestation download`: in `unseenWriter`.
- `gh api -X GET --input f`, `--field=q=@.env`: go to the decider; `key=@file` read by the
  credential check.
- `patch --directory=.claude`, `-d.claude`, through a link, built at run time: read as write places.
- Readers in no list (`shellcheck "$f"`, `black --diff "$f"`, `dmesg -F "$(...)"`, `tldr --render`,
  ...): a file named at run time goes to the model for every program allowed by name.
- `ss -D AGENTS.md`, `fastfetch --gen-config`: ask.
- `rm -rf ?*`, `**`, `[!.]*`, `[[:alpha:]]*`, `./?*`: the project-wipe ask (deny beside home).
- `go env -w GOFLAGS=...`: asks; `go run -mod=mod <remote>` asks.
- `go run -C /other .`, `cargo run --manifest-path /other/Cargo.toml`, `uv run -p ../x/python`:
  a place outside the project named by a dev tool or package manager goes to the decider.

Still open:

- `journalctl --vacuum-time=1s`, `--rotate`, `--flush`, `--setup-keys`; `hostname foo`; `ss -K`
  (need root).
- `clang -gcc-toolchain /tmp/x`, `uv run -p /tmp/x/python`: temp dirs count as the project's (a
  file the session wrote there is held by the write record).
- `fastfetch --command-text`, `bat --pager '...' --paging=always` (README: programs judged by name).
- Committed credentials read from git history behind `--` (`git log -p -- "$f"`): README Known gap.

## From review 6 (left open, or new)

- **Next step, agreed with the maintainer:** flip build, test, lint and format tools and package
  managers to an allowlist (as `unreadSpelling` does for find, tar and rsync): auto-allow only a
  call whose every word is a flag from a short per-tool table or a plain relative path in the
  project (no `..`, link, `$`, quote, bracket or `=` value beyond a short list), run in the
  project; everything else to the model. Rounds 2 to 11 of review 6 found only new spellings of
  places hidden in these tools' values (attached letters, comma lists, `=` values, structured
  JSON/list values, links before `..`); reading more spellings does not converge. Measure with the
  bench differential before and after, then delete `projectToolPlaces`' value reader.
- git after a `cd` out of the project (`cd ../other && git commit -am x`, `cd .. && git status`)
  allows, while `git -C ../other ...` goes to the decider (Opus r9; with the sandbox on the other
  `.git` is read-only).
- `findmnt -F "$f"` (journal-format files only), `NODE_COMPILE_CACHE` set in a session's
  `event.env` but not in the plugin's environment, `pacman -Fy` (Neon r1, non-blocking).
- `prettier --write "{AGENTS,README}.md"`: prettier's own brace glob (Opus r10, a reformat only).
- Over-asks introduced by review 6 (to the model): `npm pack ..`; `gcc -I/usr/include/x`,
  `gcc -Wl,-rpath,/usr/lib`, `cmake -DCMAKE_INSTALL_PREFIX=/usr/local` (places outside the
  project); `markdownlint AGENTS.md`, `prettier --check AGENTS.md`; `cd /tmp && make`; `column -t
  "$f"`; `cmake -B "build-$t"`; `uv run pytest "tests/$f"`, `pytest -k "$k"`; `uv run --env-file
  .env python app.py` (credential ask); a jest config with a regex escape; `cd .. && python -m
  pytest`; `mkdir -p sub; x=$(cd sub && pwd)`.

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
