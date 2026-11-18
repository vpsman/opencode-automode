# Contributing

Contributions of any size are welcome: bug reports, rule fixes, new benchmark rows, docs,
support for other platforms. No CLA, no sign-off. By opening a pull request you agree that your
contribution is licensed under this project's MIT licence.

## Reporting a security problem

If you find a way to get a command auto-allowed that should have asked, to write outside the
sandbox, or to make the plugin fail open, please report it privately through GitHub's
**Security → Report a vulnerability** on this repository rather than in a public issue.
Include the command and, if you can, the line from `~/.local/state/opencode-automode/decisions.jsonl`.

Anything else, including false prompts ("this harmless command keeps asking"), is a normal issue.

## Making changes

Open an issue first only for large or design-level changes; otherwise just send the pull request.

```sh
npm ci --ignore-scripts
npm run typecheck
npm run build:sandbox
npm test                 # uses a throwaway $HOME; needs no model
```

`npm test` runs the test files in parallel: `AUTOMODE_TEST_JOBS` of them at a time (default
half the processors, at most 8), each in a process of its own with its own throwaway home and
temp directory. Each file's output is printed whole when it is over; the counts for the whole
suite are the block after the line `── all N files, J at a time ──`. `AUTOMODE_TEST_JOBS=1`
runs them one after another. Options such as `--test-name-pattern=...` go to every file's run.
`TMPDIR` must be on the same file system as the test home (`~/.cache/automode-tests`, or
`$AUTOMODE_TEST_BASE`); otherwise some of the `test/c-*.test.mts` tests fail with `EXDEV`
(a rename across file systems).

A few things keep the plugin trustworthy, so please keep them true:

- **Fail closed.** Errors, timeouts, missing files and anything unexpected must end in "ask",
  never "allow". Where code grants trust (an allow, the ssh agent, a writable `.git`, a
  read-only verdict for a remote command), it accepts the exact forms it understands and asks
  about the rest; it does not list the spellings known to be dangerous.
- **Only the plugin's own decisions are sandboxed and auto-allowed.** What a user approves in a
  prompt runs exactly as shown.
- **`rules.ts` is this project's own**, derived from
  [pi-automode-classifier](https://github.com/deepu105/pi-automode-classifier) v0.4.1 (commit
  e61ea96). A bug in the shell rules is fixed in `rules.ts`, with a case in
  `test/rules.test.mts` that calls `bashVerdict()` on its own and fails without the fix. The
  checks around it (`guard.ts`, `canon.ts`, `decide.ts`) stay as a second layer: removing one
  that a fixed rule makes redundant is a change of its own, with its own evidence. Upstream
  releases are read by hand against e61ea96, not copied over the file. Rules specific to this
  plugin go in `decide.ts` (`DEFAULT_ASK`, the ssh and push matchers).
- **Changes to rules, thresholds or the model come with numbers.** Run the bench before and
  after and put both in the pull request:

  ```sh
  node bench/run.mjs --tag before --suites-dir <suites>
  node bench/score.mjs before
  ```

  Pi's labelled suites live in its repository under `bench/suites`. Don't commit command logs
  from your own sessions: they contain paths, hostnames and sometimes secrets.

Small, focused pull requests are easiest to review. Tests and benchmark rows that show a bug
are as welcome as the fix.
