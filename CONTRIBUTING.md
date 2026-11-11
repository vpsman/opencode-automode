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
npm install --ignore-scripts
npm run typecheck
npm run build:sandbox
```

A few things keep the plugin trustworthy, so please keep them true:

- **Fail closed.** Errors, timeouts, missing files and anything unexpected must end in "ask",
  never "allow".
- **Only the plugin's own decisions are sandboxed and auto-allowed.** What a user approves in a
  prompt runs exactly as shown.
- **`rules.ts` is vendored unchanged** from
  [pi-automode-classifier](https://github.com/deepu105/pi-automode-classifier). Fixes to the
  shell rules belong upstream; once released, re-vendor the file. Rules specific to this
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
