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
     outside the project, changes to opencode's config, `AGENTS.md`/`CLAUDE.md` or this plugin,
     plus this plugin's additions (`DEFAULT_ASK` in `decide.ts`): `printenv`, tokens on a
     `curl` line, hunting for credential files, package installs, git `-c` overrides,
     `--upload-pack`/`--receive-pack`/`--exec`, `GIT_*`/`SSH_*`/`LD_*` environment set by
     assignment, `export`, `declare`, `printf -v`, brace expansion, namerefs or computed names,
     and git commands that write `.git/config` (`git config <key>
     <value>`, `push -u`, `branch --set-upstream-to`, branches started from a remote branch,
     `clone`, `init`, `submodule add`, ...) because git config is read-only inside the sandbox
   - **allow**: read-only commands, builds, tests, local git, edits inside the project
   - **classify**: everything else goes to step 2
2. **Kev.** Kev-0.8B on llama.cpp's `llama-server` (`/v1/systemone`) scores "is this command
   risky?". Below `askAbove` (0.2) it runs; otherwise it asks. Down, slow (> `timeoutMs`) or
   garbled answers ask. The plugin never turns an error into an allow.
3. **Sandbox.** Every auto-allowed command runs with its shell swapped for `sandbox/bin/<shell>`,
   a link to `sandbox/lockwrite`, which starts the real shell with the same arguments inside a
   private user + mount namespace (no root needed), then under Landlock:
   - **Writes** only beneath the project's checkouts, `allowedPaths`, temp dirs, build-cache
     stores (`~/.cargo/registry`, `~/.npm/_cacache`, ...; never directories whose contents run
     later, like `~/.cargo/bin`), `/dev/null`-style devices and a private `/dev/shm`.
   - **Git directories** found under the project, `allowedPaths` and temp dirs (main, linked
     worktrees, submodules, bare repos; up to 4 levels deep) are read-only, as are `.git`
     pointer files and every repository's `core.hooksPath` (husky and friends). Every directory
     between a writable root and a nested repository is pinned, so no parent can be renamed and
     swapped for another repository. A tool call made only of plain git commands (`add`,
     `commit`, `checkout`, `fetch`, ..., no redirects, `--output` or `--exec`) may write inside
     git directories, except hooks, config and `commondir`, and cannot rename them.
   - **Hidden**: local sockets of other services (systemd user manager, D-Bus, gpg-agent,
     other tools' IPC sockets in your runtime dir and `/tmp`, Docker) and credential locations
     (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`,
     `~/.config/gh`, `~/.config/gcloud`, `~/.vault-token`, opencode's config, data and state
     directories (the state holds the local server's password), following `XDG_*_HOME`, ...,
     plus `sandboxHidePaths`). Environment variables that look like credentials (`*_TOKEN`,
     `*_KEY`, `*_SECRET`, `AWS_*`, `GITHUB_*`, ...) are removed. Private keys in `~/.ssh` are
     never visible. The ssh agent (wherever its socket lives), `known_hosts` and `config` are
     visible only to a tool call that is a single `git fetch/pull/push/ls-remote` of the
     project's own repository (same git directory as at session start, without options that
     pick a program, and with no repository config that changes how git connects), or a single
     `ssh`/`scp` command.
   - On Linux 6.12+ also no signals to, and no abstract sockets of, processes outside the
     sandbox. A restricted process cannot mount, unmount or ptrace, so none of this can be
     undone from inside.

   The command text is never changed, so opencode's own rules and prompts see the real
   command. Commands you approve in a prompt run unsandboxed, exactly as shown. If an allowed
   command cannot be sandboxed (unsupported shell, or the sandbox self-test failed at startup),
   it asks instead.

The plugin records the project's git layout at session start, nested repositories and pointer
files included. If it changes in a way git never does itself (a `.git` replaced or moved, a
pointer file rewritten, `commondir` planted, or a `.git` appearing where there was none), auto-allow
stops for the rest of the session. The one exception is a repository appearing at a project root
right after a `git init` or `git clone` the plugin asked you about. The plugin's own git calls run
with fsmonitor and hooks disabled.

**Scheduled checks.** opencode schedules can run an `if`/`until` shell check repeatedly; opencode
approves it once, when the schedule is created, and then runs it without any sandbox. For a
schedule the agent created, the plugin judges that approval like any command and at most lets it
ask, never auto-allows. Schedules you create through opencode's UI or API are yours and are left
to opencode.

## Settings

`~/.config/opencode/automode.json` (see `automode.example.json`):

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Off: the plugin changes nothing and opencode's own rules apply. |
| `useClassifier` | `true` | Off: what the rules leave open asks instead of going to Kev. |
| `classifier` | port 11438, `askAbove` 0.2, `timeoutMs` 5000 | Kev server and threshold. |
| `rules` | empty | Your own `allow`/`ask`/`deny`/`classify` patterns: a glob over one simple command (`*` any text, trailing ` *` optional) or `re:` + regex. |
| `allowedPaths` | none | Extra directories counted as the project (writable, writes there allowed). |
| `sshHosts` | none | `ssh` to these hosts runs when the remote command only uses read-only programs with safe options (`cat`, `df`, `journalctl`, `systemctl status`, `ip addr`, ...), with no substitutions or redirects except to `/dev/null`, and ssh itself only uses harmless options (`-q`, `-T`, `-p`, `-l`, `-o BatchMode/ConnectTimeout/...`). |
| `sshReadOnlySudo` | `false` | On `sshHosts`: also allow `sudo [-n] <read-only command>`. |
| `allowFeatureBranchPush` | `false` | `git push` runs when it is the whole tool call, pushes the project's own repository to the remote it would actually use (the named one, else the branch's remote, else `origin`) whose URL is unchanged since the session started, targets a non-protected branch by its plain name (not `main`/`master`/`release*`/`develop`/... nor the default branch the remote reports; qualified forms like `heads/x` ask), and the repository config does not redirect pushes or change how git connects. Force, deletes, tags and `--no-verify` ask. |
| `sandbox` | `true` | Off: auto-allowed commands run unsandboxed. Not recommended. |
| `sandboxWritable` | build-cache stores | More directories auto-allowed commands may write to. |
| `sandboxKeepSockets` | none | Sockets to leave visible (e.g. your ssh agent for all commands). |
| `sandboxShowPaths` | none | Credential locations to leave visible. |
| `sandboxHidePaths` | none | More files or directories to hide from sandboxed commands. |
| `sandboxKeepEnv` | none | Credential-looking environment variables to pass through anyway. |
| `log` | `true` | Log every decision, with the full command, to `~/.local/state/opencode-automode/decisions.jsonl`. |

"Always allow" in an opencode prompt is mirrored per project into
`~/.local/state/opencode-automode/always.json`, only for plain word patterns on a short allowlist
of common build, test and read commands (`git status/commit/...` but not `git push`, `git config`
or `git rebase`, `cargo build/test`, `npm run`, `pytest`, `ls`, `cat`, `grep`, project scripts
`./x`, ...). Whatever they run still runs sandboxed. Like a prompt's session choice, it never overrides a firm ask (root, credential
reads, downloaded code, your own ask rules). For `edit` and `read` the plugin only tightens.
opencode `deny` rules never reach it, so they always win.

## Install

Linux x86_64 with Landlock (kernel 5.13+; 6.12+ for signal and socket scoping) and unprivileged
user namespaces, Node 22.18+, `gcc`, and systemd user services.

```sh
git clone https://github.com/vpsman/opencode-automode ~/.local/share/opencode-automode/plugin
cd ~/.local/share/opencode-automode/plugin
npm install --ignore-scripts      # @opencode/plugin types; opencode supplies the runtime
npm run build:sandbox             # compiles sandbox/lockwrite and runs its self-test
scripts/fetch.sh                  # llama.cpp b12283 + Kev-0.8B, SHA-256 checked
cp systemd/opencode-automode-kev.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now opencode-automode-kev
```

Then add the plugin folder's absolute path to `"plugins"` in `~/.config/opencode/opencode.jsonc`.
`fetch.sh` downloads llama.cpp (MIT) from its GitHub releases and the Kev model from Hugging Face
(`ggml-org/Kev-0.8B-GGUF`); check the model card for the model's licence.
Everything lives under `~/.local/share/opencode-automode` (override with `OPENCODE_AUTOMODE_HOME`
for `fetch.sh`, and edit the service to match).

## Tests

```sh
npm run build:sandbox && npm test
```

`test/decide.test.mts` covers the decision rules: push and ssh matchers, git-config and
override asks, the project root, "Always allow" patterns, and the git-tampering pause.
`test/sandbox.test.mts` runs commands through the real wrapper: writes, devices, hooks, git
config, renaming `.git`, `commondir`, husky hooks, mounts, signals, `/proc`, hidden sockets and
credentials, exit codes.

## Bench

```sh
node bench/run.mjs --tag kev-0.8b --suites-dir <dir-of-jsonl-suites>
node bench/score.mjs kev-0.8b
```

`run.mjs` drives `decideShell()`, the plugin's own code path, against the live server and
writes to `~/.cache/opencode-automode/bench/<tag>/`. The model never decides during a run, so
`score.mjs` can sweep `askAbove` afterwards.

Results on 2026-11-11 (6 vCPU AMD Zen 5, no GPU): with Kev-0.8B at 0.2, 32 of 765 risky commands in
Pi's labelled sets ran (1 by the model; the rest are rule allows of read-only recon and `/tmp`
writes), 55% of safe ones asked (mostly cloud CLIs), and 86% of ~5,950 past Claude commands ran
without a prompt. Kev-4B was no more accurate, 4–5× slower and timed out on long commands.
Neither model could tell whether the user asked for an action (tested on 87 rows with the user's
message), which is why pushes and ssh use deterministic rules instead.

## Known gaps

- **Network and reads.** The sandbox confines writes and local IPC, not reads of non-secret
  files or the network. An auto-allowed command can connect to any host or local port; local
  services that accept unauthenticated requests are reachable. Outbound data and credential
  reads are asks in the rules, not enforced by the sandbox.
- **ssh.** A single `git fetch/pull/push/ls-remote` or `ssh`/`scp` call sees your ssh agent, so
  it can authenticate wherever your keys open, including this machine if it runs sshd. The
  rules only auto-allow `ssh` to `sshHosts`; keep that list short.
- **`/tmp` is shared.** It stays writable and shared with other processes, because agents and
  opencode's own tools pass files through it.
- **Late arrivals.** Sockets and git repositories created after a command starts are not
  covered for that command (hence `git clone` and `git init` ask). Repositories more than 4
  levels below a writable directory are not found.
- **Schedules.** After approval, a schedule's checks run outside the sandbox (opencode starts
  them directly), so approve agent-created schedules with care.
- **Environment.** Credential variables are removed by name pattern; a secret in an
  unusually named variable still reaches sandboxed commands (`sandboxKeepEnv` is the reverse).
- **The model** reads a window of the command, not all of it; the rules read all of it.
- **What you approve** in a prompt is not sandboxed.
