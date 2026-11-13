# Security

opencode-automode is **experimental**. It decides which commands an AI agent may run without
asking you, and runs those inside a sandbox. It has been through several rounds of AI-assisted
code review, each of which found and fixed real problems, but it has **not** had an independent
human security audit. Treat it as a way to get fewer prompts, not as a security boundary you can
rely on against a determined adversary.

## What counts as a vulnerability

Anything that breaks a guarantee the README states, for example:

- a command auto-allowed when the rules or the model should have made it ask;
- an allowed command whose printed text (the text that runs) does something else than the
  command as the agent wrote it;
- an auto-allowed command writing outside the directories the sandbox allows, changing git
  hooks or config, reaching a hidden socket or credential, or signalling a process outside;
- something planted by a sandboxed command that later runs outside the sandbox, including a
  `commondir` or `config.worktree` that is still in place after the call that made it is over;
- a file the session changed, or a build, test or script in a project the session wrote
  into, running without going to the model: a bypass of the change-time check, of the record
  of what the session wrote, or of the safe list;
- an ssh agent handed to a git command that goes into cloned submodules;
- the plugin failing open: an error, timeout or unexpected input ending in "allow".

The limits listed under "Known gaps" in the README (network access, data typed literally into
a URL or a DNS name, reads of files that are not hidden, a credential file read through a name
made earlier in the same call or by a program that reads a whole directory, project files that
run later, builds and tests in a session that has written nothing, values bash evaluates as
arithmetic in a script or program the command runs, allowed programs judged by name, a file
named like an option that an archive or a checkout brings, a planted git file for as long as
the call that made it runs, the ssh agent for ssh commands, remote read-only checks that read
only the words, abstract unix sockets on Linux 6.10 and 6.11, a bash older than 5.2, shared
`/tmp`, two opencode processes on one checkout, an `opencode.json` created mid-session,
scheduled checks after approval) are known and not vulnerabilities in themselves, but ways to
turn them into one of the above are. A shell input that bash runs differently from how the
rules read it, or differently as printed than as written, is always one:
`test/differential.test.mts` is the place to add it.

## Reporting

Please report privately through GitHub: **Security → Report a vulnerability** on this
repository. Include the command or setup that shows the problem, your Linux kernel version, and
if you can the matching line from `~/.local/state/opencode-automode/decisions.jsonl` (it holds
the full text of every command, so check it for anything private first).

Please don't open a public issue for a vulnerability until a fix is released. Reports are
handled on a best-effort basis; there is no bounty.

## Supported versions

Only the latest commit on the default branch is supported.
