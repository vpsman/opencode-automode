# Security

opencode-automode is **experimental**. It decides which commands an AI agent may run without
asking you, and runs those inside a sandbox. It has been through several rounds of AI-assisted
code review, each of which found and fixed real problems, but it has **not** had an independent
human security audit. Treat it as a way to get fewer prompts, not as a security boundary you can
rely on against a determined adversary.

## What counts as a vulnerability

Anything that breaks a guarantee the README states, for example:

- a command auto-allowed when the rules or the model should have made it ask;
- an auto-allowed command writing outside the directories the sandbox allows, changing git
  hooks or config, reaching a hidden socket or credential, or signalling a process outside;
- something planted by a sandboxed command that later runs outside the sandbox;
- the plugin failing open: an error, timeout or unexpected input ending in "allow".

The limits listed under "Known gaps" in the README (network access, reads of files that are not
hidden, project files that run later, builds and tests running the session's code, values bash
evaluates as arithmetic when they come from a file or the environment, allowed programs judged
by name, the ssh agent for ssh commands, shared `/tmp`, an `opencode.json` created mid-session,
scheduled checks after approval) are known and not vulnerabilities in themselves, but ways to
turn them into one of the above are. A shell input that bash runs differently from how the
rules read it is always one: `test/differential.test.mts` is the place to add it.

## Reporting

Please report privately through GitHub: **Security → Report a vulnerability** on this
repository. Include the command or setup that shows the problem, your Linux kernel version, and
if you can the matching line from `~/.local/state/opencode-automode/decisions.jsonl` (it holds
the full text of every command, so check it for anything private first).

Please don't open a public issue for a vulnerability until a fix is released. Reports are
handled on a best-effort basis; there is no bounty.

## Supported versions

Only the latest commit on the default branch is supported.
