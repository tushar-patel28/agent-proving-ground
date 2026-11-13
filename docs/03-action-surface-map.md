# 03 — Action surface map

Drafted by Claude Code, reviewed by Tushar
Date: Nov 13, 2026
Status: T2.1 draft. T6.2 finishes this doc (gates, export path).

This lists every action the agent can take, what the permission policy (`internal/policy`) checks before the action runs, and what the policy cannot stop. Every tool call goes through `policy.Check` before it runs. A denied call is never executed. It is written into the trace as a step with `verdict: "denied"`, the `rule`, and the `reason`, and the model gets that reason as an error result.

## The agent's tools

The agent acts only through the tools its task contract lists (`allowed_tools` in `contract.json`). Each tool becomes host commands (`kubectl exec` / `kubectl cp` into the run's pod), and every host command is recorded in the trace.

| Tool | What runs in the pod | Checked by the policy |
|---|---|---|
| `read_file` | `cat <path>` | Rules 1, 2, 3 on the path |
| `write_file` | `mkdir -p <dir>`, then `kubectl cp` of a host temp file to `<path>` | Rules 1, 2, 3 on the path; the path may not be `/workspace` itself |
| `run_command` | `timeout 60 <argv…>`: argv form, no shell | Rules 1–5 on the program and every argument |

Before an allowed call runs, the loop also runs `realpath -m -- <paths…>` in the pod (argv form) to get the real path of each path the call names. That command is recorded in the trace too.

The working directory of every `kubectl exec` is `/workspace`. `kubectl exec` has no working-directory option, so the pod spec sets `workingDir: /workspace` on the container (`internal/sandbox/kind.go`) instead of relying on the image's `WORKDIR`. The policy resolves relative paths against `/workspace`, so this must hold. In the seeded run below, `python -c "import os; print(os.getcwd())"` printed `/workspace`, and `cat calc/ops.py` read the file that `realpath` reported as `/workspace/calc/ops.py`.

## Policy rules

| # | Rule (trace `rule`) | What is denied |
|---|---|---|
| 1 | `tool` | A tool not listed in the contract, or one the policy has no rules for. |
| — | `input` | Input that does not parse (unknown fields, wrong types, empty path or argv, NUL bytes). |
| 2 | `path` | A path that is not `/workspace` or under it. First by text: relative paths are joined to `/workspace`, `..` is resolved, and control characters are denied. Then by the real path from `realpath` in the pod, which catches symlinks. |
| 3 | `check_file` | Any path or argument that names the check directory (`/tmp/apg-check-<random>`, `policy.CheckDirPrefix`). This includes patterns and python code, and real paths after symlinks. |
| 4 | `program` | `argv[0]` not exactly one of `python pytest ls cat head tail grep sed diff wc find`. With no shell, this is the program that runs, so `sh`, `bash`, `cd`, `env`, `xargs`, `/bin/ls` and `python3` are denied, and so are pipes, `&&`, redirection and globs. |
| 5 | `flag` | Options that let an allowed program run another program, delete files, write or read files the policy cannot check, or follow symlinks (list below). |

A call denied by text alone (rules 1, 3, 4, 5, and the text part of rule 2) never runs anything in the pod, not even `realpath`. A unit test checks this (`TestLexicalDenialsDoNotResolve`).

### Which arguments are paths (rules 2 and 4)

Every argument is treated as a possible path unless the program's parser knows it is something else. Treating a non-path as a path only ever denies too much, because a word like `5` or `add or divide` resolves inside `/workspace`. In an argument, the policy checks:
- the operand itself
- the value after any `=` (`--basetemp=/tmp/x`, `-o cache_dir=/tmp/c`)
- the attached value in a short-option cluster: everything from the first character that is not a letter or digit (`-f/etc/shadow`, `-i../x`)

Arguments that are not path-checked, by design:

| Program | Not path-checked | Why |
|---|---|---|
| `grep` | the pattern (first operand, unless `-e`/`-f` appears anywhere; GNU permutes arguments) and `-e`/`--regexp` values | patterns like `/usr/bin` are not paths |
| `sed` | the script (first operand, unless `-e`), checked by the sed script check instead | |
| `python` | the code after `-c` | python can run anything anyway; see below |
| `find` | the value after `-name -iname -path -ipath -wholename -iwholename -regex -iregex -lname -ilname -printf -perm` | patterns and formats |

### Denied flags (rule 5)

| Program | Denied | Class |
|---|---|---|
| `find` | `-exec -execdir -ok -okdir` | runs another program |
| `find` | `-delete` | deletes files |
| `find` | `-fprint -fprint0 -fprintf -fls` | writes files |
| `find` | `-L -H -follow` | follows symlinks |
| `grep` | `-R`, `--dereference-recursive` (and its abbreviations) | follows symlinks |
| `sed` | `e` command, `s///e` flag | runs a shell command |
| `sed` | `w W` commands, `s///w` flag | writes files |
| `sed` | `r R` commands | reads files the policy cannot check |
| `sed` | `-f`, `--file`, `--follow-symlinks` | script from a file the policy cannot read; follows symlinks |

The sed script check (`internal/policy/sed.go`) is an allowlist parser. It denies any command it does not recognise, and it scans scripts the same way GNU sed does (only a backslash escapes the delimiter). sed also always runs with `--sandbox`, so GNU sed itself refuses `e`, `r` and `w`. On Nov 13, 2026, `sed --sandbox` in `apg-sandbox:dev` (GNU sed 4.9) refused both `s/x/y/w /tmp/g` and `1e id` with "e/r/w commands disabled in sandbox mode".

## What the policy cannot stop

**python and pytest run arbitrary code.** Both are on the allowlist, and both run code the agent controls: `python -c`, a script, a test file, a `conftest.py`, any imported module. That code runs as the pod's user (uid 1000). It can read outside `/workspace`, create symlinks, delete files, and start other programs. The policy sees only the command line. The seeded run shows this: `python -c` created a symlink `etc-link → /etc` and read `/etc/hostname`, and both calls were allowed. So the policy makes the allowlist meaningful for the other nine programs and for the file tools, and it records every decision. **It is not the security boundary. The pod's isolation is the outer boundary.**

The pod spec sets these limits (`internal/sandbox/kind.go`): non-root (uid 1000), all capabilities dropped, no privilege escalation, no service-account token, CPU and memory limits, and a deny-all-egress NetworkPolicy. So far only the egress block has been tested: in T1.2 TCP and DNS from a pod with the policy failed, and every run's start probes until egress is blocked. The other limits are tested in T4.1.

Further gaps the policy has and that nothing tests yet:

- **Paths found during a walk.** `realpath` resolves the paths named on the command line. It does not resolve entries that `grep -r`, `find`, `ls -R` or `diff -r` reach while walking a directory. How each program treats a symlink found mid-walk was not checked per program. Only python can create a symlink, and python can already read those files.
- **Time between check and use.** A process the agent left running (python can start one) could swap a path for a symlink after `realpath` answers and before the command runs.
- **Check files, rule 3.** Today rule 3 holds mainly because of timing: the hidden check is copied into the pod only after the agent's last step, into a directory with a random name. During the run there is nothing to read. python could find the check if it were present. T2.3 (check after each write) must keep this in mind.
- **The test file is writable on purpose.** `tests/test_ops.py` is inside `/workspace`, so `write_file` may change it. The check's SHA-256 of the test file catches that (`check.sh`, T1.1). This is the Phase 6 controlled failure (premortem P1), so the policy must not hide it.
- **Long-running processes.** `timeout 60` stops the command it starts. A background process forked by python can outlive it until the pod is deleted (known limit noted in `kind.go`).

## Evidence (what ran)

- Unit tests, `go test ./internal/policy/` (Nov 13, 2026): 146 subtests passed. They cover each rule with allowed and denied cases, including the T1.4 shell pipeline (denied) and its `cat`/`sed`/`grep`/`pytest` parts as argv calls (allowed). Symlinks in these tests come from a fake resolver.
- Loop tests with a fake client and fake sandbox: denied calls are recorded with `verdict`, `rule` and `reason`, never reach the sandbox, and the model is sent `denied by policy (rule: …)`.
- **Seeded run** (scripted client, no model; real kind pod), `TestSeededRunOnKind`, Nov 13, 2026: `evidence/traces/20261113T204817Z-a016749b.json`. Ten steps on task 001:
  - The working directory was `/workspace`, and `calc/ops.py` resolved in the pod to `/workspace/calc/ops.py`.
  - Denied: `read_file ../etc/passwd` (path), `sh -c` (program), `find -delete` (flag), sed `1e id` (flag), and `read_file etc-link/passwd` after `realpath` answered `/etc/passwd` (path).
  - Allowed, showing the python limit: the symlink creation and the `/etc/hostname` read.
  - The bug was not fixed, so the check failed: `FAIL check_failed`.
- **Model run**, `apg run 001` with `claude-haiku-5-5`, Nov 13, 2026: `001  PASS  steps=7  reason=check_passed`, `evidence/traces/20261113T204837Z-3a19814c.json`. Its 6 tool calls were all allowed, and none was denied (step 7 was the final reply). The model listed files with `find`, read three files, rewrote `calc/ops.py` with `write_file`, and ran `python -m pytest -q tests/test_ops.py`.
