# Radare2 transport proposal

Status: draft proposal and isolated experiment. Radare2 is not registered in
REA's runtime, setup, doctor or tool catalog by this change. Integration requires
the maintainer scope decision described in [Contributing](../CONTRIBUTING.md#fail-closed-integration).
Related work: [feature request #2711](https://github.com/morluto/rea/issues/2711)
and [provider PR #3521](https://github.com/morluto/rea/pull/3521). Coordinate the
owned command/session work with that PR instead of shipping two implementations.

## Analyst question and proposed boundary

An analyst should be able to inspect and decompile a selected local binary with
their installed radare2, or continue analysis in their existing local r2 session,
without installing Hopper or a Java-based analysis provider. Rizin's command
adapter does not establish compatibility with radare2's protocols or plugins.

Preserve the provider PR's proposed one-shot and session operations. Extend the
session target with an explicit transport selection; do not add four duplicate
analysis tool families. These names describe the proposed contract, not currently
available REA commands:

| Operation                 | Intended input                                                        | Result                                                                                         |
| ------------------------- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `execute_radare2_command` | Local path, caller-selected r2pipe2 request                           | Inline command Evidence and owned cleanup outcome                                              |
| `start_radare2_session`   | Discriminated owned-path, existing HTTP endpoint, or r2mcp connection | Session identity, transport, observed capabilities, ownership and launch/connection provenance |
| `radare2_command`         | Session ID and `{cmd,json?,trim?}`                                    | Requested result inline, native status/logs, raw response Evidence and coverage                |
| `radare2_session_status`  | Session ID                                                            | Fresh lifecycle observation, retained cleanup and target-identity uncertainty                  |
| `close_radare2_session`   | Session ID                                                            | Release REA's connection; stop only resources it owns                                          |

The domain owns these contracts, the radare2 adapter owns r2pipe2 parsing and
transport state, and the application owns Evidence, session admission and
retention. CLI and MCP use that shared workflow. Transport-specific protocol
objects stay in the adapter. Preserve caller-selected executable, path, endpoint,
command, analysis settings, output format and decompiler; never select an
operation by catalog position or command-name suffix.

## Transport choices

| Transport         | Use and effects                                                                                                                 | Ownership and performance                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Command execution | One owned `r2 -N -q -e scr.color=0 -c REQUEST ABSOLUTE_PATH` process; plugins remain available                                  | Independent invocation; useful for a single question, with repeated loading/analysis for independent requests      |
| r2pipe2           | Owned `r2 -N -q -e scr.color=0 -0 ABSOLUTE_PATH`; JSON requests and NUL-framed JSON replies                                     | Reuse the same analysis state; serialize commands, bound frames and preserve cleanup ownership                     |
| r2pipe over HTTP  | POST an r2pipe2 JSON request as the body to the exact caller-selected loopback `/cmd` or `/cmd/` endpoint                       | Reuse a caller-owned r2/iaito session; never reopen its file, terminate the server or send `q` on disconnect       |
| r2mcp             | Discover and bind named advertised tools on a caller-selected local connection; raw access needs upstream `run_command` support | Retain the upstream MCP session/catalog; preserve its permission settings, tool errors, paging and server identity |

The prototype exercises owned r2mcp stdio with `-r -N`, where `-r` deliberately
enables raw commands and `-N` disables prompts. These flags differ from radare2's:
r2mcp `-n` also disables plugins, including decompilers. A production connection
must preserve caller-selected upstream arguments and must report unavailable
raw access rather than silently change permissions. r2mcp's own MCP HTTP mode
is a distinct protocol from r2's `/cmd` HTTP endpoint; it remains unverified here.

For a caller-started server, the upstream equivalents are:

```sh
# Start r2's webserver without opening a browser; the selected r2 owns its state.
r2 -N -q -e http.bind=127.0.0.1 -c '=h 9090' ./program

# Submit once. --data-binary preserves the JSON request body exactly.
curl --data-binary '{"cmd":"aflj","json":true}' http://127.0.0.1:9090/cmd/
```

These are upstream commands, not new REA entrypoints. The prototype pins
`localhost` to loopback, preserves the original endpoint separately, refuses
userinfo/remote endpoints and does not follow redirects or retry submissions.
Optional transport authorization is supplied separately and is not recorded.
The installed r2 6.2.5 emits LF-only HTTP response headers. The experiment uses
Node's HTTP compatibility parser for this explicit loopback peer, retaining raw
header values; it does not repair response bytes with string replacements.

## r2pipe2 results and failure ownership

Use [r2pipe2](https://github.com/radareorg/radare2-book/blob/master/src/scripting/r2pipe2.md)
for every carrier, including HTTP POST bodies and r2mcp `run_command`. Retain
`res`, `error`, `code`, `value`, `logs` and unknown envelope fields alongside the
original response. Parse once at the adapter boundary. Explicit `json:true`
requests native JSON; text commands use `json:false`. Never rerun a command to
change its output mode after a parse failure.

Keep process stderr separate from per-command r2pipe2 logs. A session-wide stderr
observation cannot prove which command caused every byte. Retain byte counts,
truncation, decoding loss, partial frames, startup diagnostics and cleanup
failures. Invalid JSON must preserve its original frame and uncertainty.

Observed on the original local engine: an invalid subcommand returned
`error:false`, `code:0` and an `ERROR` log; `json:true` on non-JSON output emitted
malformed JSON. These are producer defects, not reasons for REA to erase logs,
silently retry, or infer success from a single flag. Corrections are developed in
the separate radare2 checkout. REA must still preserve results from older engines.

The r2mcp raw-command implementation executes the command before applying
pagination. A subsequent cursor call can execute it again. Preserve the full
upstream tool result and paging metadata; do not follow pages by replaying an
arbitrary command. The experiment requests the advertised 10,000-item/line page
maximum when supported and does not promise completeness beyond that page.

## Decompiler choice

Recommend [r2ghidra](https://github.com/radareorg/r2ghidra) for native local
decompilation. It embeds Ghidra's C++ decompiler and does not require the full
Ghidra application or Java. Plugins and tools remain bring-your-own; this proposal
does not install software or change user configuration.

| Explicit choice | Upstream use                                                                  | Interpretation                                                                                                              |
| --------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| r2ghidra        | Analyze the selected function, then `pdg @ main`; `pdgj` supplies plugin JSON | Engine-derived pseudocode; preserve warnings and unavailable-plugin failures                                                |
| pdc             | `pdc @ main`, with the session's `cmd.pdc` selection preserved                | Built-in pseudocode backend when selected; quality and structuring differ from r2ghidra                                     |
| decai           | Caller-configured `decai -d`                                                  | Model-generated interpretation; retain selected model/provider and source evidence, without presenting it as an observation |

r2mcp supports explicit decompiler selection, for example `r2mcp -r -N -d pdg`,
and advertises `list_decompilers` / `use_decompiler`. Preserve the actual selected
backend instead of switching on failure. `cmd.pdc` can redirect `pdc`; a command
name alone does not prove which decompiler ran. See the
[decai guide](https://github.com/radareorg/r2ai/blob/master/decai/README.md) for its
local model configuration. Never select a cloud endpoint, transmit target
content, install a model or invoke decai implicitly. A loopback transport does
not constrain what caller-selected commands or plugins can do.

## Authority, Evidence and integration decision

The proposed raw-command surface is unrestricted. It can execute scripts and
shell commands, launch/attach targets, mutate files/memory/configuration and
contact services, including through plugins. The maintainer decision must cover
those effects and the final transport defaults. Existing Rizin authority does not
approve this provider. No dedicated debugging, injection, protection recovery,
evasion or bypass workflow is proposed.

For owned static workflows, preserve the caller path, resolved launch path,
executable and artifact digests before/after, without claiming these prove the
exact bytes consumed. For external sessions, launch path and caller-supplied file
names do not prove the current target. Record observed engine facts separately;
keep unresolved identity unknown. Shared external commands need the existing
external-mutation admission/analysis retirement boundary. Existing Ghidra
analysis must be closed explicitly first.

The experiment returns protocol observations, **not REA Evidence**. It deliberately
reports target identity as unverified. Production Evidence creation, persistence,
authentication redaction, session admission, resource accounting and CLI/MCP
schema validation remain integration work after approval.

## Verification and performance decision

Local verification on macOS arm64 used Node 24.18.0/npm 11.16.0, r2mcp 1.8.8,
and radare2 6.2.5 development commit `679075d13e` with local r2pipe2 producer
fixes applied. The eight explicit transport checks passed with installed
r2ghidra. REA's `build:cached`, `check`, `docs:check` and `verify:test-discovery`
also passed. The TypeScript client's separate URL-encoding regression and fix
are tracked in [upstream PR #187](https://github.com/radareorg/radare2-r2pipe/pull/187).
The Python async client's separate `quit()` lifecycle correction is tracked in
[upstream PR #188](https://github.com/radareorg/radare2-r2pipe/pull/188).

The [isolated experiment](../experiments/radare2-transports/README.md) compiles a
disposable source fixture and exercises actual local r2/r2mcp processes and a
loopback r2 webserver. Its verifier requires installed r2ghidra and also checks
pdc output, native JSON, logged command errors, malformed native JSON, HTTP
command-byte preservation, cancellation, redirects and owned cleanup. It never
runs the fixture executable or invokes a model.

Prefer a retained r2pipe2 session for multiple related questions; use an existing
HTTP/r2mcp session when the caller already has useful analysis. Run only the
requested analysis once, preserve its settings and generation, and invalidate
after mutations or unresolved command completion. Do not add a global cache
keyed only by file path. Scope selection and retained full Evidence should avoid
returning raw output plus duplicate JSON/summary copies to the agent.

No agent-token, CPU or process-family peak-memory improvement is established by
the prototype. Test durations include setup and are not equivalent-workflow
benchmarks. Before selecting production defaults, measure complete one-question
and multi-question tasks, including catalog/schema discovery, output, errors and
retries; report actual model tokens (label tokenizer estimates), elapsed time,
CPU and peak process-family memory, separately for cold starts and retained warm
sessions. Include server startup costs for cold HTTP/r2mcp runs. Linux, Windows,
older radare2 versions, r2mcp MCP-over-HTTP, actual agent selection, decompiler
quality, live-target detach and production failure/limit semantics remain
unverified.
