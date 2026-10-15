# Radare2 transport experiment

This is an isolated prototype for the [transport proposal](../../docs/radare2-proposal.md).
It is not imported by REA, advertised to agents, included in the npm package or
an approved provider. It uses REA's existing process supervision and tagged
errors/Result; it does not implement production Evidence or session admission.

Use the pinned Node/npm toolchain, install locked dependencies and build first:

```sh
npm ci
npm run build:cached
node experiments/radare2-transports/verify.mjs
```

The explicit verifier requires a C compiler, radare2 with r2ghidra and r2mcp on
`PATH`. `CC`, `REA_R2_COMMAND` and `REA_R2MCP_COMMAND` can select executables.
It compiles `fixture.c` into a private temporary directory without running it,
starts a loopback HTTP fixture and cleans up owned processes. Missing providers
fail the experiment; they are not silently skipped. These checks are separate
from the portable test suite.

To inspect a selected binary using r2pipe2:

```sh
node experiments/radare2-transports/probe.mjs '{"transport":"r2pipe","path":"./program","commands":["aa",{"cmd":"aflj","json":true},"pdg @ main"]}'
```

Other transports are `exec`, `r2mcp`, and `http`. For `http`, replace `path` with
the exact `endpoint`, for example `http://127.0.0.1:9090/cmd/`. For `exec`, each
command runs in a fresh process; include any necessary analysis in that command.
All carriers submit r2pipe2 requests. String commands request text; object
commands preserve explicit `json` and `trim` choices. Responses preserve raw
frames, parsed envelopes and process diagnostics separately. The 16 MiB frame
and transcript budgets follow REA's current reverse-command capture budget;
they do not establish production memory bounds or token savings.

The default deadline is 120 seconds for the whole batch. The programmatic `probe`
accepts a caller `signal`, `timeoutMs`, captured `environment`, and optional HTTP
`authorization`; authorization and ambient environment are not persisted. HTTP
submissions and MCP calls are never automatically replayed. `retryCleanup()`
retains and retries unresolved process owners within the experiment process.
External HTTP sessions remain unowned. Results explicitly leave target identity
unverified. Review the proposal's authority and verification gaps before running
arbitrary commands against a valuable external session.
