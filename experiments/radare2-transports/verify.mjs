// Explicit real-provider experiment, intentionally outside the portable test suite.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { connect } from "node:net";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { runOwnedCommand } from "../../dist/process/OwnedCommand.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../../dist/process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../../dist/process/ProcessOwnership.js";
import { probe, retryCleanup, stopAndDrain } from "./probe.mjs";

const root = await mkdtemp(join(tmpdir(), "rea-radare2-probe-"));
const artifact = join(root, "transport fixture");
const owners = new Set();
const r2 = process.env.REA_R2_COMMAND ?? "r2";
const commands = [
  "aa",
  { cmd: "aflj", json: true },
  "pdg @ main",
  "pdc @ main",
];

before(async () => {
  await runOwnedCommand(
    {
      command: process.env.CC ?? "cc",
      arguments: [
        "-O0",
        "-g",
        fileURLToPath(new URL("./fixture.c", import.meta.url)),
        "-o",
        artifact,
      ],
      runId: randomUUID(),
    },
    { timeoutMs: 30_000, diagnosticBytes: 1024 * 1024 },
  );
});

after(async () => {
  const pending = [];
  for (const owner of owners) {
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await stopAndDrain(owner);
      if (result.status !== "incomplete") {
        owners.delete(owner);
        break;
      }
      await owner.waitForExit(1_000);
      if (attempt === 1)
        pending.push({ result, diagnostics: owner.snapshot() });
    }
  }
  assert.equal(
    await retryCleanup(),
    0,
    "Probe cleanup ownership is still retained",
  );
  assert.equal(
    owners.size,
    0,
    `HTTP server cleanup ownership is still retained: ${JSON.stringify(pending)}`,
  );
  await rm(root, { recursive: true, force: true });
});

function replies(result) {
  assert.equal(
    result.ok,
    true,
    result.ok
      ? ""
      : `${result.error.cause?.message}: ${JSON.stringify(result.error.partialObservation)}`,
  );
  return result.value.transcript.flatMap((entry) =>
    entry.r2pipe2 ? [entry.r2pipe2] : [],
  );
}

function verifyAnalysis(result) {
  const output = replies(result);
  assert.ok(
    output.some(
      (reply) =>
        Array.isArray(reply.res) &&
        reply.res.some((fn) => fn.name.includes("main")),
    ),
  );
  const pseudocode = output.filter(
    (reply) =>
      typeof reply.res === "string" &&
      reply.res.includes("REA radare2 transport fixture"),
  );
  assert.equal(
    pseudocode.length,
    2,
    "Both r2ghidra and pdc must produce pseudocode",
  );
  assert.ok(
    output.every((reply) => reply.command_outcome === "no_error_reported"),
  );
}

for (const transport of ["exec", "r2pipe", "r2mcp"]) {
  test(`real ${transport}: JSON, decompilers, diagnostics and owned cleanup`, async () => {
    const selected =
      transport === "exec"
        ? [{ cmd: "aa; aflj", json: true }, "aa; pdg @ main", "aa; pdc @ main"]
        : commands;
    const result = await probe({
      transport,
      path: artifact,
      commands: selected,
    });
    verifyAnalysis(result);
    assert.equal(result.value.cleanup, "complete");
    if (transport !== "exec") {
      assert.ok(
        result.value.transcript.some(
          (entry) =>
            typeof entry.provider_diagnostics?.stderr.text === "string",
        ),
      );
    }
  });
}

test("r2pipe2 retains native error status and logs", async () => {
  const result = await probe({
    transport: "r2pipe",
    path: artifact,
    commands: ["rea_invalid_probe_command", { cmd: "ij", json: true }],
  });
  const output = replies(result);
  assert.equal(output[0].command_outcome, "reported_error");
  assert.ok(output[0].logs.some((log) => log.type === "ERROR" && log.message));
  assert.equal(typeof output[1].res.bin.arch, "string");
});

test("invalid native JSON preserves output on both old and corrected engines", async () => {
  const result = await probe({
    transport: "r2pipe",
    path: artifact,
    commands: [{ cmd: "?e definitely not JSON", json: true }],
  });
  if (result.ok) {
    const [reply] = replies(result);
    assert.equal(reply.error, true);
    assert.notEqual(reply.code, 0);
    assert.match(reply.res, /definitely not JSON/u);
  } else {
    assert.match(
      result.error.partialObservation.provider_partial.raw_reply,
      /definitely not JSON/u,
    );
  }
  assert.equal(await retryCleanup(), 0);
});

async function listen(server) {
  await new Promise((accept, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", accept);
  });
  return server.address().port;
}
async function close(server) {
  server.closeAllConnections();
  await new Promise((accept, reject) =>
    server.close((error) => (error ? reject(error) : accept())),
  );
}

test("real HTTP: POST r2pipe2 to an existing session without taking ownership", async () => {
  // Reserve an available port, then release it before launching the owned fixture server.
  const reservation = createServer();
  const port = await listen(reservation);
  await close(reservation);
  const launch = await spawnOwnedProviderProcess({
    command: r2,
    runId: randomUUID(),
    arguments: [
      "-N",
      "-q",
      "-e",
      "scr.color=0",
      "-e",
      "http.bind=127.0.0.1",
      "-c",
      `=h ${port}`,
      artifact,
    ],
  });
  const owner = new ProviderProcessSupervisor(
    {
      ...launch,
      ownsProcessLifetime: true,
      cleanup:
        launch.cleanup ?? (() => cleanupOwnedProcessGroup(launch.ownership)),
    },
    { maxDiagnosticBytes: 1024 * 1024 },
  );
  owners.add(owner);
  const endpoint = `http://127.0.0.1:${port}/cmd/`;
  // Only readiness is retried. Each selected command is dispatched once.
  const deadline = performance.now() + 10_000;
  for (;;) {
    try {
      await new Promise((accept, reject) => {
        const socket = connect({
          host: "127.0.0.1",
          port,
          signal: AbortSignal.timeout(250),
        });
        socket.once("connect", () => {
          socket.destroy();
          accept();
        });
        socket.once("error", reject);
      });
      break;
    } catch (cause) {
      if (performance.now() > deadline) throw cause;
    }
    await new Promise((accept) => setTimeout(accept, 25));
  }
  const result = await probe({ transport: "http", endpoint, commands });
  verifyAnalysis(result);
  assert.equal(result.value.cleanup, "external_session_unowned");
  const state = await probe({
    transport: "http",
    endpoint,
    commands: [{ cmd: "aflj", json: true }],
  });
  assert.ok(
    replies(state)[0].res.length > 0,
    "External analysis must remain available",
  );
});

test("HTTP preserves command bytes, status and URL; rejects redirects and remote hosts", async () => {
  const requests = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const bytes of request) body += bytes;
    requests.push({ url: request.url, body });
    if (request.url === "/redirect") {
      response.writeHead(302, { Location: "/must-not-run" });
      response.end();
    } else if (request.url === "/malformed") {
      response.end("malformed native reply");
    } else {
      response.end(
        JSON.stringify({ res: "ok", error: false, code: 0, value: 0 }),
      );
    }
  });
  const port = await listen(server);
  try {
    const command = "?e spaces + & % ? # café";
    const endpoint = `http://localhost:${port}/cmd/custom?selection=one`;
    const result = await probe({
      transport: "http",
      endpoint,
      commands: [command],
    });
    assert.equal(replies(result)[0].res, "ok");
    assert.equal(result.value.input.endpoint, endpoint);
    assert.deepEqual(requests[0], {
      url: "/cmd/custom?selection=one",
      body: JSON.stringify({ cmd: command, json: false, trim: false }),
    });
    assert.equal(
      (
        await probe({
          transport: "http",
          endpoint: `http://127.0.0.1:${port}/redirect`,
          commands: [command],
        })
      ).ok,
      false,
    );
    assert.equal(
      requests.length,
      2,
      "A redirect must not dispatch another command",
    );
    const malformed = await probe({
      transport: "http",
      endpoint: `http://127.0.0.1:${port}/malformed`,
      commands: [command],
    });
    assert.equal(malformed.ok, false);
    assert.equal(
      malformed.error.partialObservation.provider_partial.raw_reply,
      "malformed native reply",
    );
    assert.equal(
      requests.length,
      3,
      "A malformed response must not replay the command",
    );
    assert.equal(
      (
        await probe({
          transport: "http",
          endpoint: "http://example.com/cmd",
          commands: [command],
        })
      ).ok,
      false,
    );
    assert.equal(requests.length, 3);
  } finally {
    await close(server);
  }
});

test("HTTP cancellation after dispatch returns unknown completion without replay", async () => {
  const controller = new AbortController();
  let dispatched = 0;
  const server = createServer(async (request) => {
    for await (const _bytes of request) {
      /* wait for the complete submitted body */
    }
    dispatched++;
    controller.abort();
  });
  const port = await listen(server);
  try {
    const result = await probe(
      {
        transport: "http",
        endpoint: `http://127.0.0.1:${port}/cmd`,
        commands: ["?e once"],
      },
      { signal: controller.signal },
    );
    assert.equal(result.ok, false);
    assert.equal(result.error.partialObservation.completion, "unknown");
    assert.equal(dispatched, 1);
  } finally {
    await close(server);
  }
});
