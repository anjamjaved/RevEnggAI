#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { crc32, deflateSync } from "node:zlib";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

if (process.platform !== "win32" || process.arch !== "x64")
  throw new Error(
    "Selected-window acceptance requires a real Windows x64 desktop.",
  );
const [packageArgument = ".", fixtureArgument, reportArgument] =
  process.argv.slice(2);
assert.ok(
  fixtureArgument,
  "Supply the compiled source-owned windowCapture.cc fixture.",
);
const packageRoot = resolve(packageArgument);
const fixturePath = resolve(fixtureArgument);
const load = (path) => import(pathToFileURL(join(packageRoot, "dist", path)));
const { WindowsOwnedProcess } = await load("windows/WindowsOwnedProcess.js");
const { toolContract } = await load("contracts/toolContracts.js");
const { comparePngScreenshots } = await load("browser/PngVisualDiff.js");
const { requireWindowsNativeAuthority } = await load(
  "windows/WindowsNativeLoader.js",
);
const native = requireWindowsNativeAuthority();
const token = native.call("process_caller_token", []);
const exec = promisify(execFile);
const root = await mkdtemp(join(tmpdir(), "rea-window-acceptance-"));
const runtime = join(root, "runtime");
await mkdir(runtime);
const environment = {
  ...Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => !name.toUpperCase().startsWith("REA_"),
    ),
  ),
  REA_ANALYSIS_PROVIDER: "auto",
  REA_LOG_LEVEL: "error",
  NODE_OPTIONS: "--max-old-space-size=512",
  TEMP: runtime,
  TMP: runtime,
  APPDATA: join(root, "appdata"),
  LOCALAPPDATA: join(root, "localappdata"),
  HOME: root,
  USERPROFILE: root,
};
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const original = digest(await readFile(fixturePath));
const report = {
  ok: false,
  platform: "win32",
  architecture: "x64",
  elevated: token.elevated,
  administrator: token.administrator,
  fixtureSha256: original,
  cases: {},
  metrics: [],
};
const owned = new Set();
let client;
let transport;

// Independently encode a solid reference image. Pixel comparison catches the
// original valid-PNG/all-black false pass; dimensions and digests alone cannot.
const solid = (width, height, color) => {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  const chunk = (name, data) => {
    const type = Buffer.from(name),
      length = Buffer.alloc(4),
      checksum = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    checksum.writeUInt32BE(crc32(Buffer.concat([type, data])));
    return Buffer.concat([length, type, data, checksum]);
  };
  const rows = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y++)
    for (let x = 0; x < width; x++)
      rows.set([...color, 255], y * (width * 4 + 1) + 1 + x * 4);
  const bytes = Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(rows)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
  return {
    media_type: "image/png",
    bytes: bytes.length,
    sha256: digest(bytes),
    data_base64: bytes.toString("base64"),
  };
};
const pixels = (image, color) => {
  const expected = solid(image.width, image.height, color);
  const comparison = comparePngScreenshots({
    before: image,
    after: expected,
    channel_threshold: 3,
  });
  assert.ok(
    comparison.changed_ratio < 0.08,
    "Captured pixels do not match the source-owned painted window",
  );
  return comparison.changed_ratio;
};

const launch = async (mode = "normal") => {
  const process = new WindowsOwnedProcess(
    fixturePath,
    [mode],
    dirname(fixturePath),
    environment,
    false,
    { protocolStdin: true, memoryLimitBytes: 128 * 1024 * 1024 },
  );
  owned.add(process);
  const lines = [];
  let buffered = "";
  process.on("error", () => {});
  process.stdout.on("data", (chunk) => {
    buffered += chunk;
    assert.ok(buffered.length < 8192, "Fixture protocol exceeded its budget");
    let end;
    while ((end = buffered.indexOf("\n")) !== -1) {
      lines.push(JSON.parse(buffered.slice(0, end)));
      buffered = buffered.slice(end + 1);
    }
  });
  const next = async () => {
    const until = performance.now() + 10000;
    while (lines.length === 0) {
      assert.ok(
        performance.now() < until && process.exitCode === null,
        "Window fixture failed before readiness",
      );
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return lines.shift();
  };
  return {
    process,
    identity: await next(),
    next,
    command: (value) =>
      new Promise((resolve, reject) =>
        process.stdin.write(value + "\n", (error) =>
          error ? reject(error) : resolve(),
        ),
      ),
  };
};
const stop = async (fixture) => {
  const result = await fixture.process.cleanup();
  assert.equal(
    result.cleaned,
    true,
    "Owned GUI fixture cleanup remains incomplete",
  );
  owned.delete(fixture.process);
};
const call = async (name, arguments_) => {
  report.lastOperation = name;
  const started = performance.now();
  const response = await client.callTool(
    { name, arguments: arguments_ },
    { timeout: 60000 },
  );
  report.metrics.push({
    name,
    elapsedMs: performance.now() - started,
    wireBytes: Buffer.byteLength(JSON.stringify(response)),
  });
  return response;
};
const outputOf = (response, name) => {
  assert.notEqual(
    response.isError,
    true,
    `${name} refused the selected fixture`,
  );
  return toolContract(name).outputSchema.parse(response.structuredContent);
};
const refusal = (response, expected) => {
  assert.equal(response.isError, true);
  const text = response.content.find((item) => item.type === "text").text;
  const value = JSON.parse(text);
  assert.equal(value.error.code, expected, JSON.stringify(value.error));
};
try {
  transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(packageRoot, "scripts/rea.mjs"), "mcp"],
    env: environment,
    stderr: "pipe",
  });
  // Drain diagnostics without retaining ambient paths or serializing them into
  // the report. The process supervisor owns the helper diagnostics internally.
  transport.stderr?.resume();
  client = new Client({ name: "rea-selected-window-acceptance", version: "1" });
  await client.connect(transport);
  transport.stderr?.resume();
  const first = await launch();
  outputOf(await call("open_binary", { path: fixturePath }), "open_binary");
  const input = {
    pid: first.identity.pid,
    window_handle: first.identity.window_handle,
    max_dimension: 320,
  };
  const summary = outputOf(
    await call("capture_windows_window_screenshot", input),
    "capture_windows_window_screenshot",
  );
  assert.equal(summary.normalized_result.kind, "summary");
  assert.equal(JSON.stringify(summary).includes("data_base64"), false);
  const imageView = outputOf(
    await call("inspect_analysis_view", {
      source: {
        kind: "retained-evidence",
        evidence_id: summary.normalized_result.parent_evidence_id,
      },
      view: { kind: "windows-window", facet: "screenshot" },
    }),
    "inspect_analysis_view",
  ).normalized_result;
  report.cases.firstFramePixelDifference = pixels(
    imageView.item,
    [40, 120, 200],
  );
  assert.equal(imageView.item.source_width, first.identity.width);
  assert.equal(imageView.item.source_height, first.identity.height);
  await first.command("change");
  assert.equal((await first.next()).event, "changed");
  const changed = outputOf(
    await call("capture_windows_window_screenshot", {
      ...input,
      detail: "complete",
    }),
    "capture_windows_window_screenshot",
  );
  report.cases.freshFramePixelDifference = pixels(
    changed.normalized_result.screenshot,
    [80, 180, 40],
  );
  assert.notEqual(
    changed.normalized_result.screenshot.sha256,
    imageView.item.sha256,
  );
  const reread = outputOf(
    await call("inspect_analysis_view", {
      source: {
        kind: "retained-evidence",
        evidence_id: summary.normalized_result.parent_evidence_id,
      },
      view: { kind: "windows-window", facet: "screenshot" },
    }),
    "inspect_analysis_view",
  );
  assert.equal(reread.normalized_result.item.sha256, imageView.item.sha256);
  report.cases.retainedFrameImmutable = true;
  refusal(
    await call("capture_windows_window_screenshot", {
      ...input,
      pid: process.pid,
    }),
    "invalid_request",
  );
  report.cases.wrongPidRefused = true;
  const cli = await exec(
    process.execPath,
    [
      join(packageRoot, "scripts/rea.mjs"),
      "capture-windows-window-screenshot",
      fixturePath,
      "--pid",
      String(input.pid),
      "--window-handle",
      input.window_handle,
      "--max-dimension",
      "320",
      "--json",
    ],
    {
      env: environment,
      timeout: 60000,
      maxBuffer: 10 * 1024 * 1024,
      windowsHide: true,
    },
  );
  const cliEvidence = toolContract(
    "capture_windows_window_screenshot",
  ).outputSchema.parse(JSON.parse(cli.stdout));
  pixels(cliEvidence.normalized_result.screenshot, [80, 180, 40]);
  report.cases.cliPixelsAndContract = true;
  await stop(first);
  refusal(
    await call("capture_windows_window_screenshot", input),
    "invalid_request",
  );
  report.cases.destroyedWindowRefused = true;
  const ansi = await launch("ansi");
  const ansiFrame = outputOf(
    await call("capture_windows_window_screenshot", {
      pid: ansi.identity.pid,
      window_handle: ansi.identity.window_handle,
      max_dimension: 320,
      detail: "complete",
    }),
    "capture_windows_window_screenshot",
  );
  pixels(ansiFrame.normalized_result.screenshot, [40, 120, 200]);
  report.cases.ansiTitle = {
    estimate: ansi.identity.title_length_estimate,
    copied: ansi.identity.title_copied,
  };
  await stop(ansi);
  const oversized = await launch("large");
  assert.ok(
    oversized.identity.width * oversized.identity.height > 4 * 1024 * 1024,
  );
  refusal(
    await call("capture_windows_window_screenshot", {
      pid: oversized.identity.pid,
      window_handle: oversized.identity.window_handle,
    }),
    "resource_constraint",
  );
  report.cases.sourcePixelLimit = true;
  await stop(oversized);
  const noisy = await launch("noise");
  const noisyInput = {
    pid: noisy.identity.pid,
    window_handle: noisy.identity.window_handle,
  };
  refusal(
    await call("capture_windows_window_screenshot", noisyInput),
    "resource_constraint",
  );
  const noiseSummary = outputOf(
    await call("capture_windows_window_screenshot", {
      ...noisyInput,
      max_dimension: 512,
    }),
    "capture_windows_window_screenshot",
  );
  const summaryBytes = report.metrics.at(-1).wireBytes;
  const noiseImage = outputOf(
    await call("inspect_analysis_view", {
      source: {
        kind: "retained-evidence",
        evidence_id: noiseSummary.normalized_result.parent_evidence_id,
      },
      view: { kind: "windows-window", facet: "screenshot" },
    }),
    "inspect_analysis_view",
  ).normalized_result.item;
  const imageBytes = report.metrics.at(-1).wireBytes;
  assert.ok(noiseImage.bytes > 16000 && imageBytes > summaryBytes * 10);
  assert.equal(noiseImage.width, 512);
  report.cases.pngCapacityAndRetry = {
    pngBytes: noiseImage.bytes,
    summaryWireBytes: summaryBytes,
    imageWireBytes: imageBytes,
  };
  await stop(noisy);
  const blocked = await launch();
  await blocked.command("block");
  assert.equal((await blocked.next()).event, "blocking");
  const controller = new AbortController();
  const reason = "REA selected-window acceptance cancellation";
  const send = transport.send.bind(transport);
  // Cancel after the selected request was written, instead of racing a cached
  // compositor response or cancelling an RPC that never left the client.
  transport.send = async (message, options) => {
    await send(message, options);
    if (
      message.method === "tools/call" &&
      message.params.name === "capture_windows_window_screenshot" &&
      message.params.arguments.pid === blocked.identity.pid
    )
      controller.abort(reason);
  };
  const pending = client.callTool(
    {
      name: "capture_windows_window_screenshot",
      arguments: {
        pid: blocked.identity.pid,
        window_handle: blocked.identity.window_handle,
      },
    },
    { signal: controller.signal, timeout: 60000 },
  );
  try {
    await assert.rejects(
      pending,
      (cause) => cause instanceof Error && cause.message === reason,
    );
  } finally {
    transport.send = send;
    await stop(blocked);
  }
  const recovery = await launch();
  let attempts = 0;
  while (true) {
    const response = await call("capture_windows_window_screenshot", {
      pid: recovery.identity.pid,
      window_handle: recovery.identity.window_handle,
      max_dimension: 320,
      detail: "complete",
    });
    attempts++;
    if (response.isError !== true) {
      pixels(
        outputOf(response, "capture_windows_window_screenshot")
          .normalized_result.screenshot,
        [40, 120, 200],
      );
      break;
    }
    refusal(response, "resource_constraint");
    assert.ok(
      attempts < 10,
      "Cancelled helper did not release capture admission",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  report.cases.cancellationAndRecovery = { attempts };
  await stop(recovery);
  const copy = join(root, "identical-other-file.exe");
  await copyFile(fixturePath, copy);
  const other = await launch();
  outputOf(await call("open_binary", { path: copy }), "open_binary");
  refusal(
    await call("capture_windows_window_screenshot", {
      pid: other.identity.pid,
      window_handle: other.identity.window_handle,
      detail: "complete",
    }),
    "invalid_request",
  );
  report.cases.identicalBytesDifferentFileRefused = true;
  await stop(other);
  outputOf(await call("close_binary", {}), "close_binary");
  await client.close();
  client = undefined;
  assert.equal(digest(await readFile(fixturePath)), original);
  report.cases.fixtureUnchanged = true;
  report.runtimeResidualCount = (await readdir(runtime)).length;
  assert.equal(report.runtimeResidualCount, 0);
  report.ok = true;
} catch (cause) {
  report.failure = {
    name: cause instanceof Error ? cause.name : "UnknownError",
    message: cause instanceof Error ? cause.message : String(cause),
  };
  throw cause;
} finally {
  const cleanupFailures = [];
  try {
    await client?.close();
  } catch (cause) {
    cleanupFailures.push(cause);
  }
  for (const process of owned) {
    try {
      const stopped = await process.cleanup();
      if (!stopped.cleaned)
        throw new Error("Owned GUI fixture cleanup remains incomplete");
      owned.delete(process);
    } catch (cause) {
      cleanupFailures.push(cause);
    }
  }
  // Do not erase ownership evidence if any process cleanup remains unverified.
  if (cleanupFailures.length === 0) {
    await rm(root, { recursive: true, force: true });
    report.workspaceCleanup = true;
  } else {
    report.ok = false;
    report.workspaceCleanup = false;
    report.cleanupFailureCount = cleanupFailures.length;
  }
  if (reportArgument !== undefined)
    await writeFile(reportArgument, JSON.stringify(report, null, 2) + "\n");
  if (cleanupFailures.length !== 0)
    throw new AggregateError(
      cleanupFailures,
      "Acceptance cleanup remains incomplete; retain its workspace",
    );
}

process.stdout.write(JSON.stringify(report) + "\n");
