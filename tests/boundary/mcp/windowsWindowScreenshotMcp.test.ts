import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pe } from "../../../src/domain/binaryTarget.fixture.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { z } from "zod";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, expect, it } from "vitest";

import {
  createAnalysisExecution,
  type AnalysisOperationPort,
} from "../../../src/application/AnalysisProvider.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";

const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAF/gJ+Qv1aRwAAAABJRU5ErkJggg==",
  "base64",
);
const provider = {
  id: "native-windows-ui",
  name: "Windows selected-window capture",
  version: null,
} as const;
const resources: Array<{ close(): Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(resources.splice(0).map((resource) => resource.close()));
});

const result = {
  target_sha256: "a".repeat(64),
  window: {
    pid: 42,
    window_handle: "0x1234",
    executable: "C:\\Apps\\fixture.exe",
    process_image_path: "C:\\Apps\\fixture.exe",
    process_start_time_unix_ms: 1_700_000_000_000,
    title: "Fixture",
  },
  screenshot: {
    media_type: "image/png",
    data_base64: PNG.toString("base64"),
    sha256: createHash("sha256").update(PNG).digest("hex"),
    bytes: PNG.byteLength,
    width: 1,
    height: 1,
    source_width: 1,
    source_height: 1,
  },
  gaps: ["Accessibility-tree capture is unavailable."],
};
it("delivers target-bound Windows screenshot Evidence through MCP", async () => {
  const calls: Array<{
    readonly operation: string;
    readonly parameters: Readonly<Record<string, unknown>>;
  }> = [];
  const execute: AnalysisOperationPort["execute"] = (operation, parameters) => {
    calls.push({ operation, parameters });
    return Promise.resolve(ok(createAnalysisExecution(result, provider)));
  };
  const server = createServer({ kind: "fixed", analysis: { execute } });
  const client = new Client({ name: "windows-window-mcp-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  resources.push(client, server);
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const observed = await client.callTool({
    name: "capture_windows_window_screenshot",
    arguments: { pid: 42, window_handle: "0x1234", detail: "complete" },
  });

  expect(observed.isError).not.toBe(true);
  expect(calls).toEqual([
    {
      operation: "capture_windows_window_screenshot",
      parameters: {
        pid: 42,
        window_handle: "0x1234",
        max_dimension: 2048,
      },
    },
  ]);
  expect(
    toolContract("capture_windows_window_screenshot").outputSchema.parse(
      observed.structuredContent,
    ),
  ).toMatchObject({
    normalized_result: { window: { pid: 42, window_handle: "0x1234" } },
  });
});

it("defaults to a retained summary and reads the same image without recapturing", async () => {
  const directory = await createTestTempDirectory("rea-window-summary-mcp-");
  const path = join(directory, "fixture.exe");
  await writeFile(path, pe(0x8664));
  let captures = 0;
  const session = createTestBinarySession((target) => ({
    execute: async (operation) => {
      if (operation === "health")
        return ok(createAnalysisExecution(null, provider));
      expect(operation).toBe("capture_windows_window_screenshot");
      captures++;
      return ok(
        createAnalysisExecution(
          {
            ...result,
            target_sha256: target.sha256,
            window: {
              ...result.window,
              executable: target.path,
              process_image_path: target.path,
            },
          },
          provider,
        ),
      );
    },
    close: async () => ok(null),
  }));
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "windows-window-summary", version: "1" });
  resources.push(client, server, {
    close: async () => {
      await session.close();
    },
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  await client.connect(a);
  const opened = await client.callTool({
    name: "open_binary",
    arguments: { path },
  });
  expect(opened.isError).not.toBe(true);
  const summary = await client.callTool({
    name: "capture_windows_window_screenshot",
    arguments: { pid: 42, window_handle: "0x1234" },
  });
  expect(summary.isError, JSON.stringify(summary.content)).not.toBe(true);
  const parsed = toolContract(
    "capture_windows_window_screenshot",
  ).outputSchema.parse(summary.structuredContent);
  const frame = z
    .object({
      normalized_result: z.object({
        kind: z.literal("summary"),
        parent_evidence_id: z.string(),
        summary: z.object({
          screenshot: z.object({ sha256: z.string(), width: z.number() }),
        }),
      }),
    })
    .parse(parsed).normalized_result;
  expect(frame.summary.screenshot).toMatchObject({
    width: 1,
    sha256: result.screenshot.sha256,
  });
  expect(JSON.stringify(summary)).not.toContain(PNG.toString("base64"));
  expect(Buffer.byteLength(JSON.stringify(summary))).toBeLessThan(8000);
  const image = await client.callTool({
    name: "inspect_analysis_view",
    arguments: {
      source: {
        kind: "retained-evidence",
        evidence_id: frame.parent_evidence_id,
      },
      view: { kind: "windows-window", facet: "screenshot" },
    },
  });
  expect(image.isError, JSON.stringify(image.content)).not.toBe(true);
  expect(
    toolContract("inspect_analysis_view").outputSchema.parse(
      image.structuredContent,
    ),
  ).toMatchObject({
    normalized_result: { kind: "windows-window", item: result.screenshot },
  });
  expect(captures).toBe(1);
});
