import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";

import { expect, it } from "vitest";

import { MAX_WINDOWS_WINDOW_PNG_BYTES } from "../domain/native/windowsWindowScreenshot.js";
import { encodeToolResult } from "./toolResultEncoding.js";

it("keeps the largest Windows window PNG inside the default duplicated MCP response budget", () => {
  const bytes = Buffer.alloc(MAX_WINDOWS_WINDOW_PNG_BYTES);
  const maximumPath = "C:" + "\\a".repeat(16382);
  const result = {
    subject: { local_path: maximumPath },
    normalized_result: {
      window: {
        title: "\u0001".repeat(32767),
        executable: maximumPath,
        process_image_path: maximumPath,
      },
      screenshot: { data_base64: bytes.toString("base64") },
    },
  };
  const encoded = encodeToolResult(
    result,
    STDIO_DEFAULT_MAX_BUFFER_SIZE - 1024,
  );

  expect(encoded.ok).toBe(true);
});
