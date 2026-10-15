import { createHash } from "node:crypto";

import { expect, it } from "vitest";

import {
  MAX_WINDOWS_WINDOW_PNG_BYTES,
  windowsWindowPngSchema,
  windowsWindowScreenshotInputSchema,
} from "./windowsWindowScreenshot.js";

const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAF/gJ+Qv1aRwAAAABJRU5ErkJggg==",
  "base64",
);

it("accepts a self-verifying canonical PNG for a selected Windows window", () => {
  expect(
    windowsWindowPngSchema.parse({
      media_type: "image/png",
      data_base64: PNG.toString("base64"),
      sha256: createHash("sha256").update(PNG).digest("hex"),
      bytes: PNG.byteLength,
      width: 1,
      height: 1,
      source_width: 1,
      source_height: 1,
    }),
  ).toMatchObject({ width: 1, height: 1 });
});

it("rejects a non-canonical or zero HWND before native capture", () => {
  expect(
    windowsWindowScreenshotInputSchema.safeParse({
      pid: 1,
      window_handle: "0x0001",
    }).success,
  ).toBe(false);
  expect(
    windowsWindowScreenshotInputSchema.safeParse({
      pid: 1,
      window_handle: "0x0",
    }).success,
  ).toBe(false);
});

it("rejects PNG dimensions that disagree with its IHDR", () => {
  expect(
    windowsWindowPngSchema.safeParse({
      media_type: "image/png",
      data_base64: PNG.toString("base64"),
      sha256: createHash("sha256").update(PNG).digest("hex"),
      bytes: PNG.byteLength,
      width: 2,
      height: 1,
      source_width: 2,
      source_height: 1,
    }).success,
  ).toBe(false);
});

it.each(["chunk-length", "high-bit-chunk-type"] as const)(
  "rejects a self-consistent digest with a malformed %s",
  (kind) => {
    const bytes = Buffer.from(PNG);
    if (kind === "chunk-length") bytes.writeUInt32BE(12, 8);
    else for (let index = 12; index < 16; index++) bytes[index]! |= 0x80;
    expect(
      windowsWindowPngSchema.safeParse({
        media_type: "image/png",
        data_base64: bytes.toString("base64"),
        sha256: createHash("sha256").update(bytes).digest("hex"),
        bytes: bytes.byteLength,
        width: 1,
        height: 1,
        source_width: 1,
        source_height: 1,
      }).success,
    ).toBe(false);
  },
);

it("bounds encoded PNG bytes independently of the declared size", () => {
  const result = windowsWindowPngSchema.safeParse({
    media_type: "image/png",
    data_base64: "A".repeat(
      4 * Math.ceil(MAX_WINDOWS_WINDOW_PNG_BYTES / 3) + 4,
    ),
    sha256: "a".repeat(64),
    bytes: 1,
    width: 1,
    height: 1,
    source_width: 1,
    source_height: 1,
  });
  expect(result.success).toBe(false);
  if (result.success) return;
  expect(result.error.issues).toEqual([
    expect.objectContaining({
      path: ["data_base64"],
      message: "PNG base64 exceeds the retained byte limit",
    }),
  ]);
});
