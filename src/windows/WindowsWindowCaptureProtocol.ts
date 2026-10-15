import { z } from "zod";

import {
  MAX_WINDOWS_WINDOW_PNG_BYTES,
  windowsWindowScreenshotInputSchema,
} from "../domain/native/windowsWindowScreenshot.js";

export const WINDOWS_CAPTURE_TIMEOUT_MS = 5000;
const MAX_WINDOWS_TEXT_UNITS = 32767;
export const WINDOWS_CAPTURE_REQUEST_BYTES = MAX_WINDOWS_TEXT_UNITS * 6 + 4096;
// Title and image path can each expand to six ASCII bytes per UTF-16 unit
// under JSON escaping. Reserve the remaining fixed fields independently.
export const WINDOWS_CAPTURE_REPLY_BYTES =
  4 * Math.ceil(MAX_WINDOWS_WINDOW_PNG_BYTES / 3) +
  2 * MAX_WINDOWS_TEXT_UNITS * 6 +
  4096;

/** Private process protocol; identity is validated again by the native owner. */
export const windowsCaptureRequestSchema = z.strictObject({
  ...windowsWindowScreenshotInputSchema.shape,
  target_path: z.string().min(1).max(MAX_WINDOWS_TEXT_UNITS),
  target_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  target_file_identity: z.string().min(1).max(32),
});

const identityFields = {
  pid: windowsWindowScreenshotInputSchema.shape.pid,
  window_handle: windowsWindowScreenshotInputSchema.shape.window_handle,
  process_image_path: z.string().min(1).max(MAX_WINDOWS_TEXT_UNITS),
  process_start_time_unix_ms: z.number().int().nonnegative(),
  title: z.string().max(MAX_WINDOWS_TEXT_UNITS),
  source_width: z
    .number()
    .int()
    .positive()
    .max(4 * 1024 * 1024),
  source_height: z
    .number()
    .int()
    .positive()
    .max(4 * 1024 * 1024),
  width: z.number().int().positive().max(4096),
  height: z.number().int().positive().max(4096),
};

export const nativeWindowsCaptureSchema = z.strictObject({
  ...identityFields,
  png: z.custom<Buffer>(
    (value) =>
      Buffer.isBuffer(value) &&
      value.byteLength > 0 &&
      value.byteLength <= MAX_WINDOWS_WINDOW_PNG_BYTES,
    "Expected a native PNG buffer within the retained byte limit",
  ),
});

/** Typed producer reasons keep request refusals out of capability state. */
export const windowsCaptureFailureSchema = z.object({
  win32Code: z.number().int().nonnegative(),
  requestedPath: z.string().exactOptional(),
  failureKind: z
    .enum([
      "artifact_changed",
      "window_owner_mismatch",
      "window_state",
      "process_identity_mismatch",
      "source_pixel_limit",
    ])
    .exactOptional(),
});

export const windowsCaptureReplySchema = z.discriminatedUnion("ok", [
  z.strictObject({
    ok: z.literal(true),
    capture: z.strictObject({
      ...identityFields,
      png_base64: z
        .string()
        .min(4)
        .max(4 * Math.ceil(MAX_WINDOWS_WINDOW_PNG_BYTES / 3)),
    }),
  }),
  z.strictObject({
    ok: z.literal(false),
    message: z.string(),
    failure: windowsCaptureFailureSchema.nullable(),
  }),
]);
