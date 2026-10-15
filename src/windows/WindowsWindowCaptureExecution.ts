import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";

import {
  AnalysisCancelledError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisCleanupObservation } from "../domain/analysisErrorBase.js";
import { decodeCanonicalBase64 } from "../domain/webScreenshot.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import {
  WINDOWS_CAPTURE_REPLY_BYTES,
  WINDOWS_CAPTURE_TIMEOUT_MS,
  windowsCaptureReplySchema,
  windowsCaptureRequestSchema,
} from "./WindowsWindowCaptureProtocol.js";
import type { z } from "zod";

const operation = "capture_windows_window_screenshot";
let active = false;
const retained = new Map<ProviderProcessSupervisor, readonly string[]>();

/** Retry exact retained owners, never a PID or image-name lookup. */
export const retryWindowsCaptureCleanup = async (): Promise<
  AnalysisCleanupObservation | undefined
> => {
  let reason: string | undefined;
  for (const [owner] of retained) {
    try {
      const result = await owner.stop();
      if (result.status !== "incomplete") retained.delete(owner);
      else reason ??= result.reason;
    } catch (cause: unknown) {
      reason ??= cause instanceof Error ? cause.message : String(cause);
    }
  }
  if (retained.size === 0) return undefined;
  return {
    reason: reason ?? "Selected-window helper cleanup remains incomplete.",
    resources: [...retained.values()].flat(),
  };
};

/** Isolate the blocking OS API in one bounded, supervised helper at a time. */
export const executeWindowsCapture = async (
  request: z.output<typeof windowsCaptureRequestSchema>,
  selectedEnvironment: Readonly<NodeJS.ProcessEnv>,
  signal?: AbortSignal,
): Promise<unknown> => {
  if (active)
    throw new AnalysisResourceConstraintError(
      operation,
      "capacity",
      "Another selected-window capture is still active.",
      { maximum_concurrent_captures: 1 },
    );
  active = true;
  try {
    const cleanup = await retryWindowsCaptureCleanup();
    if (cleanup !== undefined)
      throw new AnalysisOutputError(operation, cleanup.reason, { cleanup });
    // Preserve inherited values without allowing ambient Node options to run
    // preload scripts or replace this helper's explicit heap limit.
    const environment = Object.fromEntries(
      Object.entries(selectedEnvironment).filter(
        ([name]) => name.toUpperCase() !== "NODE_OPTIONS",
      ),
    );
    const snapshot = await runOwnedCommand(
      {
        command: process.execPath,
        arguments: [
          "--max-old-space-size=64",
          fileURLToPath(
            new URL("../windows-capture-runtime/worker.js", import.meta.url),
          ),
        ],
        runId: `rea-window-capture-${randomUUID()}`,
        expectedCommand: null,
        hostEnvironment: environment,
        memoryLimitBytes: 256 * 1024 * 1024,
      },
      {
        timeoutMs: WINDOWS_CAPTURE_TIMEOUT_MS,
        diagnosticBytes: WINDOWS_CAPTURE_REPLY_BYTES,
      },
      {
        signal,
        input: Buffer.from(
          JSON.stringify(windowsCaptureRequestSchema.parse(request)),
          "utf8",
        ),
      },
    );
    const value: unknown = JSON.parse(snapshot.stdout.text);
    const reply = windowsCaptureReplySchema.parse(value);
    if (!reply.ok) {
      if (reply.failure === null)
        throw new AnalysisOutputError(operation, reply.message);
      throw Object.assign(new Error(reply.message), reply.failure);
    }
    const { png_base64, ...capture } = reply.capture;
    const png = decodeCanonicalBase64(png_base64);
    if (png === undefined)
      throw new AnalysisOutputError(
        operation,
        "Capture helper returned invalid PNG base64.",
      );
    return { ...capture, png };
  } catch (cause: unknown) {
    if (!(cause instanceof OwnedCommandFailure)) throw cause;
    let cleanup: AnalysisCleanupObservation | undefined;
    if (cause.cleanupOwner !== undefined) {
      retained.set(cause.cleanupOwner, cause.resources);
      cleanup = {
        reason:
          cause.cleanupFailure ??
          "Selected-window helper cleanup remains incomplete.",
        resources: cause.resources,
      };
    }
    const options = { cause, ...(cleanup === undefined ? {} : { cleanup }) };
    if (cause.reason === "cancelled")
      throw new AnalysisCancelledError(operation, options);
    if (cause.reason === "timeout")
      throw new AnalysisTimeoutError(
        operation,
        WINDOWS_CAPTURE_TIMEOUT_MS,
        options,
      );
    if (cause.snapshot?.memoryLimitReached === true)
      throw new AnalysisResourceConstraintError(
        operation,
        "memory",
        cause.message,
        { maximum_helper_commit_bytes: 256 * 1024 * 1024 },
        options,
      );
    if (cause.reason === "output-limit")
      throw new AnalysisResourceConstraintError(
        operation,
        "transport",
        cause.message,
        { maximum_helper_reply_bytes: WINDOWS_CAPTURE_REPLY_BYTES },
        options,
      );
    throw new AnalysisOutputError(
      operation,
      "Selected-window capture helper failed.",
      options,
    );
  } finally {
    active = false;
  }
};
