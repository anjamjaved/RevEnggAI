import { createHash } from "node:crypto";
import { stat } from "node:fs/promises";

import { z } from "zod";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisProvider,
  type CapabilityDescriptor,
  type ExecutionOptions,
  type ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  openRegularFile,
  RegularFileAdmissionFailure,
  RegularFileChangedError,
  sameRegularFileState,
} from "../filesystem/RegularFile.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import {
  AnalysisError,
  type AnalysisCleanupObservation,
} from "../domain/analysisErrorBase.js";
import {
  MAX_WINDOWS_WINDOW_PNG_BYTES,
  windowsWindowPngSchema,
  windowsWindowScreenshotInputSchema,
  windowsWindowScreenshotResultSchema,
  type WindowsWindowScreenshotResult,
} from "../domain/native/windowsWindowScreenshot.js";
import { err, ok, type Result } from "../domain/result.js";
import { requireWindowsWindowCaptureAuthority } from "./WindowsNativeLoader.js";
import {
  executeWindowsCapture,
  retryWindowsCaptureCleanup,
} from "./WindowsWindowCaptureExecution.js";
import {
  nativeWindowsCaptureSchema,
  windowsCaptureFailureSchema,
} from "./WindowsWindowCaptureProtocol.js";
import {
  NATIVE_WINDOWS_UI_PROVIDER_IDENTITY as IDENTITY,
  nativeWindowsUiCapabilities,
} from "./NativeWindowsUiProviderMetadata.js";

const OPERATION = "capture_windows_window_screenshot" as const;
const MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024;

interface ExecutableIdentity {
  readonly fileIdentity: string;
  readonly sha256: string;
}

type ExecutableIdentityOutcome =
  | { readonly kind: "completed"; readonly value: ExecutableIdentity }
  | { readonly kind: "failed"; readonly cause: unknown };

/** Preserves both identity outcome and a descriptor whose close is unconfirmed. */
class ExecutableIdentityCleanupFailure extends Error {
  constructor(
    readonly path: string,
    readonly owner: OwnedFileHandle,
    readonly outcome: ExecutableIdentityOutcome,
    readonly cleanupCause: unknown,
  ) {
    super(`Selected executable descriptor cleanup failed: ${path}`, {
      cause: outcome.kind === "failed" ? outcome.cause : cleanupCause,
    });
    this.name = "ExecutableIdentityCleanupFailure";
  }
}

const retainedExecutableIdentityHandles = new Map<OwnedFileHandle, string>();

const retainExecutableIdentityHandle = (
  owner: OwnedFileHandle,
  path: string,
): void => {
  retainedExecutableIdentityHandles.set(owner, path);
};

/** Retry every retained owner before admitting more target-identity work. */
const retryRetainedExecutableIdentityHandles = async (): Promise<
  AnalysisCleanupObservation | undefined
> => {
  let failure: unknown;
  for (const [owner] of retainedExecutableIdentityHandles) {
    try {
      await owner.close();
      retainedExecutableIdentityHandles.delete(owner);
    } catch (cause: unknown) {
      failure ??= cause;
    }
  }
  if (retainedExecutableIdentityHandles.size === 0) return undefined;
  return {
    reason: `Selected executable descriptor cleanup remains incomplete: ${failureReason(failure)}`,
    resources: [...new Set(retainedExecutableIdentityHandles.values())],
  };
};

const incompleteExecutableIdentityCleanupError = (
  cleanup: AnalysisCleanupObservation,
): AnalysisOutputError =>
  new AnalysisOutputError(
    OPERATION,
    "Previous selected executable descriptor cleanup remains incomplete.",
    { cleanup },
  );

/** Narrow test seam: no test needs a Windows desktop or a packaged addon. */
export interface WindowsWindowCaptureHost {
  capture(
    pid: number,
    windowHandle: string,
    maximumDimension: number,
    targetIdentity: {
      readonly path: string;
      readonly sha256: string;
      readonly fileIdentity: string;
    },
    signal?: AbortSignal,
  ): unknown;
  identifyExecutable(
    path: string,
    signal?: AbortSignal,
  ): Promise<ExecutableIdentity>;
}

const systemCaptureHost = (
  environment: Readonly<NodeJS.ProcessEnv>,
): WindowsWindowCaptureHost => ({
  capture: async (
    pid,
    windowHandle,
    maximumDimension,
    targetIdentity,
    signal,
  ) => {
    try {
      requireWindowsWindowCaptureAuthority();
    } catch (cause) {
      throw new AnalysisCapabilityUnavailableError(
        IDENTITY.id,
        OPERATION,
        nativeFailureReason(cause),
        { cause },
      );
    }
    return executeWindowsCapture(
      {
        pid,
        window_handle: windowHandle,
        max_dimension: maximumDimension,
        target_path: targetIdentity.path,
        target_sha256: targetIdentity.sha256,
        target_file_identity: targetIdentity.fileIdentity,
      },
      environment,
      signal,
    );
  },
  identifyExecutable: hashExecutable,
});

/** Optional auxiliary provider for one passive, target-bound Windows PNG observation. */
export class NativeWindowsUiProvider implements AnalysisProvider {
  readonly #capabilities: readonly CapabilityDescriptor[];

  constructor(
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
    private readonly captureHost: WindowsWindowCaptureHost = systemCaptureHost(
      environment,
    ),
    platform: NodeJS.Platform = process.platform,
  ) {
    this.#capabilities = nativeWindowsUiCapabilities(platform);
  }

  identity(): ProviderIdentity {
    return IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return this.#capabilities;
  }

  createClient(target: BinaryTarget): AnalysisClient {
    return {
      execute: async (operation, parameters, options) => {
        if (operation === "health")
          return ok(createAnalysisExecution(null, IDENTITY));
        if (operation !== OPERATION)
          return err(
            new AnalysisCapabilityUnavailableError(
              IDENTITY.id,
              operation,
              "Operation is not implemented by the Windows selected-window adapter.",
            ),
          );
        const result = await captureWindowsWindowScreenshot(
          target,
          parameters,
          this.captureHost,
          options,
        );
        return result.ok
          ? ok(
              createAnalysisExecution(result.value, IDENTITY, {
                limitations: [
                  "One target-bound client-area frame was requested through PrintWindow; no desktop, region, title-search, or input fallback exists.",
                  "GPU-composited, minimized, protected, elevated, or custom-drawn windows can refuse or incompletely render PrintWindow; a successful PNG does not prove what was visible on a physical display.",
                  "PrintWindow can execute the selected process's paint handler, which can change UI state or cause target filesystem and network effects. The title and PNG can contain private application data and REA retains them only in returned Evidence for this selected window.",
                  "The selected on-disk executable matched the active target before and after capture. That comparison does not prove every byte originally mapped into the process.",
                ],
              }),
            )
          : result;
      },
      close: async () => {
        const cleanups = await Promise.all([
          retryRetainedExecutableIdentityHandles(),
          retryWindowsCaptureCleanup(),
        ]);
        const incomplete = cleanups.filter((cleanup) => cleanup !== undefined);
        return incomplete.length === 0
          ? ok(null)
          : err(
              incompleteExecutableIdentityCleanupError({
                reason: incomplete.map((cleanup) => cleanup.reason).join("; "),
                resources: incomplete.flatMap((cleanup) => cleanup.resources),
              }),
            );
      },
    };
  }
}

/** Validate target identity around one short native capture without broad fallback. */
export const captureWindowsWindowScreenshot = async (
  target: BinaryTarget,
  parameters: Readonly<Record<string, unknown>>,
  host: WindowsWindowCaptureHost = systemCaptureHost(process.env),
  options: ExecutionOptions = {},
): Promise<Result<WindowsWindowScreenshotResult, AnalysisError>> => {
  if (options.signal?.aborted)
    return err(new AnalysisCancelledError(OPERATION));
  const input = windowsWindowScreenshotInputSchema.safeParse(parameters);
  if (!input.success)
    return err(
      analysisInputErrorFromIssues(OPERATION, input.error.issues, parameters, {
        cause: input.error,
      }),
    );
  if (
    target.kind !== "executable" ||
    target.format !== "pe" ||
    target.executableRole !== "application"
  )
    return err(
      new AnalysisCapabilityUnavailableError(
        IDENTITY.id,
        OPERATION,
        "Selected-window capture requires an active PE application target.",
      ),
    );
  let before: ExecutableIdentity;
  try {
    before = await host.identifyExecutable(target.path, options.signal);
  } catch (cause) {
    return err(identityError(target.path, cause, options.signal));
  }
  if (before.sha256 !== target.sha256)
    return err(
      new AnalysisArtifactChangedError(
        OPERATION,
        target.path,
        "The active target bytes no longer match its opened SHA-256 identity.",
      ),
    );
  if (options.signal?.aborted)
    return err(new AnalysisCancelledError(OPERATION));

  let reply: unknown;
  try {
    reply = await host.capture(
      input.data.pid,
      input.data.window_handle,
      input.data.max_dimension,
      {
        path: target.path,
        sha256: target.sha256,
        fileIdentity: before.fileIdentity,
      },
      options.signal,
    );
  } catch (cause) {
    return err(
      captureFailure(
        target.path,
        input.data.pid,
        input.data.window_handle,
        cause,
      ),
    );
  }
  const parsed = nativeWindowsCaptureSchema.safeParse(reply);
  if (!parsed.success)
    return err(
      new AnalysisOutputError(
        OPERATION,
        "Native capture returned malformed output.",
        { cause: parsed.error },
      ),
    );
  const raw = parsed.data;
  if (options.signal?.aborted)
    return err(new AnalysisCancelledError(OPERATION));
  if (
    raw.pid !== input.data.pid ||
    raw.window_handle !== input.data.window_handle
  )
    return err(
      new AnalysisOutputError(
        OPERATION,
        "Native capture returned a different process or window handle.",
      ),
    );
  if (
    raw.width > input.data.max_dimension ||
    raw.height > input.data.max_dimension ||
    raw.width > raw.source_width ||
    raw.height > raw.source_height ||
    raw.source_width * raw.source_height > 4 * 1024 * 1024
  )
    return err(
      new AnalysisOutputError(
        OPERATION,
        "Native capture violated the declared pixel bounds.",
      ),
    );

  const [targetIdentity, processIdentity] = await Promise.allSettled([
    host.identifyExecutable(target.path, options.signal),
    host.identifyExecutable(raw.process_image_path, options.signal),
  ]);
  if (
    targetIdentity.status === "rejected" ||
    processIdentity.status === "rejected"
  ) {
    // Both settled errors own resources independently. Project both before
    // selecting a primary result, otherwise the second admission failure can
    // lose its descriptor owner and never receive a cleanup retry.
    const targetIdentityError =
      targetIdentity.status === "rejected"
        ? identityError(target.path, targetIdentity.reason, options.signal)
        : undefined;
    const processIdentityError =
      processIdentity.status === "rejected"
        ? identityError(
            raw.process_image_path,
            processIdentity.reason,
            options.signal,
          )
        : undefined;
    if (targetIdentityError !== undefined) {
      if (processIdentityError !== undefined)
        targetIdentityError.retainSecondaryFailure(processIdentityError, {
          process_identity_error: processIdentityError.message,
        });
      return err(
        withCleanup(targetIdentityError, processIdentityError?.cleanup),
      );
    }
    if (processIdentityError !== undefined) return err(processIdentityError);
    return err(
      new AnalysisOutputError(
        OPERATION,
        "Selected executable identity checks failed without a reported cause.",
      ),
    );
  }
  const afterTarget = targetIdentity.value;
  const processImage = processIdentity.value;
  if (options.signal?.aborted)
    return err(new AnalysisCancelledError(OPERATION));
  if (
    afterTarget.sha256 !== target.sha256 ||
    afterTarget.fileIdentity !== before.fileIdentity
  )
    return err(
      new AnalysisArtifactChangedError(
        OPERATION,
        target.path,
        "The active target path or bytes changed during capture.",
      ),
    );
  if (
    processImage.sha256 !== target.sha256 ||
    processImage.fileIdentity !== before.fileIdentity
  )
    return err(
      analysisInputErrorFromIssues(
        OPERATION,
        [
          {
            path: ["pid"],
            code: "custom",
            message: "Selected PID does not map to the active PE target bytes.",
          },
        ],
        parameters,
      ),
    );

  try {
    const screenshot = windowsWindowPngSchema.parse({
      media_type: "image/png",
      data_base64: raw.png.toString("base64"),
      sha256: createHash("sha256").update(raw.png).digest("hex"),
      bytes: raw.png.byteLength,
      width: raw.width,
      height: raw.height,
      source_width: raw.source_width,
      source_height: raw.source_height,
    });
    return ok(
      windowsWindowScreenshotResultSchema.parse({
        target_sha256: target.sha256,
        window: {
          pid: raw.pid,
          window_handle: raw.window_handle,
          executable: target.path,
          process_image_path: raw.process_image_path,
          process_start_time_unix_ms: raw.process_start_time_unix_ms,
          title: raw.title,
        },
        screenshot,
        gaps: [
          "Accessibility-tree capture and UI actions are unavailable in this screenshot-only Windows capability.",
        ],
      }),
    );
  } catch (cause) {
    return err(
      new AnalysisOutputError(
        OPERATION,
        "Native capture returned an invalid PNG result.",
        { cause },
      ),
    );
  }
};

const hashExecutable = async (
  path: string,
  signal?: AbortSignal,
): Promise<ExecutableIdentity> => {
  const priorCleanup = await retryRetainedExecutableIdentityHandles();
  if (priorCleanup !== undefined)
    throw incompleteExecutableIdentityCleanupError(priorCleanup);
  const handle = await openRegularFile(path, { symlinks: "follow", signal });
  const owner = new OwnedFileHandle(handle);
  let outcome: ExecutableIdentityOutcome;
  try {
    const metadata = await handle.stat({ bigint: true });
    if (metadata.ino === 0n)
      throw new AnalysisOutputError(
        OPERATION,
        "The host did not report stable executable file identity.",
      );
    if (metadata.size > BigInt(MAX_EXECUTABLE_BYTES))
      throw new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        "Selected executable exceeds the 256 MiB target-identity budget.",
        { maximum_bytes: MAX_EXECUTABLE_BYTES },
      );
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    const size = Number(metadata.size);
    while (position < size) {
      if (signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      const { bytesRead } = await handle.read(
        buffer,
        0,
        buffer.byteLength,
        position,
      );
      if (signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      if (bytesRead === 0) break;
      digest.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    if (signal?.aborted) throw new AnalysisCancelledError(OPERATION);
    if (position !== size) throw new RegularFileChangedError(path);
    const [opened, currentPath] = await Promise.all([
      handle.stat({ bigint: true }),
      stat(path, { bigint: true }),
    ]);
    if (
      !sameRegularFileState(metadata, opened) ||
      !sameRegularFileState(metadata, currentPath)
    )
      throw new RegularFileChangedError(path);
    outcome = {
      kind: "completed",
      value: {
        fileIdentity: `${String(metadata.dev)}:${String(metadata.ino)}`,
        sha256: digest.digest("hex"),
      },
    };
  } catch (cause: unknown) {
    outcome = { kind: "failed", cause };
  }
  try {
    await owner.close();
  } catch (cleanupCause: unknown) {
    retainExecutableIdentityHandle(owner, path);
    throw new ExecutableIdentityCleanupFailure(
      path,
      owner,
      outcome,
      cleanupCause,
    );
  }
  if (outcome.kind === "failed") throw outcome.cause;
  return outcome.value;
};

/** Narrow descriptor-cleanup test seam; production reaches this through the host. */
export const hashWindowsCaptureExecutable = hashExecutable;

const identityError = (
  path: string,
  cause: unknown,
  signal?: AbortSignal,
): AnalysisError => {
  let cleanup: AnalysisCleanupObservation | undefined;
  if (cause instanceof RegularFileAdmissionFailure) {
    retainExecutableIdentityHandle(cause.owner, path);
    cleanup = {
      reason: `Selected executable descriptor close failed: ${failureReason(cause.cleanupCause)}`,
      resources: [path],
    };
    cause = cause.cause;
  } else if (cause instanceof ExecutableIdentityCleanupFailure) {
    cleanup = {
      reason: `Selected executable descriptor close failed: ${failureReason(cause.cleanupCause)}`,
      resources: [cause.path],
    };
    cause =
      cause.outcome.kind === "failed"
        ? cause.outcome.cause
        : cause.cleanupCause;
  }
  const options = {
    cause,
    ...(cleanup === undefined ? {} : { cleanup }),
  };
  if (
    signal?.aborted === true ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, options);
  if (cause instanceof AnalysisError) return withCleanup(cause, cleanup);
  if (cause instanceof RegularFileChangedError)
    return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
      ...options,
    });
  const filesystem = z.object({ code: z.string() }).safeParse(cause);
  if (filesystem.success) {
    if (filesystem.data.code === "EACCES" || filesystem.data.code === "EPERM")
      return new AnalysisAccessDeniedError(
        OPERATION,
        path,
        filesystem.data.code,
        options,
      );
    if (filesystem.data.code === "ENOENT" || filesystem.data.code === "ESTALE")
      return new AnalysisArtifactChangedError(
        OPERATION,
        path,
        "Selected executable is no longer available.",
        options,
      );
  }
  return new AnalysisOutputError(
    OPERATION,
    `Cannot establish selected executable identity: ${cause instanceof Error ? cause.message : String(cause)}`,
    options,
  );
};

const failureReason = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

/** Keep the primary typed error while surfacing unconfirmed descriptor cleanup. */
const withCleanup = (
  error: AnalysisError,
  cleanup: AnalysisCleanupObservation | undefined,
): AnalysisError => {
  if (cleanup === undefined) return error;
  const merged =
    error.cleanup === undefined
      ? cleanup
      : {
          reason: `${error.cleanup.reason}; ${cleanup.reason}`,
          resources: [
            ...new Set([...error.cleanup.resources, ...cleanup.resources]),
          ],
        };
  Object.defineProperties(error, {
    cleanup: { configurable: true, value: merged },
    cleanupIncomplete: { configurable: true, value: true },
    cleanupResources: { configurable: true, value: merged.resources },
  });
  return error;
};

const nativeFailureReason = (cause: unknown): string =>
  cause instanceof Error && cause.message.length > 0
    ? cause.message
    : "Selected window capture is unavailable on this host.";

/** Only the addon-loading owner produces capability errors; native failures stay request-scoped. */
const captureFailure = (
  path: string,
  pid: number,
  windowHandle: string,
  cause: unknown,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  const native = windowsCaptureFailureSchema.safeParse(cause);
  if (!native.success)
    return new AnalysisOutputError(OPERATION, nativeFailureReason(cause), {
      cause,
    });
  if (native.data.failureKind === "artifact_changed")
    return new AnalysisArtifactChangedError(
      OPERATION,
      path,
      nativeFailureReason(cause),
      { cause },
    );
  if (native.data.failureKind === "source_pixel_limit")
    return new AnalysisResourceConstraintError(
      OPERATION,
      "capacity",
      nativeFailureReason(cause),
      { maximum_source_pixels: 4 * 1024 * 1024 },
      {
        cause,
        remediationAction:
          "Resize the selected window below maximum_source_pixels, then retry. Lowering max_dimension does not reduce the source area.",
      },
    );
  if (
    native.data.failureKind === "window_owner_mismatch" ||
    native.data.failureKind === "window_state" ||
    native.data.failureKind === "process_identity_mismatch"
  ) {
    const field =
      native.data.failureKind === "window_owner_mismatch"
        ? "window_handle"
        : native.data.failureKind === "window_state"
          ? "window_handle"
          : "pid";
    return analysisInputErrorFromIssues(
      OPERATION,
      [{ path: [field], code: "custom", message: nativeFailureReason(cause) }],
      { pid, window_handle: windowHandle },
      { cause },
    );
  }
  const code = native.data.win32Code;
  if (code === 995) return new AnalysisCancelledError(OPERATION, { cause });
  if (
    code === 5 &&
    native.data.requestedPath !== undefined &&
    native.data.requestedPath.length > 0
  )
    return new AnalysisAccessDeniedError(
      OPERATION,
      native.data.requestedPath,
      "EACCES",
      { cause },
    );
  if (code === 5)
    return new AnalysisAccessDeniedError(OPERATION, "", "EACCES", {
      cause,
      processWindow: { pid, windowHandle },
    });
  if (code === 170)
    return new AnalysisResourceConstraintError(
      OPERATION,
      "capacity",
      nativeFailureReason(cause),
      { maximum_concurrent_captures: 1 },
      { cause },
    );
  if (code === 1460 || code === 258)
    return new AnalysisTimeoutError(OPERATION, 5000, { cause });
  // STG_E_MEDIUMFULL is the fixed retained PNG stream's capacity refusal.
  if (code === 0x80030070)
    return new AnalysisResourceConstraintError(
      OPERATION,
      "capacity",
      nativeFailureReason(cause),
      { maximum_png_bytes: MAX_WINDOWS_WINDOW_PNG_BYTES },
      { cause, remediationAction: "Retry with a smaller max_dimension." },
    );
  // Native allocation failures and HRESULT_FROM_WIN32 allocation failures.
  if ([8, 14, 1455, 0x8007000e, 0x80070008].includes(code))
    return new AnalysisResourceConstraintError(
      OPERATION,
      "memory",
      nativeFailureReason(cause),
      null,
      { cause },
    );
  if (code === 1400 || code === 6 || code === 87)
    return analysisInputErrorFromIssues(
      OPERATION,
      [
        {
          path: ["window_handle"],
          code: "custom",
          message: nativeFailureReason(cause),
        },
      ],
      { pid, window_handle: windowHandle },
      { cause },
    );
  return new AnalysisOutputError(OPERATION, nativeFailureReason(cause), {
    cause,
  });
};
