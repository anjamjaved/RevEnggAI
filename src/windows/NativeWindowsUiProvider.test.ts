import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, it, vi } from "vitest";

import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { MAX_WINDOWS_WINDOW_PNG_BYTES } from "../domain/native/windowsWindowScreenshot.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { RegularFileAdmissionFailure } from "../filesystem/RegularFile.js";
import {
  captureWindowsWindowScreenshot,
  hashWindowsCaptureExecutable,
  NativeWindowsUiProvider,
  type WindowsWindowCaptureHost,
} from "./NativeWindowsUiProvider.js";

const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAF/gJ+Qv1aRwAAAABJRU5ErkJggg==",
  "base64",
);
const SHA256 = "a".repeat(64);
const TARGET = {
  path: "C:\\Apps\\fixture.exe",
  sha256: SHA256,
  kind: "executable",
  format: "pe",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
  executableRole: "application",
  managed: false,
} satisfies BinaryTarget;

const captureReply = () => ({
  pid: 42,
  window_handle: "0x1234",
  process_image_path: "C:\\Apps\\fixture.exe",
  process_start_time_unix_ms: 1_700_000_000_000,
  title: "Fixture",
  source_width: 1,
  source_height: 1,
  width: 1,
  height: 1,
  png: PNG,
});

const host = (
  overrides: Partial<WindowsWindowCaptureHost> = {},
): WindowsWindowCaptureHost => ({
  capture: captureReply,
  identifyExecutable: async () => ({
    fileIdentity: "c:\\apps\\fixture.exe",
    sha256: SHA256,
  }),
  ...overrides,
});

it("captures only an HWND whose live executable identity matches the active PE target", async () => {
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x1234" },
    host(),
  );

  expect(captured.ok).toBe(true);
  if (!captured.ok) return;
  expect(captured.value).toMatchObject({
    target_sha256: SHA256,
    window: { pid: 42, window_handle: "0x1234" },
    screenshot: {
      sha256: createHash("sha256").update(PNG).digest("hex"),
      width: 1,
      height: 1,
    },
  });
});

it("fails closed when the selected PID maps to different executable bytes", async () => {
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x1234" },
    host({
      capture: () => ({
        pid: 42,
        window_handle: "0x1234",
        process_image_path: "C:\\Apps\\other.exe",
        process_start_time_unix_ms: 1_700_000_000_000,
        title: "Fixture",
        source_width: 1,
        source_height: 1,
        width: 1,
        height: 1,
        png: PNG,
      }),
      identifyExecutable: async (path) => ({
        fileIdentity: path.toLowerCase(),
        sha256: path === TARGET.path ? SHA256 : "b".repeat(64),
      }),
    }),
  );

  expect(captured).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
});

it("does not invoke native capture for a malformed HWND", async () => {
  let invoked = false;
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x0001" },
    host({
      capture: () => {
        invoked = true;
        return {};
      },
    }),
  );

  expect(invoked).toBe(false);
  expect(captured).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
});

it("classifies malformed native replies as output failures", async () => {
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x1234" },
    host({ capture: () => ({ pid: 42 }) }),
  );
  expect(captured).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisOutputError" },
  });
});

it("rejects an oversized native PNG before base64 allocation or post-capture hashing", async () => {
  const png = Buffer.alloc(MAX_WINDOWS_WINDOW_PNG_BYTES + 1);
  const encode = vi.spyOn(png, "toString");
  const identifyExecutable = vi.fn(async () => ({
    fileIdentity: "fixture",
    sha256: SHA256,
  }));
  const captureHost = host({ identifyExecutable });
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x1234" },
    {
      ...captureHost,
      capture: () => ({ ...captureReply(), png }),
    },
  );
  expect(captured).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisOutputError" },
  });
  expect(encode).not.toHaveBeenCalled();
  expect(identifyExecutable).toHaveBeenCalledTimes(1);
});

it.each([
  [2, "artifact_changed", "AnalysisArtifactChangedError"],
  [3, "artifact_changed", "AnalysisArtifactChangedError"],
  [6, "artifact_changed", "AnalysisArtifactChangedError"],
  [13, "artifact_changed", "AnalysisArtifactChangedError"],
  [5, "window_owner_mismatch", "AnalysisInputError"],
  [13, "window_state", "AnalysisInputError"],
  [5, "process_identity_mismatch", "AnalysisInputError"],
  [87, "process_identity_mismatch", "AnalysisInputError"],
] as const)(
  "preserves native refusal semantics for code %s and %s",
  async (code, kind, tag) => {
    const captured = await captureWindowsWindowScreenshot(
      TARGET,
      { pid: 42, window_handle: "0x1234" },
      host({
        capture: () => {
          throw Object.assign(new Error("Native refusal"), {
            win32Code: code,
            failureKind: kind,
          });
        },
      }),
    );
    expect(captured).toMatchObject({ ok: false, error: { _tag: tag } });
  },
);

it("keeps source-pixel capacity distinct from selected window state", async () => {
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x1234" },
    host({
      capture: () => {
        throw Object.assign(
          new Error("Source area exceeds the capture limit"),
          {
            win32Code: 8,
            failureKind: "source_pixel_limit",
          },
        );
      },
    }),
  );
  expect(captured).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisResourceConstraintError",
      resource: "capacity",
      reportedLimits: { maximum_source_pixels: 4 * 1024 * 1024 },
    },
  });
});

it("retains and retries an executable descriptor whose close first fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-window-capture-"));
  const executable = join(directory, "fixture.exe");
  const originalClose = OwnedFileHandle.prototype.close;
  let firstClose = true;
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(async function (this: OwnedFileHandle): Promise<void> {
      if (firstClose) {
        firstClose = false;
        throw new Error("injected executable close failure");
      }
      await originalClose.call(this);
    });
  try {
    await writeFile(executable, "fixture");
    await expect(hashWindowsCaptureExecutable(executable)).rejects.toThrow(
      "Selected executable descriptor cleanup failed",
    );
    close.mockRestore();
    const client = new NativeWindowsUiProvider(
      {},
      host(),
      "linux",
    ).createClient(TARGET);
    await expect(client.close()).resolves.toMatchObject({ ok: true });
    await expect(
      hashWindowsCaptureExecutable(executable),
    ).resolves.toMatchObject({
      sha256: createHash("sha256").update("fixture").digest("hex"),
    });
  } finally {
    close.mockRestore();
    await rm(directory, { force: true, recursive: true });
  }
});

it("retains both final identity owners before returning their primary failure", async () => {
  const targetClose = vi.fn(async () => undefined);
  const processClose = vi.fn(async () => undefined);
  const targetOwner = new OwnedFileHandle({
    fd: 701,
    close: targetClose,
  }) as unknown as OwnedFileHandle;
  const processOwner = new OwnedFileHandle({
    fd: 702,
    close: processClose,
  }) as unknown as OwnedFileHandle;
  const targetFailure = new RegularFileAdmissionFailure(
    TARGET.path,
    new Error("target admission failed"),
    new Error("target close failed"),
    targetOwner,
  );
  const processPath = "C:\\Apps\\process.exe";
  const processFailure = new RegularFileAdmissionFailure(
    processPath,
    new Error("process admission failed"),
    new Error("process close failed"),
    processOwner,
  );
  let initialIdentity = true;
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x1234" },
    host({
      capture: () => ({
        pid: 42,
        window_handle: "0x1234",
        process_image_path: processPath,
        process_start_time_unix_ms: 1_700_000_000_000,
        title: "Fixture",
        source_width: 1,
        source_height: 1,
        width: 1,
        height: 1,
        png: PNG,
      }),
      identifyExecutable: async (path) => {
        if (initialIdentity) {
          initialIdentity = false;
          return { fileIdentity: "c:\\apps\\fixture.exe", sha256: SHA256 };
        }
        throw path === TARGET.path ? targetFailure : processFailure;
      },
    }),
  );

  expect(captured).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      cleanup: { resources: [TARGET.path, processPath] },
    },
  });
  const client = new NativeWindowsUiProvider({}, host(), "linux").createClient(
    TARGET,
  );
  await expect(client.close()).resolves.toMatchObject({ ok: true });
  expect(targetClose).toHaveBeenCalledTimes(1);
  expect(processClose).toHaveBeenCalledTimes(1);
});

it("does not commit a screenshot cancelled during final identity reads", async () => {
  const controller = new AbortController();
  let reads = 0;
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x1234" },
    host({
      identifyExecutable: async () => {
        if (++reads > 1) controller.abort();
        return { fileIdentity: "c:\\apps\\fixture.exe", sha256: SHA256 };
      },
    }),
    { signal: controller.signal },
  );
  expect(captured).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});

it.each([undefined, ""])(
  "preserves pathless native permission refusals (%s)",
  async (requestedPath) => {
    const captured = await captureWindowsWindowScreenshot(
      TARGET,
      { pid: 42, window_handle: "0x1234" },
      host({
        capture: () => {
          throw Object.assign(
            new Error("Windows refused process/window access"),
            {
              win32Code: 5,
              ...(requestedPath === undefined ? {} : { requestedPath }),
            },
          );
        },
      }),
    );
    expect(captured).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisAccessDeniedError",
        processWindow: { pid: 42, windowHandle: "0x1234" },
      },
    });
  },
);
it("reports concurrent native capture admission as bounded capacity", async () => {
  const captured = await captureWindowsWindowScreenshot(
    TARGET,
    { pid: 42, window_handle: "0x1234" },
    host({
      capture: () => {
        throw { win32Code: 170 };
      },
    }),
  );
  expect(captured).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisResourceConstraintError",
      resource: "capacity",
      reportedLimits: { maximum_concurrent_captures: 1 },
    },
  });
});
