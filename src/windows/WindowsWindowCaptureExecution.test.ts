import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";

import * as command from "../process/OwnedCommand.js";
import { executeWindowsCapture } from "./WindowsWindowCaptureExecution.js";
import { WINDOWS_CAPTURE_REQUEST_BYTES } from "./WindowsWindowCaptureProtocol.js";
import * as native from "./WindowsNativeLoader.js";
import { NativeWindowsUiProvider } from "./NativeWindowsUiProvider.js";
import { pe } from "../domain/binaryTarget.fixture.js";

afterEach(() => vi.restoreAllMocks());

it("sends long selected paths through stdin and preserves only the selected environment", async () => {
  const run = vi
    .spyOn(command, "runOwnedCommand")
    .mockRejectedValue(
      new command.OwnedCommandFailure(
        "cancelled",
        "Fixture stopped after launch inspection",
      ),
    );
  const request = {
    pid: 42,
    window_handle: "0x1234",
    max_dimension: 320,
    target_path: "C:" + "\\a".repeat(16000),
    target_sha256: "a".repeat(64),
    target_file_identity: "1:42",
  };
  await expect(
    executeWindowsCapture(request, {
      TEMP: "selected-temp",
      REA_CAPTURE_SELECTED: "selected",
      NODE_OPTIONS: "--require=never-run",
    }),
  ).rejects.toMatchObject({ _tag: "AnalysisCancelledError" });
  expect(run).toHaveBeenCalledTimes(1);
  const [spawn, , options] = run.mock.calls[0]!;
  expect(spawn.arguments).toHaveLength(2);
  expect(spawn.hostEnvironment).toEqual({
    TEMP: "selected-temp",
    REA_CAPTURE_SELECTED: "selected",
  });
  const input = Buffer.from(options?.input ?? []);
  expect(input.byteLength).toBeGreaterThan(32767);
  expect(input.byteLength).toBeLessThanOrEqual(WINDOWS_CAPTURE_REQUEST_BYTES);
  expect(JSON.parse(input.toString("utf8"))).toEqual(request);
});

it("carries the provider's selected environment through executable admission to helper launch", async () => {
  const directory = await mkdtemp(join(tmpdir(), "rea-capture-environment-"));
  const path = join(directory, "fixture.exe");
  const bytes = pe(0x8664);
  await writeFile(path, bytes);
  vi.spyOn(native, "requireWindowsWindowCaptureAuthority").mockReturnValue({
    call: () => {
      throw new Error("Admission must not invoke native paint directly");
    },
  });
  const run = vi
    .spyOn(command, "runOwnedCommand")
    .mockRejectedValue(
      new command.OwnedCommandFailure(
        "cancelled",
        "Fixture stopped before native launch",
      ),
    );
  const client = new NativeWindowsUiProvider({
    TEMP: "provider-selected",
  }).createClient({
    kind: "executable",
    path,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    format: "pe",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
    executableRole: "application",
    managed: false,
  });
  try {
    expect(
      await client.execute("capture_windows_window_screenshot", {
        pid: 42,
        window_handle: "0x1234",
      }),
    ).toMatchObject({ ok: false, error: { _tag: "AnalysisCancelledError" } });
    expect(run).toHaveBeenCalledTimes(1);
    expect(run.mock.calls[0]![0].hostEnvironment).toEqual({
      TEMP: "provider-selected",
    });
  } finally {
    await client.close();
    await rm(directory, { recursive: true, force: true });
  }
});
