import { readFile, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { describe, expect } from "vitest";

import { bundleRuntime } from "../../../scripts/bundle-runtime.mjs";
import { workspaceCliTest } from "../../support/cli/workspaceCliFixture.js";

const runtimeFixtureFiles = {
  "node_modules/zod/package.json": JSON.stringify({
    type: "module",
    exports: "./index.js",
  }),
  "node_modules/zod/index.js":
    "export const z = {string: () => ({parse: value => value})};",
  "dist/windows/WindowsWindowCaptureWorker.js": `
import { z } from 'zod';
import { generatedPackageMetadata } from '../generatedPackageMetadata.js';
process.stdout.write(z.string().parse('capture-worker:' + generatedPackageMetadata.version));`,
  "package.json": JSON.stringify({
    type: "module",
    imports: {
      "#javascript-analysis-worker":
        "./dist/composition/javascriptAnalysisWorkerProcess.js",
    },
  }),
  "bridge/resource.txt": "bridge resource\n",
  "node_modules/external-probe/package.json": JSON.stringify({
    name: "external-probe",
    main: "index.cjs",
  }),
  "node_modules/external-probe/index.cjs": 'module.exports = "external";',
  "dist/provider/probe λ.js": `
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
globalThis.effects ??= [];
globalThis.effects.push('provider');
export const facts = {
  url: import.meta.url,
  resource: readFileSync(new URL('../../bridge/resource.txt', import.meta.url), 'utf8'),
  external: createRequire(import.meta.url)('external-probe'),
  worker: import.meta.resolve('#javascript-analysis-worker')
};`,
  "dist/lazy.js": `
globalThis.effects.push('lazy');
export const lazyUrl = import.meta.url;`,
  "dist/composition/javascriptAnalysisWorkerProcess.js":
    'process.stdout.write("worker-entry");',
  "dist/generatedPackageMetadata.js":
    'export const generatedPackageMetadata = { version: "1.0.0" };',
  "dist/cli.js": 'export { facts, run } from "./main.js";',
  "dist/cliOutput.js": 'export { facts } from "./provider/probe λ.js";',
  "dist/cli/cliResultOutput.js":
    'export { facts } from "../provider/probe λ.js";',
  "dist/mcpDoctor.js": 'export { run } from "./main.js";',
  "dist/main.js": `
import { facts } from './provider/probe λ.js';
import { generatedPackageMetadata } from './generatedPackageMetadata.js';
export { facts };
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
globalThis.effects.push('main');
export const run = async () => {
  const beforeLazy = [...globalThis.effects];
  const { lazyUrl } = await import('./lazy.js');
  return {
    ...facts, version: generatedPackageMetadata.version, beforeLazy, afterLazy: globalThis.effects, lazyUrl,
    workerOutput: execFileSync(process.execPath, [fileURLToPath(facts.worker)], { encoding: 'utf8' })
  };
};`,
};

describe("CLI and MCP runtime bundles", () => {
  workspaceCliTest(
    "preserves module locations, lazy side effects, package resolution and worker entrypoints",
    async ({ processes, workspace }) => {
      await workspace.mkdir("dist/provider");
      await workspace.mkdir("dist/composition");
      await workspace.mkdir("dist/cli");
      await workspace.mkdir("dist/windows");
      await workspace.mkdir("bridge");
      await workspace.mkdir("node_modules/external-probe");
      await workspace.mkdir("node_modules/zod");
      for (const [path, contents] of Object.entries(runtimeFixtureFiles))
        await workspace.write(path, contents);
      const invoke = async (entry: string) => {
        const moduleUrl = pathToFileURL(join(workspace.root, entry)).href;
        const result = await processes.run(
          process.execPath,
          [
            "--input-type=module",
            "--eval",
            `const { run } = await import(${JSON.stringify(moduleUrl)}); process.stdout.write(JSON.stringify(await run()));`,
          ],
          { cwd: workspace.root },
        );
        expect(result.exitCode).toBe(0);
        return JSON.parse(result.stdout) as unknown;
      };
      const original = await invoke("dist/main.js");
      await bundleRuntime(workspace.root);
      const bundled = await invoke("dist/mcp/main.js");
      expect(bundled).toEqual(original);
      expect(await invoke("dist/cli-runtime/cli.js")).toEqual(
        await invoke("dist/cli.js"),
      );
      const cliDirectory = join(workspace.root, "dist/cli-runtime");
      const identity = await processes.run(
        process.execPath,
        [
          "--input-type=module",
          "--eval",
          `const { facts } = await import(${JSON.stringify(pathToFileURL(join(cliDirectory, "cli.js")).href)}); const output = await import(${JSON.stringify(pathToFileURL(join(cliDirectory, "cliOutput.js")).href)}); const streamed = await import(${JSON.stringify(pathToFileURL(join(cliDirectory, "cliResultOutput.js")).href)}); process.stdout.write(JSON.stringify(facts === output.facts && facts === streamed.facts));`,
        ],
        { cwd: workspace.root },
      );
      expect(identity).toMatchObject({ exitCode: 0, stdout: "true" });
      expect(bundled).toMatchObject({
        resource: "bridge resource\n",
        external: "external",
        beforeLazy: ["provider", "main"],
        afterLazy: ["provider", "main", "lazy"],
        workerOutput: "worker-entry",
      });
      for (const [path, contents] of Object.entries(runtimeFixtureFiles))
        expect(await readFile(join(workspace.root, path), "utf8")).toBe(
          contents,
        );
      // The real capture deadline includes cold startup. This worker bundles
      // its schema dependency instead of reopening its module graph per frame.
      await rm(join(workspace.root, "node_modules/zod"), { recursive: true });
      const captureWorker = () =>
        processes.run(
          process.execPath,
          [join(workspace.root, "dist/windows-capture-runtime/worker.js")],
          { cwd: workspace.root },
        );
      expect(await captureWorker()).toMatchObject({
        exitCode: 0,
        stdout: "capture-worker:1.0.0",
      });
      expect(
        (await readdir(join(workspace.root, "dist/mcp"))).length,
      ).toBeGreaterThan(1);
      await workspace.write(
        "dist/generatedPackageMetadata.js",
        'export const generatedPackageMetadata = { version: "0.0.0" };',
      );
      const previousRelease = await invoke("dist/main.js");
      expect(previousRelease).toMatchObject({ version: "0.0.0" });
      expect(await invoke("dist/mcp/main.js")).toEqual(previousRelease);
      expect(await invoke("dist/cli-runtime/cli.js")).toEqual(previousRelease);
      expect(await captureWorker()).toMatchObject({
        exitCode: 0,
        stdout: "capture-worker:0.0.0",
      });
    },
  );

  workspaceCliTest(
    "rejects module-relative resolution and unknown import metadata during the build",
    async ({ workspace }) => {
      await workspace.mkdir("dist");
      await workspace.mkdir("dist/cli");
      await workspace.mkdir("dist/windows");
      await workspace.write(
        "dist/windows/WindowsWindowCaptureWorker.js",
        "export {};\n",
      );
      await workspace.write("package.json", '{"type":"module"}');
      for (const path of [
        "dist/cliOutput.js",
        "dist/cli/cliResultOutput.js",
        "dist/mcpDoctor.js",
      ])
        await workspace.write(path, "export {};\n");
      for (const entry of ["dist/main.js", "dist/cli.js"]) {
        for (const expression of [
          "import.meta.resolve('./worker.js')",
          "import.meta.env",
        ]) {
          await workspace.write("dist/main.js", "export {};\n");
          await workspace.write("dist/cli.js", "export {};\n");
          await workspace.write(entry, `export const value = ${expression};`);
          await expect(bundleRuntime(workspace.root)).rejects.toThrow(
            "Unsupported import.meta use in runtime bundle",
          );
        }
      }
    },
  );
});
