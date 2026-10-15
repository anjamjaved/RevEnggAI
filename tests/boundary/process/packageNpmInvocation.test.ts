import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { expect, it } from "vitest";

const execute = promisify(execFile);

it("runs the caller-selected npm entry through Node without rewriting its inputs", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-npm-invocation-"));
  try {
    const npmEntry = join(root, "selected npm entry.mjs");
    await writeFile(
      npmEntry,
      `process.stdout.write(JSON.stringify({ arguments: process.argv.slice(2), cwd: process.cwd(), marker: process.env.REA_NPM_TEST_MARKER }));\n`,
    );
    const helper = pathToFileURL(
      resolve("scripts/lib/verify-package-core.mjs"),
    ).href;
    const program = `
      const { execNpm } = await import(${JSON.stringify(helper)});
      const result = await execNpm(["pack", "value with spaces"], {
        cwd: ${JSON.stringify(root)},
        env: { ...process.env, npm_execpath: ${JSON.stringify(npmEntry)}, REA_NPM_TEST_MARKER: "caller-selected" },
      });
      process.stdout.write(result.stdout);
    `;
    const result = await execute(
      process.execPath,
      ["--input-type=module", "--eval", program],
      { windowsHide: true },
    );
    expect(JSON.parse(result.stdout)).toEqual({
      arguments: ["pack", "value with spaces"],
      cwd: root,
      marker: "caller-selected",
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
