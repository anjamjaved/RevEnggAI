import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { scanCanonicalArtifactInventory } from "../../../fixtures/artifactInventory.js";
import { readJavaScriptArtifactFiles } from "../../../support/javascriptApplicationScope.js";
import { createJavaScriptArtifactReader } from "../../../../src/artifacts/javascript/JavaScriptArtifactReader.js";
import { analyzeJavaScriptArtifactFiles } from "../../../../src/application/javascript/JavaScriptArtifactAnalysis.js";
import { buildJavaScriptArtifactGraph } from "../../../../src/application/javascript/JavaScriptArtifactGraphBuilder.js";

it("projects a qualified global socket with its source evidence and excludes a local lookalike", async () => {
  const root = await createTestTempDirectory("rea-js-qualified-socket-");
  await writeFile(
    join(root, "app.js"),
    [
      'function local(window) { new window.WebSocket("wss://example.test/local"); }',
      'new globalThis.WebSocket("wss://example.test/socket");',
    ].join("\n"),
  );
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const endpoints = graph.nodes.filter(({ kind }) => kind === "endpoint");
    expect(endpoints).toHaveLength(1);
    const observation = endpoints[0]?.observations[0];
    expect(observation?.properties).toMatchObject({
      value: "wss://example.test/socket",
      mechanism: "call:globalThis.WebSocket",
    });
    expect(observation?.evidence).toMatchObject({
      authority: "ast-static-analysis",
      state: "observed",
      confidence: "exact",
      location: {
        available: true,
        value: {
          kind: "source-range",
          source: "app.js",
          start: { line: 2, column: 0 },
        },
      },
    });
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("retains constructor captures, ws imports and template keys with their graph source ranges", async () => {
  const root = await createTestTempDirectory("rea-js-bound-socket-");
  await writeFile(
    join(root, "app.js"),
    [
      'import Socket from "ws";',
      "const Captured = globalThis.WebSocket;",
      'new Socket("wss://example.test/imported");',
      'new Captured("wss://example.test/captured");',
      'new globalThis[`WebSocket`]("wss://example.test/template");',
      'const CommonJs = require("ws");',
      'new CommonJs("wss://example.test/commonjs");',
      "const { WebSocket: Projected } = globalThis;",
      'new Projected("wss://example.test/projected");',
      "function connect() {",
      'new Deferred("wss://example.test/deferred");',
      "}",
      "const Deferred = globalThis.WebSocket;",
      "connect();",
      'const { WebSocket: Named } = require("ws");',
      'new Named("wss://example.test/named-commonjs");',
      'const Member = require("ws").WebSocket;',
      'new Member("wss://example.test/member-commonjs");',
    ].join("\n"),
  );
  await writeFile(
    join(root, "import-equals.ts"),
    'import Socket = require("ws");\nnew Socket("wss://example.test/import-equals");',
  );
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const endpoints = graph.nodes.filter(({ kind }) => kind === "endpoint");
    expect(endpoints).toHaveLength(9);
    for (const [path, constructor, line, source] of [
      ["imported", "Socket", 3, "app.js"],
      ["captured", "Captured", 4, "app.js"],
      ["template", "globalThis.WebSocket", 5, "app.js"],
      ["commonjs", "CommonJs", 7, "app.js"],
      ["projected", "Projected", 9, "app.js"],
      ["deferred", "Deferred", 11, "app.js"],
      ["import-equals", "Socket", 2, "import-equals.ts"],
      ["named-commonjs", "Named", 16, "app.js"],
      ["member-commonjs", "Member", 18, "app.js"],
    ] as const) {
      const observation = endpoints.find(({ observations }) =>
        observations.some(
          ({ properties }) => properties.value === `wss://example.test/${path}`,
        ),
      )?.observations[0];
      expect(observation?.properties).toMatchObject({
        value: `wss://example.test/${path}`,
        mechanism: `call:${constructor}`,
      });
      expect(observation?.evidence).toMatchObject({
        authority: "ast-static-analysis",
        state: "observed",
        confidence: "exact",
        location: {
          available: true,
          value: {
            kind: "source-range",
            source,
            start: { line, column: 0 },
          },
        },
      });
    }
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("preserves eager and deferred socket phases through filesystem graph projection", async () => {
  const root = await createTestTempDirectory("rea-js-socket-phases-");
  const fixtures = {
    "wrapped.ts":
      '(function () { new Socket("wss://example.test/eager-wrapper"); } as any)();\nconst Socket = globalThis.WebSocket;',
    "fields.js":
      'class Client { socket = new Socket("wss://example.test/field"); }\nconst Socket = globalThis.WebSocket; new Client();',
    "generator.js":
      '(function* (x = new Socket("wss://example.test/eager-parameter")) {})();\n(function* () { new Socket("wss://example.test/generator-body"); })();\nconst Socket = globalThis.WebSocket;',
    "bound.js":
      '(function () { new Socket("wss://example.test/eager-bind"); }).bind(null)();\nconst connect = (function () { new Socket("wss://example.test/deferred-bind"); }).bind(null);\nconst Socket = globalThis.WebSocket; connect();',
    "async.js":
      '(async () => { new Socket("wss://example.test/eager-async"); await ready; })();\n(async () => { await ready; new Socket("wss://example.test/continuation"); })();\nconst Socket = globalThis.WebSocket;',
    "await-inputs.js": [
      'let value; (async () => { value = await ready; new Socket("wss://example.test/assignment"); })();',
      '(async () => { new (class { socket = new Socket("wss://example.test/argument-field"); })(await ready); })();',
      '(async () => { new (class { constructor() { new Socket("wss://example.test/argument-constructor"); } })(await ready); })();',
      '(async () => { new (class { socket = new Socket("wss://example.test/computed-key"); [await ready] = 0; })(); })();',
      "const Socket = globalThis.WebSocket;",
    ].join("\n"),
    "immediate-generator.js":
      '(function* () { new Socket("wss://example.test/tdz-generator"); })().next(); const Socket = globalThis.WebSocket;',
    "delegated-generator.js":
      '(function* () { yield* []; new Socket("wss://example.test/tdz-delegation"); })().next(); const Socket = globalThis.WebSocket;',
    "waiting-caller.js":
      '(async () => { await (async () => { await ready; new Socket("wss://example.test/tdz-waiting"); })(); const Socket = globalThis.WebSocket; })();',
    "switch-case.js":
      'switch (kind) { case 0: const Socket = globalThis.WebSocket; break; case 1: new Socket("wss://example.test/tdz-case"); }',
    "loop-array.js": [
      '(async () => { while (await ready) { new Socket("wss://example.test/loop-continuation"); break; } })();',
      '(async () => { [await ready, new Socket("wss://example.test/array-continuation")]; })();',
      "const Socket = globalThis.WebSocket;",
    ].join("\n"),
    "sequence-capture.js":
      'const Socket = (0, globalThis.WebSocket); new Socket("wss://example.test/sequence-capture");',
    "dynamic-import.mjs":
      'const { WebSocket: Socket } = await import("ws"); new Socket("wss://example.test/dynamic-import");',
    "await-branch.js":
      '(async () => { if (await ready) new Socket("wss://example.test/branch-continuation"); })(); const Socket = globalThis.WebSocket;',
    "immediate-sequence.js":
      '(0, function () { new Socket("wss://example.test/tdz-sequence"); })(); const Socket = globalThis.WebSocket;',
    "async-local.js":
      '(async () => { new Socket("wss://example.test/tdz-before-await"); await ready; const Socket = globalThis.WebSocket; })();',
    "async-phases.js":
      '(async () => { await ready; new Socket("wss://example.test/tdz-between-awaits"); await ready; const Socket = globalThis.WebSocket; })();',
    "immediate-class.js":
      'new (class { socket = new Socket("wss://example.test/tdz-field"); })(); const Socket = globalThis.WebSocket;',
    "immediate-constructor.js":
      'new (class { constructor() { new Socket("wss://example.test/tdz-constructor"); } })(); const Socket = globalThis.WebSocket;',
  };
  for (const [path, source] of Object.entries(fixtures))
    await writeFile(join(root, path), source);
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const observations = graph.nodes
      .filter(({ kind }) => kind === "endpoint")
      .flatMap(({ observations }) => observations);
    expect(
      observations.map(({ properties }) => properties.value).sort(),
    ).toEqual([
      "wss://example.test/argument-constructor",
      "wss://example.test/argument-field",
      "wss://example.test/array-continuation",
      "wss://example.test/assignment",
      "wss://example.test/branch-continuation",
      "wss://example.test/computed-key",
      "wss://example.test/continuation",
      "wss://example.test/deferred-bind",
      "wss://example.test/dynamic-import",
      "wss://example.test/field",
      "wss://example.test/generator-body",
      "wss://example.test/loop-continuation",
      "wss://example.test/sequence-capture",
    ]);
    for (const [path, source, line] of [
      ["assignment", "await-inputs.js", 1],
      ["argument-field", "await-inputs.js", 2],
      ["argument-constructor", "await-inputs.js", 3],
      ["computed-key", "await-inputs.js", 4],
      ["branch-continuation", "await-branch.js", 1],
      ["continuation", "async.js", 2],
      ["deferred-bind", "bound.js", 2],
      ["field", "fields.js", 1],
      ["generator-body", "generator.js", 2],
      ["array-continuation", "loop-array.js", 2],
      ["loop-continuation", "loop-array.js", 1],
      ["sequence-capture", "sequence-capture.js", 1],
      ["dynamic-import", "dynamic-import.mjs", 1],
    ] as const) {
      const observation = observations.find(
        ({ properties }) => properties.value === `wss://example.test/${path}`,
      );
      expect(observation?.evidence).toMatchObject({
        authority: "ast-static-analysis",
        state: "observed",
        confidence: "exact",
        location: {
          available: true,
          value: { kind: "source-range", source, start: { line } },
        },
      });
    }
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("keeps CommonJS socket member writes separate from earlier constructor captures", async () => {
  const root = await createTestTempDirectory("rea-js-socket-member-writes-");
  const fixtures = {
    "replaced.js":
      'const ws = require("ws"); ws.WebSocket = class {}; new ws.WebSocket("wss://example.test/replaced");',
    "aliased.js":
      'const ws = require("ws"); const alias = ws; alias.WebSocket = class {}; new ws.WebSocket("wss://example.test/aliased");',
    "repeated.js":
      'require("ws").WebSocket = class {}; const ws = require("ws"); new ws.WebSocket("wss://example.test/repeated");',
    "captured.js":
      'const ws = require("ws"); const Socket = ws.WebSocket; ws.WebSocket = class {};\nnew Socket("wss://example.test/captured-before-write");',
    "loop-capture.js":
      'const ws = require("ws"); const Socket = ws.WebSocket; for (const item of items) { ws.WebSocket = class {}; }\nnew Socket("wss://example.test/loop-captured");',
    "sibling.js":
      'const ws = require("ws"); ws.Server = class {};\nnew ws.WebSocket("wss://example.test/unchanged-sibling");',
  };
  for (const [path, source] of Object.entries(fixtures))
    await writeFile(join(root, path), source);
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const graph = buildJavaScriptArtifactGraph(
      snapshot,
      files,
      analyzeJavaScriptArtifactFiles(files),
    );
    const observations = graph.nodes
      .filter(({ kind }) => kind === "endpoint")
      .flatMap(({ observations }) => observations);
    expect(
      observations.map(({ properties }) => properties.value).sort(),
    ).toEqual([
      "wss://example.test/captured-before-write",
      "wss://example.test/loop-captured",
      "wss://example.test/unchanged-sibling",
    ]);
    for (const [value, source] of [
      ["captured-before-write", "captured.js"],
      ["loop-captured", "loop-capture.js"],
      ["unchanged-sibling", "sibling.js"],
    ]) {
      const observation = observations.find(
        ({ properties }) => properties.value === `wss://example.test/${value}`,
      );
      expect(observation?.evidence).toMatchObject({
        authority: "ast-static-analysis",
        state: "observed",
        confidence: "exact",
        location: {
          available: true,
          value: { kind: "source-range", source, start: { line: 2 } },
        },
      });
    }
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});

it("keeps ambiguous endpoint candidates inferred through artifact graph projection", async () => {
  const root = await createTestTempDirectory("rea-js-endpoint-certainty-");
  await writeFile(join(root, "app.js"), 'form.get("shared"); fetch("shared");');
  const snapshot = await scanCanonicalArtifactInventory(root, {});
  const reader = createJavaScriptArtifactReader(root, "directory");
  try {
    const files = await readJavaScriptArtifactFiles(reader, snapshot);
    const analysis = analyzeJavaScriptArtifactFiles(files);
    const graph = buildJavaScriptArtifactGraph(snapshot, files, analysis);
    const endpoints = graph.nodes.filter(({ kind }) => kind === "endpoint");
    const candidate = endpoints.find(({ observations }) =>
      observations.some(
        ({ properties }) => properties.interpretation === "candidate",
      ),
    );
    const observed = endpoints.find(({ observations }) =>
      observations.some(
        ({ properties }) =>
          properties.value === "shared" &&
          properties.interpretation === undefined,
      ),
    );

    expect(candidate).toBeDefined();
    expect(observed).toBeDefined();
    expect(candidate?.node_id).not.toBe(observed?.node_id);
    const candidateObservation = candidate?.observations[0];
    expect(candidateObservation?.properties).toMatchObject({
      value: "shared",
      interpretation: "candidate",
    });
    expect(candidateObservation?.evidence).toMatchObject({
      authority: "static-relationship-inference",
      state: "inferred",
      confidence: "low",
      location: {
        available: true,
        value: { kind: "source-range", source: "app.js" },
      },
    });
    expect(candidateObservation?.evidence.limitations).toEqual(
      expect.arrayContaining([expect.stringContaining("only a candidate")]),
    );
    expect(observed?.observations[0]?.evidence).toMatchObject({
      authority: "ast-static-analysis",
      state: "observed",
      confidence: "exact",
    });
    const candidateEdge = graph.edges.find(
      ({ target_node_id }) => target_node_id === candidate?.node_id,
    );
    expect(candidateEdge?.properties.interpretation).toBe("candidate");
    expect(candidateEdge?.evidence).toMatchObject({
      state: "inferred",
      confidence: "low",
    });
    expect(candidateEdge?.evidence.limitations).toEqual(
      expect.arrayContaining([expect.stringContaining("only a candidate")]),
    );
  } finally {
    await reader.close();
    await rm(root, { recursive: true, force: true });
  }
});
