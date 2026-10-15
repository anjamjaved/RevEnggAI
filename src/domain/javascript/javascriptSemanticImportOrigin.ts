import * as t from "@babel/types";

import type { JavaScriptModuleOrigin } from "./javascriptSemanticIr.js";
import { semanticMemberChain } from "./javascriptSemanticRequireOrigin.js";
import { unwrapJavaScriptExpression } from "./javascriptAstValues.js";
import { stringValue } from "./javascriptStaticAnalysisHelpers.js";

/** Recover an exact export of a fulfilled literal import, never its promise. */
export const semanticAwaitedImportOrigin = (
  node: t.Node,
): JavaScriptModuleOrigin | undefined => {
  const chain = semanticMemberChain(node);
  if (chain === undefined || !t.isAwaitExpression(chain.root)) return undefined;
  const imported = unwrapJavaScriptExpression(chain.root.argument).node;
  const source = t.isImportExpression(imported)
    ? imported.source
    : t.isCallExpression(imported) && t.isImport(imported.callee)
      ? imported.arguments[0]
      : undefined;
  const specifier = stringValue(source);
  return specifier === undefined
    ? undefined
    : { specifier, importedPath: chain.members, resolutionMode: "import" };
};
