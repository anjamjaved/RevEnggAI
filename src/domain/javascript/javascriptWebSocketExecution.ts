import * as t from "@babel/types";

import {
  unwrapJavaScriptExpression,
  semanticStaticPropertyName,
} from "./javascriptAstValues.js";
import type { JavaScriptSemanticAnalysisState } from "./javascriptSemanticState.js";

/** Outward syntax wrappers preserve the expression's runtime identity. */
const webSocketOuterExpression = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.Node => {
  let current = node;
  let identity = node;
  for (;;) {
    const parent = state.parentsByNode.get(current);
    if (
      t.isSequenceExpression(parent) &&
      parent.expressions.at(-1) === current
    ) {
      current = parent;
      identity = parent;
      continue;
    }
    if (
      parent === undefined ||
      unwrapJavaScriptExpression(parent).node !== identity
    )
      return current;
    current = parent;
  }
};

/** Binding a literal defers it only until that bound result is invoked. */
const webSocketImmediateInvocation = (
  node: t.Function | t.ClassExpression,
  state: JavaScriptSemanticAnalysisState,
):
  | t.CallExpression
  | t.OptionalCallExpression
  | t.NewExpression
  | undefined => {
  let callee = webSocketOuterExpression(node, state);
  for (;;) {
    let invocation = state.parentsByNode.get(callee);
    let binds = false;
    if (
      (t.isMemberExpression(invocation) ||
        t.isOptionalMemberExpression(invocation)) &&
      invocation.object === callee
    ) {
      const member = semanticStaticPropertyName(
        invocation.property,
        invocation.computed,
      );
      if (member !== "call" && member !== "apply" && member !== "bind")
        return undefined;
      binds = member === "bind";
      callee = webSocketOuterExpression(invocation, state);
      invocation = state.parentsByNode.get(callee);
    }
    if (
      (!t.isCallExpression(invocation) &&
        !t.isOptionalCallExpression(invocation) &&
        !t.isNewExpression(invocation)) ||
      invocation.callee !== callee
    )
      return undefined;
    if (!binds || t.isNewExpression(invocation)) return invocation;
    callee = webSocketOuterExpression(invocation, state);
  }
};

type WebSocketSuspension = t.AwaitExpression | t.YieldExpression;

/** Class keys complete before any static initializer or instance construction. */
const webSocketClassKeys = (node: t.Class): readonly t.Node[] => [
  ...(t.isNode(node.superClass) ? [node.superClass] : []),
  ...node.body.body.flatMap((member) =>
    (t.isClassProperty(member) || t.isClassMethod(member)) && member.computed
      ? [member.key]
      : [],
  ),
];

const webSocketStaticInitializers = (member: t.Node): readonly t.Node[] =>
  t.isStaticBlock(member)
    ? member.body
    : (t.isClassProperty(member) || t.isClassPrivateProperty(member)) &&
        member.static &&
        t.isNode(member.value)
      ? [member.value]
      : [];

/** Children completed in order if this straight-line node completes normally. */
const webSocketOrderedEvaluation = (node: t.Node): readonly t.Node[] => {
  if (t.isBlockStatement(node)) return node.body;
  if (t.isExpressionStatement(node)) return [node.expression];
  if (t.isVariableDeclaration(node)) return node.declarations;
  if (t.isVariableDeclarator(node))
    return t.isNode(node.init) ? [node.init] : [];
  if (t.isUnaryExpression(node)) return [node.argument];
  if (t.isAssignmentExpression(node) && node.operator === "=")
    return [node.left, node.right];
  if (t.isClass(node))
    return [
      ...webSocketClassKeys(node),
      ...node.body.body.flatMap(webSocketStaticInitializers),
    ];
  if (t.isSequenceExpression(node)) return node.expressions;
  if (t.isArrayExpression(node))
    return node.elements.filter((element) => element !== null);
  if (t.isSpreadElement(node)) return [node.argument];
  if (t.isBinaryExpression(node)) return [node.left, node.right];
  // Tests/left operands always complete before either a selected branch or a
  // later sibling; conditional branch bodies do not establish suspension.
  if (t.isIfStatement(node) || t.isConditionalExpression(node))
    return [node.test];
  if (t.isLogicalExpression(node)) return [node.left];
  // Every normally completed loop evaluates its initial test, but its body
  // and updates may never execute. A do/while body precedes its first test.
  if (t.isWhileStatement(node)) return [node.test];
  if (t.isForStatement(node))
    return [node.init, node.test].filter((element) => element != null);
  if (t.isYieldExpression(node) && node.argument != null)
    return [node.argument];
  if (t.isCallExpression(node) || t.isNewExpression(node))
    return [node.callee, ...node.arguments];
  // Conditional/short-circuit branches, nested functions and try/catch do not
  // establish a suspension on every path to the following expression.
  return [];
};

const webSocketCompletedSuspensions = new WeakMap<
  JavaScriptSemanticAnalysisState,
  WeakMap<t.Node, WebSocketSuspension | null>
>();

/** Successful completion crosses the last suspension in this straight-line node. */
const webSocketCompletedSuspension = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): WebSocketSuspension | undefined => {
  let cached = webSocketCompletedSuspensions.get(state);
  if (cached === undefined) {
    cached = new WeakMap();
    webSocketCompletedSuspensions.set(state, cached);
  }
  const existing = cached.get(node);
  if (existing !== undefined) return existing ?? undefined;
  const pending = [node];
  while (pending.length > 0) {
    const next = pending.pop();
    if (next === undefined) continue;
    const current = unwrapJavaScriptExpression(next).node;
    const delegateOwner =
      t.isYieldExpression(current) && current.delegate
        ? webSocketSuspensionOwner(current, state)
        : undefined;
    if (
      t.isAwaitExpression(current) ||
      (t.isYieldExpression(current) &&
        (!current.delegate ||
          // Async delegation awaits the iterator result even when it is done;
          // synchronous delegation can finish without yielding at all.
          (t.isFunction(delegateOwner) && delegateOwner.async)))
    ) {
      cached.set(node, current);
      return current;
    }
    for (const child of webSocketOrderedEvaluation(current))
      pending.push(child);
  }
  cached.set(node, null);
  return undefined;
};

const webSocketSuspensionPrefixes = new WeakMap<
  JavaScriptSemanticAnalysisState,
  WeakMap<t.Node, ReadonlyMap<t.Node, WebSocketSuspension>>
>();

/** Index sibling phases once rather than rescan a suspended body per socket. */
const webSocketPrecedingSuspension = (
  parent: t.Node,
  child: t.Node,
  state: JavaScriptSemanticAnalysisState,
): WebSocketSuspension | undefined => {
  if (
    (t.isIfStatement(parent) || t.isConditionalExpression(parent)) &&
    (child === parent.consequent || child === parent.alternate)
  )
    return webSocketCompletedSuspension(parent.test, state);
  if (t.isLogicalExpression(parent) && child === parent.right)
    return webSocketCompletedSuspension(parent.left, state);
  if (
    (t.isWhileStatement(parent) || t.isForStatement(parent)) &&
    (child === parent.body ||
      (t.isForStatement(parent) && child === parent.update))
  )
    return (
      (parent.test == null
        ? undefined
        : webSocketCompletedSuspension(parent.test, state)) ??
      (t.isForStatement(parent) && parent.init != null
        ? webSocketCompletedSuspension(parent.init, state)
        : undefined)
    );
  let byParent = webSocketSuspensionPrefixes.get(state);
  if (byParent === undefined) {
    byParent = new WeakMap();
    webSocketSuspensionPrefixes.set(state, byParent);
  }
  let prefixes = byParent.get(parent);
  if (prefixes === undefined) {
    const indexed = new Map<t.Node, WebSocketSuspension>();
    let awaited: WebSocketSuspension | undefined;
    for (const node of webSocketOrderedEvaluation(parent)) {
      if (awaited !== undefined) indexed.set(node, awaited);
      awaited = webSocketCompletedSuspension(node, state) ?? awaited;
    }
    byParent.set(parent, indexed);
    prefixes = indexed;
  }
  return prefixes.get(child);
};

/** Find a completed suspension on the containing straight-line evaluation path. */
const webSocketContinuation = (
  node: t.Node,
  body: t.Node,
  state: JavaScriptSemanticAnalysisState,
): WebSocketSuspension | undefined => {
  let current = node;
  while (current !== body) {
    const parent = state.parentsByNode.get(current);
    if (parent === undefined) return undefined;
    const awaited = webSocketPrecedingSuspension(parent, current, state);
    if (awaited !== undefined) return awaited;
    current = parent;
  }
  return undefined;
};

/** Find the literal class whose construction evaluates a field or constructor. */
const webSocketClassConstruction = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.NewExpression | undefined => {
  const body = state.parentsByNode.get(node);
  const declaration =
    body === undefined ? undefined : state.parentsByNode.get(body);
  if (!t.isClassExpression(declaration)) return undefined;
  const invocation = webSocketImmediateInvocation(declaration, state);
  return t.isNewExpression(invocation) ? invocation : undefined;
};

/** Resume only a directly produced generator with a literal next call. */
const webSocketGeneratorResume = (
  invocation: t.Node,
  state: JavaScriptSemanticAnalysisState,
): t.CallExpression | t.OptionalCallExpression | undefined => {
  const result = webSocketOuterExpression(invocation, state);
  const member = state.parentsByNode.get(result);
  if (
    (!t.isMemberExpression(member) && !t.isOptionalMemberExpression(member)) ||
    member.object !== result ||
    semanticStaticPropertyName(member.property, member.computed) !== "next"
  )
    return undefined;
  const callee = webSocketOuterExpression(member, state);
  const call = state.parentsByNode.get(callee);
  return (t.isCallExpression(call) || t.isOptionalCallExpression(call)) &&
    call.callee === callee
    ? call
    : undefined;
};

/** The lexical body that actually suspends owns the continuation boundary. */
const webSocketSuspensionOwner = (
  node: WebSocketSuspension,
  state: JavaScriptSemanticAnalysisState,
): t.Node => {
  let current: t.Node = node;
  for (;;) {
    const parent = state.parentsByNode.get(current);
    if (parent === undefined) return current;
    if (
      t.isFunction(parent) &&
      !(
        (t.isClassMethod(parent) || t.isObjectMethod(parent)) &&
        parent.key === current
      )
    )
      return parent;
    current = parent;
  }
};

/** A caller directly awaiting this result cannot initialize later locals yet. */
const webSocketWaitingContexts = (
  invocation: t.Node,
  state: JavaScriptSemanticAnalysisState,
): readonly t.Node[] => {
  const contexts: t.Node[] = [];
  let current: t.Node | undefined = invocation;
  while (current !== undefined) {
    const result = webSocketOuterExpression(current, state);
    const awaited = state.parentsByNode.get(result);
    if (!t.isAwaitExpression(awaited) || awaited.argument !== result) break;
    const owner = webSocketSuspensionOwner(awaited, state);
    contexts.push(owner);
    current = t.isFunction(owner)
      ? webSocketImmediateInvocation(owner, state)
      : undefined;
  }
  return contexts;
};

/** A lexical switch initializer is not reached by entering another case. */
export const webSocketInitializerDominatesRead = (
  initializer: t.Node,
  read: t.Node,
  state: JavaScriptSemanticAnalysisState,
): boolean => {
  let current: t.Node | undefined = initializer;
  while (
    current !== undefined &&
    !t.isFunction(current) &&
    !t.isProgram(current)
  ) {
    if (t.isSwitchCase(current)) {
      let ancestor: t.Node | undefined = read;
      while (ancestor !== undefined && ancestor !== current)
        ancestor = state.parentsByNode.get(ancestor);
      if (ancestor === undefined) return false;
    }
    current = state.parentsByNode.get(current);
  }
  const readContexts = webSocketExecutionContexts(read, state);
  return !(
    webSocketExecutionContexts(initializer, state).some((context) =>
      readContexts.includes(context),
    ) && (initializer.end ?? Infinity) >= (read.start ?? -1)
  );
};

const webSocketClassPrefixes = new WeakMap<
  JavaScriptSemanticAnalysisState,
  WeakMap<
    t.Class,
    {
      readonly keys: ReadonlyMap<t.Node, WebSocketSuspension | null>;
      readonly statics: ReadonlyMap<t.Node, WebSocketSuspension | null>;
    }
  >
>();

/** Index class evaluation once; all keys precede every static initializer. */
const webSocketClassPrefix = (
  member: t.Node,
  computedKey: boolean,
  state: JavaScriptSemanticAnalysisState,
): WebSocketSuspension | undefined => {
  const body = state.parentsByNode.get(member);
  const declaration =
    body === undefined ? undefined : state.parentsByNode.get(body);
  if (!t.isClass(declaration)) return undefined;
  let byClass = webSocketClassPrefixes.get(state);
  if (byClass === undefined) {
    byClass = new WeakMap();
    webSocketClassPrefixes.set(state, byClass);
  }
  let prefixes = byClass.get(declaration);
  if (prefixes === undefined) {
    const keys = new Map<t.Node, WebSocketSuspension | null>();
    const statics = new Map<t.Node, WebSocketSuspension | null>();
    let suspended = t.isNode(declaration.superClass)
      ? webSocketCompletedSuspension(declaration.superClass, state)
      : undefined;
    for (const item of declaration.body.body) {
      keys.set(item, suspended ?? null);
      if ((t.isClassProperty(item) || t.isClassMethod(item)) && item.computed)
        suspended = webSocketCompletedSuspension(item.key, state) ?? suspended;
    }
    for (const item of declaration.body.body) {
      statics.set(item, suspended ?? null);
      for (const initializer of webSocketStaticInitializers(item))
        suspended =
          webSocketCompletedSuspension(initializer, state) ?? suspended;
    }
    prefixes = { keys, statics };
    byClass.set(declaration, prefixes);
  }
  return (
    (computedKey ? prefixes.keys : prefixes.statics).get(member) ?? undefined
  );
};

/**
 * Keep local initialization ordered across suspension phases. A suspension cuts
 * off outer execution frames only after retaining the body that owns it. Calls
 * evaluate callee/arguments before bodies; classes evaluate keys, static values,
 * and construction arguments before instance fields and constructor bodies.
 */
export const webSocketExecutionContexts = (
  node: t.Node,
  state: JavaScriptSemanticAnalysisState,
): readonly t.Node[] => {
  const contexts: t.Node[] = [];
  let suspendedOwner: t.Node | undefined;
  const suspendedAt = (suspension: WebSocketSuspension | undefined): void => {
    if (suspension !== undefined)
      suspendedOwner = webSocketSuspensionOwner(suspension, state);
  };
  const suspendedAfter = (evaluated: t.Node): void =>
    suspendedAt(webSocketCompletedSuspension(evaluated, state));
  let current = node;
  for (;;) {
    const parent = state.parentsByNode.get(current);
    if (parent === undefined) return [...contexts, current];
    if (
      (t.isClassProperty(parent) || t.isClassPrivateProperty(parent)) &&
      parent.value === current
    ) {
      if (parent.static)
        suspendedAt(webSocketClassPrefix(parent, false, state));
      else {
        const construction = webSocketClassConstruction(parent, state);
        if (construction === undefined) return [...contexts, parent];
        suspendedAfter(construction);
      }
    }
    if (
      (t.isClassProperty(parent) || t.isClassMethod(parent)) &&
      parent.computed &&
      parent.key === current
    )
      suspendedAt(webSocketClassPrefix(parent, true, state));
    if (t.isStaticBlock(parent))
      suspendedAt(webSocketClassPrefix(parent, false, state));
    if (t.isFunction(parent)) {
      if (
        (t.isObjectMethod(parent) || t.isClassMethod(parent)) &&
        parent.key === current
      ) {
        current = parent;
        continue;
      }
      let invocation =
        t.isClassMethod(parent) && parent.kind === "constructor"
          ? webSocketClassConstruction(parent, state)
          : webSocketImmediateInvocation(parent, state);
      contexts.push(parent);
      const generatorBody =
        current === parent.body &&
        !t.isArrowFunctionExpression(parent) &&
        parent.generator;
      if (
        generatorBody &&
        invocation !== undefined &&
        !t.isNewExpression(invocation)
      )
        invocation = webSocketGeneratorResume(invocation, state);
      if (invocation === undefined) return contexts;
      suspendedAfter(invocation);
      if ((parent.async || generatorBody) && current === parent.body) {
        const continuation = webSocketContinuation(node, parent.body, state);
        if (continuation !== undefined)
          suspendedOwner = webSocketSuspensionOwner(continuation, state);
      }
      if (suspendedOwner === parent)
        return [...contexts, ...webSocketWaitingContexts(invocation, state)];
    }
    current = parent;
  }
};
