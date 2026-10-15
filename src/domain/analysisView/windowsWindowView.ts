import { z } from "zod";

import type { AnalysisError } from "../analysisErrorBase.js";
import { windowsWindowScreenshotResultSchema } from "../native/windowsWindowScreenshot.js";
import { err, ok, type Result } from "../result.js";
import type {
  AnalysisViewParent,
  AnalysisViewRequest,
  UnsignedAnalysisView,
} from "./analysisView.js";
import { completeWithinViewCoverage } from "./analysisViewCoverage.js";
import { analysisViewInputError } from "./analysisViewErrors.js";
import { parseAnalysisViewResult } from "./analysisViewParent.js";

const { data_base64: _imageBytes, ...metadata } =
  windowsWindowScreenshotResultSchema.shape.screenshot.shape;

/** Window identity and image facts without allocating another base64 response. */
export const windowsWindowSummarySchema = z.strictObject({
  target_sha256: windowsWindowScreenshotResultSchema.shape.target_sha256,
  window: windowsWindowScreenshotResultSchema.shape.window,
  screenshot: z.strictObject(metadata),
  gaps: windowsWindowScreenshotResultSchema.shape.gaps,
});

/** An explicit image read reuses the retained frame, without recapturing UI. */
export const windowsWindowViewRequestSchema = z.strictObject({
  kind: z.literal("windows-window"),
  facet: z.literal("screenshot"),
});

export const projectWindowsWindowView = (
  parent: AnalysisViewParent,
  view: AnalysisViewRequest,
): Result<UnsignedAnalysisView, AnalysisError> => {
  if (view.kind !== "summary" && view.kind !== "windows-window")
    return err(
      analysisViewInputError([
        {
          path: ["view"],
          reason: "invalid_value",
          message:
            "Windows window capture supports summary and windows-window screenshot views.",
        },
      ]),
    );
  const parsed = parseAnalysisViewResult(
    windowsWindowScreenshotResultSchema,
    parent,
  );
  if (!parsed.ok) return parsed;
  const report = parsed.value;
  const common = {
    parent_evidence_id: parent.evidenceId,
    parent_operation: "capture_windows_window_screenshot" as const,
    parent_digest: parent.evidenceId.slice(3),
    artifact:
      parent.subject == null
        ? { path: "", sha256: null }
        : {
            path: parent.subject.local_path,
            sha256: parent.subject.digest.sha256,
          },
    coverage: completeWithinViewCoverage(1, 1),
    limitations: [...parent.limitations],
    unknowns: [
      "Successful PNG capture does not establish complete rendering or physical-display visibility.",
    ],
  };
  if (view.kind === "windows-window")
    return ok({
      kind: "windows-window",
      view,
      item: report.screenshot,
      ...common,
    });
  const { data_base64: _bytes, ...screenshot } = report.screenshot;
  return ok({
    kind: "summary",
    view,
    ...common,
    summary: { ...report, screenshot },
  });
};
