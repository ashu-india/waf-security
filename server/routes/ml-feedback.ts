/**
 * ML Feedback Routes
 * Handle feedback/labeling submissions and management
 */

import { Router, Request, Response } from "express";
import { feedbackService } from "../services/feedback-service.js";

// Simple auth check - checking if user is authenticated
function requireAuth(req: any, res: any, next: any) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  next();
}

const router = Router();

/**
 * POST /api/ml/feedback
 * Submit feedback label for a request
 */
router.post("/api/ml/feedback", requireAuth, async (req: Request, res: Response) => {
  try {
    const { requestId, tenantId, actualLabel, predictedLabel, notes, confidence } = req.body;

    if (!requestId || actualLabel === undefined || predictedLabel === undefined) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const feedback = await feedbackService.submitFeedback(
      requestId,
      tenantId || "",
      req.user?.id || "system",
      actualLabel as 0 | 1,
      predictedLabel as 0 | 1,
      notes,
      confidence
    );

    res.json({
      success: true,
      feedback,
      message: `Feedback recorded: ${feedback.falsePositive ? "false positive" : feedback.falseNegative ? "false negative" : "correct prediction"}`,
    });
  } catch (error) {
    console.error("❌ Feedback submission error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to submit feedback",
    });
  }
});

/**
 * GET /api/ml/feedback
 * Get all feedback labels
 */
router.get("/api/ml/feedback", requireAuth, async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 1000;
    const feedback = feedbackService.getAllFeedback(limit);

    res.json({
      success: true,
      count: feedback.length,
      feedback,
    });
  } catch (error) {
    console.error("❌ Get feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve feedback",
    });
  }
});

/**
 * GET /api/ml/feedback/stats
 * Get feedback statistics
 */
router.get("/api/ml/feedback/stats", requireAuth, async (req: Request, res: Response) => {
  try {
    const stats = feedbackService.getStatistics();
    const metrics = feedbackService.getPerformanceMetrics();

    res.json({
      success: true,
      statistics: stats,
      metrics,
    });
  } catch (error) {
    console.error("❌ Get stats error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve stats",
    });
  }
});

/**
 * GET /api/ml/feedback/request/:requestId
 * Get feedback for specific request
 */
router.get("/api/ml/feedback/request/:requestId", requireAuth, async (req: Request, res: Response) => {
  try {
    const feedback = feedbackService.getFeedbackByRequest(req.params.requestId);

    res.json({
      success: true,
      count: feedback.length,
      feedback,
    });
  } catch (error) {
    console.error("❌ Get request feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve request feedback",
    });
  }
});

/**
 * GET /api/ml/feedback/tenant/:tenantId
 * Get feedback for specific tenant
 */
router.get("/api/ml/feedback/tenant/:tenantId", requireAuth, async (req: Request, res: Response) => {
  try {
    const feedback = feedbackService.getFeedbackByTenant(req.params.tenantId);

    res.json({
      success: true,
      count: feedback.length,
      feedback,
    });
  } catch (error) {
    console.error("❌ Get tenant feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve tenant feedback",
    });
  }
});

/**
 * GET /api/ml/feedback/false-positives
 * Get all false positives
 */
router.get("/api/ml/feedback/false-positives", requireAuth, async (req: Request, res: Response) => {
  try {
    const fps = feedbackService.getFalsePositives();

    res.json({
      success: true,
      count: fps.length,
      falsePositives: fps,
    });
  } catch (error) {
    console.error("❌ Get false positives error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve false positives",
    });
  }
});

/**
 * GET /api/ml/feedback/false-negatives
 * Get all false negatives
 */
router.get("/api/ml/feedback/false-negatives", requireAuth, async (req: Request, res: Response) => {
  try {
    const fns = feedbackService.getFalseNegatives();

    res.json({
      success: true,
      count: fns.length,
      falseNegatives: fns,
    });
  } catch (error) {
    console.error("❌ Get false negatives error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to retrieve false negatives",
    });
  }
});

/**
 * PUT /api/ml/feedback/:id
 * Update feedback
 */
router.put("/api/ml/feedback/:id", requireAuth, async (req: Request, res: Response) => {
  try {
    const updated = await feedbackService.updateFeedback(req.params.id, req.body);

    if (!updated) {
      return res.status(404).json({ error: "Feedback not found" });
    }

    res.json({
      success: true,
      feedback: updated,
    });
  } catch (error) {
    console.error("❌ Update feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to update feedback",
    });
  }
});

/**
 * DELETE /api/ml/feedback/:id
 * Delete feedback
 */
router.delete("/api/ml/feedback/:id", requireAuth, async (req: Request, res: Response) => {
  try {
    const deleted = feedbackService.deleteFeedback(req.params.id);

    if (!deleted) {
      return res.status(404).json({ error: "Feedback not found" });
    }

    res.json({
      success: true,
      message: "Feedback deleted",
    });
  } catch (error) {
    console.error("❌ Delete feedback error:", error);
    res.status(500).json({
      error: error instanceof Error ? error.message : "Failed to delete feedback",
    });
  }
});

export default router;
