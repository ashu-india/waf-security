/**
 * Feedback/Labeling Service
 * Collects ground truth labels from security team for model training
 */

import { storage } from "../storage.js";
import { v4 as uuidv4 } from "uuid";

export interface FeedbackLabel {
  id: string;
  requestId: string;
  tenantId: string;
  userId: string;
  actualLabel: 0 | 1; // 0 = legitimate, 1 = malicious
  predictedLabel: 0 | 1;
  falsePositive: boolean;
  falseNegative: boolean;
  confidence: number; // 0-1
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface FeedbackStats {
  totalLabeled: number;
  falsePositives: number;
  falseNegatives: number;
  agreementRate: number;
  recentLabels: FeedbackLabel[];
}

export class FeedbackService {
  private feedbackLabels: Map<string, FeedbackLabel> = new Map();
  private requestPredictions: Map<string, { predicted: 0 | 1; score: number }> = new Map();

  /**
   * Submit feedback label for a request
   */
  async submitFeedback(
    requestId: string,
    tenantId: string,
    userId: string,
    actualLabel: 0 | 1,
    predictedLabel: 0 | 1,
    notes?: string,
    confidence?: number
  ): Promise<FeedbackLabel> {
    try {
      const id = uuidv4();
      const now = new Date();

      const feedback: FeedbackLabel = {
        id,
        requestId,
        tenantId,
        userId,
        actualLabel,
        predictedLabel,
        falsePositive: actualLabel === 0 && predictedLabel === 1,
        falseNegative: actualLabel === 1 && predictedLabel === 0,
        confidence: confidence || 0.95,
        notes,
        createdAt: now,
        updatedAt: now,
      };

      this.feedbackLabels.set(id, feedback);

      console.log(
        `✅ Feedback recorded: ${feedback.falsePositive ? "FP" : feedback.falseNegative ? "FN" : "TP/TN"} for request ${requestId}`
      );

      return feedback;
    } catch (error) {
      console.error("❌ Failed to submit feedback:", error);
      throw error;
    }
  }

  /**
   * Get feedback for a specific request
   */
  getFeedbackByRequest(requestId: string): FeedbackLabel[] {
    return Array.from(this.feedbackLabels.values()).filter((f) => f.requestId === requestId);
  }

  /**
   * Get all feedback labels
   */
  getAllFeedback(limit: number = 10000): FeedbackLabel[] {
    const labels = Array.from(this.feedbackLabels.values());
    return labels
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit);
  }

  /**
   * Get feedback for model training
   */
  getTrainingFeedback(): Array<{
    actualLabel: 0 | 1;
    predictedLabel: 0 | 1;
    confidence: number;
  }> {
    return this.getAllFeedback().map((f) => ({
      actualLabel: f.actualLabel,
      predictedLabel: f.predictedLabel,
      confidence: f.confidence,
    }));
  }

  /**
   * Record prediction for comparison with feedback
   */
  recordPrediction(requestId: string, predicted: 0 | 1, score: number): void {
    this.requestPredictions.set(requestId, { predicted, score });
  }

  /**
   * Get feedback statistics
   */
  getStatistics(): FeedbackStats {
    const feedback = this.getAllFeedback();
    const falsePositives = feedback.filter((f) => f.falsePositive).length;
    const falseNegatives = feedback.filter((f) => f.falseNegative).length;

    let agreementRate = 0;
    if (feedback.length > 0) {
      const correct = feedback.filter((f) => f.actualLabel === f.predictedLabel).length;
      agreementRate = correct / feedback.length;
    }

    return {
      totalLabeled: feedback.length,
      falsePositives,
      falseNegatives,
      agreementRate,
      recentLabels: feedback.slice(0, 10),
    };
  }

  /**
   * Get feedback for specific tenant
   */
  getFeedbackByTenant(tenantId: string): FeedbackLabel[] {
    return Array.from(this.feedbackLabels.values())
      .filter((f) => f.tenantId === tenantId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Get false positives
   */
  getFalsePositives(): FeedbackLabel[] {
    return Array.from(this.feedbackLabels.values()).filter((f) => f.falsePositive);
  }

  /**
   * Get false negatives
   */
  getFalseNegatives(): FeedbackLabel[] {
    return Array.from(this.feedbackLabels.values()).filter((f) => f.falseNegative);
  }

  /**
   * Update feedback
   */
  async updateFeedback(id: string, updates: Partial<FeedbackLabel>): Promise<FeedbackLabel | null> {
    const feedback = this.feedbackLabels.get(id);
    if (!feedback) {
      return null;
    }

    const updated: FeedbackLabel = {
      ...feedback,
      ...updates,
      updatedAt: new Date(),
    };

    this.feedbackLabels.set(id, updated);
    return updated;
  }

  /**
   * Delete feedback
   */
  deleteFeedback(id: string): boolean {
    return this.feedbackLabels.delete(id);
  }

  /**
   * Clear all feedback (for testing)
   */
  clear(): void {
    this.feedbackLabels.clear();
    this.requestPredictions.clear();
  }

  /**
   * Get model performance improvement estimate
   */
  getPerformanceMetrics(): {
    totalFeedback: number;
    accuracyOnFeedback: number;
    falsePositiveRate: number;
    falseNegativeRate: number;
  } {
    const feedback = this.getAllFeedback();
    if (feedback.length === 0) {
      return {
        totalFeedback: 0,
        accuracyOnFeedback: 0,
        falsePositiveRate: 0,
        falseNegativeRate: 0,
      };
    }

    const correct = feedback.filter((f) => f.actualLabel === f.predictedLabel).length;
    const accuracy = correct / feedback.length;

    const negatives = feedback.filter((f) => f.actualLabel === 0);
    const fpRate = negatives.length > 0 ? feedback.filter((f) => f.falsePositive).length / negatives.length : 0;

    const positives = feedback.filter((f) => f.actualLabel === 1);
    const fnRate = positives.length > 0 ? feedback.filter((f) => f.falseNegative).length / positives.length : 0;

    return {
      totalFeedback: feedback.length,
      accuracyOnFeedback: accuracy,
      falsePositiveRate: fpRate,
      falseNegativeRate: fnRate,
    };
  }
}

export const feedbackService = new FeedbackService();
