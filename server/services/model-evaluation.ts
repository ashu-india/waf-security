/**
 * Model Evaluation Service
 * Calculates precision, recall, F1, ROC-AUC, and confusion matrix
 */

export interface EvaluationMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  rocAuc: number;
  confusionMatrix: {
    truePositives: number;
    trueNegatives: number;
    falsePositives: number;
    falseNegatives: number;
  };
  specificityTpr: number;
  sensitivityFpr: number;
}

export interface PredictionResult {
  actual: number | boolean; // 0 or 1, false or true
  predicted: number | boolean; // 0 or 1, false or true
  probability?: number; // 0-1 confidence
}

export class ModelEvaluationService {
  /**
   * Calculate comprehensive evaluation metrics
   */
  evaluate(predictions: PredictionResult[]): EvaluationMetrics {
    if (predictions.length === 0) {
      throw new Error("No predictions provided");
    }

    const normalized = this.normalizePredictions(predictions);
    const cm = this.calculateConfusionMatrix(normalized);
    const accuracy = this.calculateAccuracy(cm);
    const precision = this.calculatePrecision(cm);
    const recall = this.calculateRecall(cm);
    const f1 = this.calculateF1(precision, recall);
    const rocAuc = this.calculateROCAuc(normalized);

    return {
      accuracy,
      precision,
      recall,
      f1,
      rocAuc,
      confusionMatrix: cm,
      specificityTpr: this.calculateSpecificity(cm),
      sensitivityFpr: this.calculateSensitivity(cm),
    };
  }

  /**
   * Normalize predictions to binary (0/1)
   */
  private normalizePredictions(predictions: PredictionResult[]): Array<{ actual: number; predicted: number }> {
    return predictions.map((p) => ({
      actual: typeof p.actual === "boolean" ? (p.actual ? 1 : 0) : p.actual,
      predicted: typeof p.predicted === "boolean" ? (p.predicted ? 1 : 0) : p.predicted,
    }));
  }

  /**
   * Calculate confusion matrix
   */
  private calculateConfusionMatrix(
    predictions: Array<{ actual: number; predicted: number }>
  ): {
    truePositives: number;
    trueNegatives: number;
    falsePositives: number;
    falseNegatives: number;
  } {
    let tp = 0,
      tn = 0,
      fp = 0,
      fn = 0;

    predictions.forEach((p) => {
      if (p.actual === 1 && p.predicted === 1) tp++;
      else if (p.actual === 0 && p.predicted === 0) tn++;
      else if (p.actual === 0 && p.predicted === 1) fp++;
      else if (p.actual === 1 && p.predicted === 0) fn++;
    });

    return { truePositives: tp, trueNegatives: tn, falsePositives: fp, falseNegatives: fn };
  }

  /**
   * Calculate accuracy: (TP + TN) / (TP + TN + FP + FN)
   */
  private calculateAccuracy(cm: {
    truePositives: number;
    trueNegatives: number;
    falsePositives: number;
    falseNegatives: number;
  }): number {
    const total = cm.truePositives + cm.trueNegatives + cm.falsePositives + cm.falseNegatives;
    if (total === 0) return 0;
    return (cm.truePositives + cm.trueNegatives) / total;
  }

  /**
   * Calculate precision: TP / (TP + FP)
   */
  private calculatePrecision(cm: {
    truePositives: number;
    falsePositives: number;
  }): number {
    const denominator = cm.truePositives + cm.falsePositives;
    if (denominator === 0) return 0;
    return cm.truePositives / denominator;
  }

  /**
   * Calculate recall: TP / (TP + FN)
   */
  private calculateRecall(cm: { truePositives: number; falseNegatives: number }): number {
    const denominator = cm.truePositives + cm.falseNegatives;
    if (denominator === 0) return 0;
    return cm.truePositives / denominator;
  }

  /**
   * Calculate F1 score: 2 * (Precision * Recall) / (Precision + Recall)
   */
  private calculateF1(precision: number, recall: number): number {
    const denominator = precision + recall;
    if (denominator === 0) return 0;
    return 2 * (precision * recall) / denominator;
  }

  /**
   * Calculate specificity (True Negative Rate): TN / (TN + FP)
   */
  private calculateSpecificity(cm: {
    trueNegatives: number;
    falsePositives: number;
  }): number {
    const denominator = cm.trueNegatives + cm.falsePositives;
    if (denominator === 0) return 0;
    return cm.trueNegatives / denominator;
  }

  /**
   * Calculate sensitivity (True Positive Rate): TP / (TP + FN)
   */
  private calculateSensitivity(cm: { truePositives: number; falseNegatives: number }): number {
    const denominator = cm.truePositives + cm.falseNegatives;
    if (denominator === 0) return 0;
    return cm.truePositives / denominator;
  }

  /**
   * Calculate ROC-AUC (simplified without probability thresholds)
   */
  private calculateROCAuc(predictions: Array<{ actual: number; predicted: number }>): number {
    // Simplified AUC calculation
    // In production, would use probability scores and sweep thresholds
    let auc = 0;
    let n_pos = 0,
      n_neg = 0;

    predictions.forEach((p) => {
      if (p.actual === 1) n_pos++;
      else n_neg++;
    });

    if (n_pos === 0 || n_neg === 0) return 0.5;

    // Count concordant and discordant pairs
    let concordant = 0,
      discordant = 0;

    for (let i = 0; i < predictions.length; i++) {
      for (let j = 0; j < predictions.length; j++) {
        if (predictions[i].actual === 1 && predictions[j].actual === 0) {
          if (predictions[i].predicted > predictions[j].predicted) concordant++;
          else if (predictions[i].predicted < predictions[j].predicted) discordant++;
        }
      }
    }

    const totalPairs = n_pos * n_neg;
    if (totalPairs === 0) return 0.5;

    auc = concordant / totalPairs;
    return Math.max(0, Math.min(1, auc));
  }

  /**
   * Generate confusion matrix display
   */
  displayConfusionMatrix(cm: {
    truePositives: number;
    trueNegatives: number;
    falsePositives: number;
    falseNegatives: number;
  }): string {
    return `
    ┌─────────────────────────────────┐
    │     Predicted Positive Negative │
    │ Actual                          │
    │ Positive       ${cm.truePositives}           ${cm.falseNegatives}      │
    │ Negative       ${cm.falsePositives}           ${cm.trueNegatives}      │
    └─────────────────────────────────┘
    `;
  }

  /**
   * Generate evaluation report
   */
  generateReport(metrics: EvaluationMetrics): string {
    return `
    ╔════════════════════════════════════════╗
    ║   Model Evaluation Report              ║
    ╠════════════════════════════════════════╣
    ║ Accuracy:        ${(metrics.accuracy * 100).toFixed(2)}%                ║
    ║ Precision:       ${(metrics.precision * 100).toFixed(2)}%                ║
    ║ Recall:          ${(metrics.recall * 100).toFixed(2)}%                ║
    ║ F1 Score:        ${(metrics.f1 * 100).toFixed(2)}%                ║
    ║ ROC-AUC:         ${(metrics.rocAuc * 100).toFixed(2)}%                ║
    ║                                        ║
    ║ Specificity:     ${(metrics.specificityTpr * 100).toFixed(2)}%                ║
    ║ Sensitivity:     ${(metrics.sensitivityFpr * 100).toFixed(2)}%                ║
    ╠════════════════════════════════════════╣
    ║ Confusion Matrix:                      ║
    ║ TP: ${metrics.confusionMatrix.truePositives}  FP: ${metrics.confusionMatrix.falsePositives}                    ║
    ║ FN: ${metrics.confusionMatrix.falseNegatives}  TN: ${metrics.confusionMatrix.trueNegatives}                    ║
    ╚════════════════════════════════════════╝
    `;
  }
}

export const modelEvaluation = new ModelEvaluationService();
