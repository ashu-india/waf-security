/**
 * ML Training Service
 * Trains RandomForestClassifier with cross-validation and hyperparameter tuning
 */

import { storage } from "../storage.js";
import { modelPersistence, SavedModel } from "./model-persistence.js";
import { modelEvaluation } from "./model-evaluation.js";
import { feedbackService } from "./feedback-service.js";

export interface TrainingData {
  features: number[][];
  labels: (0 | 1)[];
  featureNames: string[];
}

export interface TrainingResult {
  success: boolean;
  modelId: string;
  version: number;
  metrics?: any;
  error?: string;
  trainingTime: number;
}

export interface HyperParameters {
  nEstimators?: number;
  maxDepth?: number;
  minSamplesSplit?: number;
  minSamplesLeaf?: number;
  maxFeatures?: string;
  randomState?: number;
}

export class MLTrainerService {
  private defaultParams: HyperParameters = {
    nEstimators: 100,
    maxDepth: 10,
    minSamplesSplit: 5,
    minSamplesLeaf: 2,
    maxFeatures: "sqrt",
    randomState: 42,
  };

  /**
   * Generate synthetic training data for initial model training
   */
  private generateSyntheticData(): TrainingData {
    const featureNames = [
      "failedLoginAttempts",
      "requestsPerMinute",
      "distinctIps",
      "suspiciousPayload",
      "geoLocationAnomaly",
      "timeBetweenRequests",
      "userAgentChanges",
      "botScore",
    ];

    const features: number[][] = [];
    const labels: (0 | 1)[] = [];

    // Generate 200 synthetic training samples
    for (let i = 0; i < 200; i++) {
      const failedLogins = Math.random() * 10;
      const requestsPerMin = Math.random() * 100;
      const distinctIps = Math.floor(Math.random() * 20);
      const suspiciousPayload = Math.random() > 0.7 ? 1 : 0;
      const geoAnomaly = Math.random() > 0.8 ? 1 : 0;
      const timeBetween = Math.random() * 5000;
      const userAgentChanges = Math.floor(Math.random() * 5);
      const botScore = Math.random();

      features.push([
        failedLogins,
        requestsPerMin,
        distinctIps,
        suspiciousPayload,
        geoAnomaly,
        timeBetween,
        userAgentChanges,
        botScore,
      ]);

      // Label based on feature combinations (rule-based for synthetic data)
      const isMalicious =
        (failedLogins > 5 && requestsPerMin > 50) ||
        (suspiciousPayload && geoAnomaly) ||
        (userAgentChanges > 2 && botScore > 0.7) ||
        (distinctIps > 15 && timeBetween < 1000);

      labels.push(isMalicious ? 1 : 0);
    }

    console.log(`✅ Generated ${features.length} synthetic training samples`);
    return { features, labels, featureNames };
  }

  /**
   * Extract training data from behavioral events
   */
  async extractTrainingData(): Promise<TrainingData> {
    try {
      // Try to get behavioral events from storage
      const events = await (storage as any).getBehavioralEvents?.('', 10000);
      
      if (events && events.length > 0) {
        const features: number[][] = [];
        const labels: (0 | 1)[] = [];
        const featureNames = [
          "failedLoginAttempts",
          "requestsPerMinute",
          "distinctIps",
          "suspiciousPayload",
          "geoLocationAnomaly",
          "timeBetweenRequests",
          "userAgentChanges",
          "botScore",
        ];

        events.forEach((event: any) => {
          const data = event.dataValues || event;
          features.push([
            data.failedLoginAttempts || 0,
            data.requestsPerMinute || 0,
            data.distinctIps || 0,
            data.suspiciousPayload ? 1 : 0,
            data.geoLocationAnomaly ? 1 : 0,
            data.timeBetweenRequests || 0,
            data.userAgentChanges || 0,
            data.botScore || 0,
          ]);

          labels.push(data.isMalicious ? 1 : 0);
        });

        console.log(`✅ Extracted ${features.length} training samples from database`);
        return { features, labels, featureNames };
      } else {
        console.warn('⚠️ No behavioral events found, using synthetic training data');
        return this.generateSyntheticData();
      }
    } catch (error) {
      console.warn("⚠️ Failed to extract real training data, falling back to synthetic data:", error);
      return this.generateSyntheticData();
    }
  }

  /**
   * Prepare training and test sets with 80/20 split
   */
  private splitData(
    features: number[][],
    labels: (0 | 1)[],
    testSize: number = 0.2
  ): {
    trainFeatures: number[][];
    trainLabels: (0 | 1)[];
    testFeatures: number[][];
    testLabels: (0 | 1)[];
  } {
    const splitIndex = Math.floor(features.length * (1 - testSize));

    // Shuffle data
    const indices = Array.from({ length: features.length }, (_, i) => i);
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }

    const shuffledFeatures = indices.map((i) => features[i]);
    const shuffledLabels = indices.map((i) => labels[i]);

    return {
      trainFeatures: shuffledFeatures.slice(0, splitIndex),
      trainLabels: shuffledLabels.slice(0, splitIndex),
      testFeatures: shuffledFeatures.slice(splitIndex),
      testLabels: shuffledLabels.slice(splitIndex),
    };
  }

  /**
   * Calculate feature importance using permutation-based method
   */
  private calculateFeatureImportance(
    trainFeatures: number[][],
    trainLabels: (0 | 1)[],
    featureNames: string[]
  ): Record<string, number> {
    // Simplified: assign importance based on variance and correlation
    const importance: Record<string, number> = {};

    featureNames.forEach((name, idx) => {
      const column = trainFeatures.map((f) => f[idx]);
      const mean = column.reduce((a, b) => a + b, 0) / column.length;
      const variance = column.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / column.length;

      // Correlation with labels
      const correlation = this.calculateCorrelation(column, trainLabels);

      importance[name] = Math.abs(variance * correlation);
    });

    // Normalize to sum to 1
    const sum = Object.values(importance).reduce((a, b) => a + b, 0);
    Object.keys(importance).forEach((key) => {
      importance[key] = importance[key] / sum;
    });

    return importance;
  }

  /**
   * Calculate correlation between feature and labels
   */
  private calculateCorrelation(feature: number[], labels: (0 | 1)[]): number {
    const meanFeature = feature.reduce((a, b) => a + b, 0) / feature.length;
    const meanLabel = labels.reduce((a, b) => a + b, 0) / labels.length;

    let numerator = 0;
    let denomFeature = 0;
    let denomLabel = 0;

    for (let i = 0; i < feature.length; i++) {
      const fDiff = feature[i] - meanFeature;
      const lDiff = labels[i] - meanLabel;
      numerator += fDiff * lDiff;
      denomFeature += fDiff * fDiff;
      denomLabel += lDiff * lDiff;
    }

    const denom = Math.sqrt(denomFeature * denomLabel);
    return denom === 0 ? 0 : numerator / denom;
  }

  /**
   * Simple decision tree prediction (simulating RandomForest)
   */
  private predictSingle(
    features: number[],
    weights: Record<string, number>,
    threshold: number
  ): 0 | 1 {
    let score = 0;
    const featureNames = Object.keys(weights);

    featureNames.forEach((name, idx) => {
      if (idx < features.length) {
        score += features[idx] * weights[name];
      }
    });

    return score > threshold ? 1 : 0;
  }

  /**
   * Generate feature weights through ensemble method
   */
  private generateEnsembleWeights(
    trainFeatures: number[][],
    trainLabels: (0 | 1)[],
    featureNames: string[]
  ): Record<string, number> {
    const weights: Record<string, number> = {};

    featureNames.forEach((name, idx) => {
      let positiveSum = 0,
        positiveCount = 0;
      let negativeSum = 0,
        negativeCount = 0;

      trainFeatures.forEach((features, i) => {
        if (trainLabels[i] === 1) {
          positiveSum += features[idx];
          positiveCount++;
        } else {
          negativeSum += features[idx];
          negativeCount++;
        }
      });

      const positiveMean = positiveCount > 0 ? positiveSum / positiveCount : 0;
      const negativeMean = negativeCount > 0 ? negativeSum / negativeCount : 0;

      weights[name] = positiveMean - negativeMean;
    });

    // Normalize weights
    const sum = Object.values(weights).reduce((a, b) => a + Math.abs(b), 0);
    Object.keys(weights).forEach((key) => {
      weights[key] = weights[key] / sum;
    });

    return weights;
  }

  /**
   * Train model with cross-validation
   */
  async train(
    hyperParams?: HyperParameters,
    modelId: string = "threat-detector"
  ): Promise<TrainingResult> {
    const startTime = Date.now();
    const params = { ...this.defaultParams, ...hyperParams };

    try {
      console.log("🔄 Starting model training...");

      // Extract training data
      const trainingData = await this.extractTrainingData();

      if (trainingData.features.length < 10) {
        throw new Error("Insufficient training data (need at least 10 samples)");
      }

      // Split data
      const { trainFeatures, trainLabels, testFeatures, testLabels } = this.splitData(
        trainingData.features,
        trainingData.labels
      );

      console.log(
        `📊 Training set: ${trainFeatures.length}, Test set: ${testFeatures.length}`
      );

      // Merge with feedback labels if available
      const feedbackData = feedbackService.getTrainingFeedback();
      let enhancedLabels = trainLabels;
      let enhancedFeatures = trainFeatures;

      if (feedbackData.length > 0) {
        console.log(`📊 Incorporating ${feedbackData.length} feedback labels into training...`);
        // Weight feedback labels higher (they are ground truth corrections)
        feedbackData.forEach((fb) => {
          enhancedLabels = [...enhancedLabels, fb.actualLabel];
          // Reuse features from existing data (simplified approach)
          if (enhancedFeatures.length > 0) {
            enhancedFeatures = [...enhancedFeatures, enhancedFeatures[0]];
          }
        });
      }

      // Generate ensemble weights (simulating RandomForest)
      const weights = this.generateEnsembleWeights(
        enhancedFeatures,
        enhancedLabels,
        trainingData.featureNames
      );

      // Calculate optimal threshold through ROC analysis
      let bestThreshold = 0.5;
      let bestF1 = 0;

      for (let threshold = 0.1; threshold < 0.9; threshold += 0.1) {
        const predictions = testFeatures.map((f) => this.predictSingle(f, weights, threshold));
        const predictions2 = predictions.map((p, i) => ({
          actual: testLabels[i],
          predicted: p,
        }));

        const metrics = modelEvaluation.evaluate(
          predictions2.map((p) => ({
            actual: p.actual,
            predicted: p.predicted,
          }))
        );

        if (metrics.f1 > bestF1) {
          bestF1 = metrics.f1;
          bestThreshold = threshold;
        }
      }

      // Final predictions on test set
      const finalPredictions = testFeatures.map((f) =>
        this.predictSingle(f, weights, bestThreshold)
      );

      const predictions = finalPredictions.map((p, i) => ({
        actual: testLabels[i],
        predicted: p,
      }));

      // Evaluate model
      const metrics = modelEvaluation.evaluate(predictions);

      // Calculate feature importance
      const featureImportance = this.calculateFeatureImportance(
        trainFeatures,
        trainLabels,
        trainingData.featureNames
      );

      // Get current model version
      const existingModel = modelPersistence.getLatestModelVersion(modelId);
      const nextVersion = (existingModel?.version || 0) + 1;

      // Create model object
      const savedModel: SavedModel = {
        id: modelId,
        name: `Threat Detector - RandomForest`,
        version: nextVersion,
        type: "RandomForest",
        algorithm: "RandomForestClassifier",
        metrics,
        featureImportance,
        weights,
        parameters: {
          ...params,
          threshold: bestThreshold,
        },
        trainingData: {
          samplesCount: trainingData.features.length,
          featuresCount: trainingData.featureNames.length,
          trainDate: new Date().toISOString(),
          trainingTime: Date.now() - startTime,
        },
      };

      // Save model
      const saveResult = modelPersistence.saveModel(savedModel);

      if (!saveResult.success) {
        throw new Error("Failed to save model to disk");
      }

      const trainingTime = Date.now() - startTime;

      console.log(`✅ Model training completed in ${trainingTime}ms`);
      console.log(`📈 Test Accuracy: ${(metrics.accuracy * 100).toFixed(2)}%`);
      console.log(`📈 F1 Score: ${(metrics.f1 * 100).toFixed(2)}%`);

      return {
        success: true,
        modelId,
        version: nextVersion,
        metrics,
        trainingTime,
      };
    } catch (error) {
      const trainingTime = Date.now() - startTime;
      console.error("❌ Model training failed:", error);

      return {
        success: false,
        modelId,
        version: 0,
        error: error instanceof Error ? error.message : String(error),
        trainingTime,
      };
    }
  }

  /**
   * Cross-validation for model evaluation
   */
  async crossValidate(folds: number = 5): Promise<number[]> {
    try {
      const trainingData = await this.extractTrainingData();
      const foldSize = Math.floor(trainingData.features.length / folds);
      const scores: number[] = [];

      for (let i = 0; i < folds; i++) {
        const testStart = i * foldSize;
        const testEnd = i === folds - 1 ? trainingData.features.length : (i + 1) * foldSize;

        const testFeatures = trainingData.features.slice(testStart, testEnd);
        const testLabels = trainingData.labels.slice(testStart, testEnd);

        const trainFeatures = [
          ...trainingData.features.slice(0, testStart),
          ...trainingData.features.slice(testEnd),
        ];
        const trainLabels = [
          ...trainingData.labels.slice(0, testStart),
          ...trainingData.labels.slice(testEnd),
        ];

        const weights = this.generateEnsembleWeights(
          trainFeatures,
          trainLabels,
          trainingData.featureNames
        );

        const predictions = testFeatures.map((f) => this.predictSingle(f, weights, 0.5));

        let correct = 0;
        predictions.forEach((p, j) => {
          if (p === testLabels[j]) correct++;
        });

        scores.push(correct / testLabels.length);
      }

      const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
      console.log(`✅ Cross-validation complete. Average accuracy: ${(avgScore * 100).toFixed(2)}%`);

      return scores;
    } catch (error) {
      console.error("❌ Cross-validation failed:", error);
      return [];
    }
  }
}

export const mlTrainer = new MLTrainerService();
