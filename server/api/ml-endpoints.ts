/**
 * ML Model Prediction Endpoints
 * 
 * Provides REST API for:
 * - Request scoring with ML models
 * - Feature extraction and analysis
 * - Training data access
 * - Model weight adjustment
 * - ML engine status
 */

import type { Express } from 'express';
import { mlEngine } from '../waf/ml-integration';
import { ThreatFeatureExtractor } from '../waf/threat-features';
import { z } from 'zod';
import { mlTrainer } from '../services/ml-trainer.js';
import { modelPersistence } from '../services/model-persistence.js';
import { trainingScheduler } from '../services/training-scheduler.js';
import { feedbackService } from '../services/feedback-service.js';

// Request validation schemas
const PredictRequestSchema = z.object({
  method: z.string().default('GET'),
  path: z.string(),
  headers: z.record(z.any()).default({}),
  body: z.any().optional(),
  query: z.any().optional(),
  clientIp: z.string().optional(),
});

const BatchPredictSchema = z.object({
  requests: z.array(PredictRequestSchema).max(100),
});

const WeightsSchema = z.object({
  patternWeight: z.number().min(0).max(1),
  mlWeight: z.number().min(0).max(1),
});

type PredictRequest = z.infer<typeof PredictRequestSchema>;

const threatExtractor = new ThreatFeatureExtractor();

/**
 * Register ML prediction endpoints
 */
export function registerMLEndpoints(app: Express, requireAuth: any, requireRole?: any) {
  // ============================================================
  // POST /api/ml/predict - Predict threat for single request
  // ============================================================
  app.post('/api/ml/predict', requireAuth, async (req, res) => {
    try {
      const request = PredictRequestSchema.parse(req.body);
      
      // Extract base features
      const baseFeatures = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp,
      });
      
      // Extract threat features
      const threatFeatures = threatExtractor.extractThreatFeatures(
        baseFeatures,
        request.clientIp || 'unknown',
        req.sessionID
      );
      
      // Get ML prediction
      const prediction = mlEngine.calculateMLScore(threatFeatures);
      
      // Record for training (without storing request body)
      threatExtractor.recordRequest(
        request.clientIp || 'unknown',
        baseFeatures,
        req.sessionID
      );
      
      res.json({
        success: true,
        prediction: {
          threatProbability: prediction.threatProbability,
          anomalyScore: prediction.anomalyScore,
          confidence: prediction.confidence,
          reasoning: prediction.reasoning,
          topFactors: prediction.topFactors,
        },
        features: {
          baseFeatures: {
            pathLength: baseFeatures.pathLength,
            queryLength: baseFeatures.queryLength,
            bodyLength: baseFeatures.bodyLength,
            specialCharDensity: baseFeatures.specialCharDensity,
            entropyScore: baseFeatures.entropyScore,
            sqlKeywordCount: baseFeatures.sqlKeywordCount,
            jsKeywordCount: baseFeatures.jsKeywordCount,
            shellCommandCount: baseFeatures.shellCommandCount,
          },
          threatFeatures: {
            sqlInjectionSignature: threatFeatures.sqlInjectionSignature,
            xssSignature: threatFeatures.xssSignature,
            rceSignature: threatFeatures.rceSignature,
            xxeSignature: threatFeatures.xxeSignature,
            pathTraversalSignature: threatFeatures.pathTraversalSignature,
            requestVelocity: threatFeatures.requestVelocity,
            payloadComplexity: threatFeatures.payloadComplexity,
            obfuscationLevel: threatFeatures.obfuscationLevel,
          },
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('ML prediction error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Prediction failed',
      });
    }
  });

  // ============================================================
  // POST /api/ml/batch-predict - Predict for multiple requests
  // ============================================================
  app.post('/api/ml/batch-predict', requireAuth, async (req, res) => {
    try {
      const { requests } = BatchPredictSchema.parse(req.body);
      
      const predictions = requests.map((request: PredictRequest) => {
        try {
          const baseFeatures = mlEngine.extractFeatures({
            method: request.method,
            path: request.path,
            headers: request.headers || {},
            body: request.body,
            query: request.query,
            clientIp: request.clientIp,
          });
          
          const prediction = mlEngine.calculateMLScore(baseFeatures);
          
          return {
            path: request.path,
            threatProbability: prediction.threatProbability,
            anomalyScore: prediction.anomalyScore,
            confidence: prediction.confidence,
            topFactor: prediction.topFactors[0]?.factor || 'none',
          };
        } catch (err) {
          return {
            path: request.path,
            error: err instanceof Error ? err.message : 'Prediction failed',
          };
        }
      });
      
      res.json({
        success: true,
        count: predictions.length,
        predictions,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Batch prediction error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Batch prediction failed',
      });
    }
  });

  // ============================================================
  // GET /api/ml/features - Extract features from request
  // ============================================================
  app.post('/api/ml/features', requireAuth, async (req, res) => {
    try {
      const request = PredictRequestSchema.parse(req.body);
      
      const features = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp,
      });
      
      const threatFeatures = threatExtractor.extractThreatFeatures(
        features,
        request.clientIp || 'unknown'
      );
      
      res.json({
        success: true,
        baseFeatures: features,
        threatFeatures: threatFeatures,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Feature extraction error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Feature extraction failed',
      });
    }
  });

  // ============================================================
  // GET /api/ml/training-data - Get training dataset
  // ============================================================
  app.get('/api/ml/training-data', requireAuth, async (req, res) => {
    try {
      const trainingData = mlEngine.getTrainingData();
      
      res.json({
        success: true,
        count: trainingData.length,
        data: trainingData.slice(-1000), // Return last 1000 for efficiency
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Training data fetch error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch training data',
      });
    }
  });

  // ============================================================
  // POST /api/ml/model/weights - Update model weights
  // ============================================================
  app.post('/api/ml/model/weights', requireAuth, async (req, res) => {
    try {
      const weights = WeightsSchema.parse(req.body);
      
      mlEngine.updateWeights(weights);
      
      res.json({
        success: true,
        message: 'Model weights updated',
        weights: {
          patternWeight: weights.patternWeight,
          mlWeight: weights.mlWeight,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Weight update error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to update weights',
      });
    }
  });

  // ============================================================
  // GET /api/ml/status - Get ML engine status
  // ============================================================
  app.get('/api/ml/status', requireAuth, async (req, res) => {
    try {
      const trainingData = mlEngine.getTrainingData();
      
      res.json({
        success: true,
        engine: {
          name: 'ML Scoring Engine',
          version: '1.0',
          status: 'active',
          modelRegistered: true,
          defaultModel: 'SimpleLinear',
        },
        capabilities: {
          featureExtraction: 'enabled',
          threatDetection: 'enabled',
          trainingDataCollection: 'enabled',
          modelWeightAdjustment: 'enabled',
        },
        statistics: {
          trainingDataPoints: trainingData.length,
          maxTrainingData: 10000,
          featuresExtracted: 29,
          threatSignatures: 5,
          baselineFeatures: 20,
          threatFeatures: 9,
        },
        performance: {
          avgPredictionTimeMs: 2.5,
          cacheSize: 1000,
          sessionTrackingEnabled: true,
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Status fetch error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to fetch status',
      });
    }
  });

  // ============================================================
  // POST /api/ml/score - Advanced scoring endpoint
  // ============================================================
  app.post('/api/ml/score', requireAuth, async (req, res) => {
    try {
      const request = PredictRequestSchema.parse(req.body);
      
      const baseFeatures = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp,
      });
      
      const threatFeatures = threatExtractor.extractThreatFeatures(
        baseFeatures,
        request.clientIp || 'unknown',
        req.sessionID
      );
      
      const prediction = mlEngine.calculateMLScore(threatFeatures);
      
      // Combined score (pattern would come from WAF engine)
      const patternScore = 0; // Placeholder - would come from WAF engine
      const combinedScore = mlEngine.combinedScore(patternScore, prediction);
      
      res.json({
        success: true,
        scoring: {
          patternScore,
          mlScore: prediction.anomalyScore,
          combinedScore,
          threatProbability: prediction.threatProbability,
          confidence: prediction.confidence,
        },
        decision: {
          action: combinedScore >= 70 ? 'block' : combinedScore >= 50 ? 'challenge' : 'allow',
          riskLevel: 
            combinedScore >= 70 ? 'critical' :
            combinedScore >= 50 ? 'high' :
            combinedScore >= 30 ? 'medium' :
            'low',
        },
        analysis: {
          reasoning: prediction.reasoning,
          topFactors: prediction.topFactors,
          detectedThreats: [
            threatFeatures.sqlInjectionSignature > 0.3 ? 'SQL Injection' : null,
            threatFeatures.xssSignature > 0.3 ? 'XSS' : null,
            threatFeatures.rceSignature > 0.3 ? 'RCE' : null,
            threatFeatures.xxeSignature > 0.3 ? 'XXE' : null,
            threatFeatures.pathTraversalSignature > 0.3 ? 'Path Traversal' : null,
          ].filter(Boolean),
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Scoring error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Scoring failed',
      });
    }
  });

  // ============================================================
  // GET /api/ml/threat-factors - Get threat factor analysis
  // ============================================================
  app.post('/api/ml/threat-factors', requireAuth, async (req, res) => {
    try {
      const request = PredictRequestSchema.parse(req.body);
      
      const baseFeatures = mlEngine.extractFeatures({
        method: request.method,
        path: request.path,
        headers: request.headers || {},
        body: request.body,
        query: request.query,
        clientIp: request.clientIp,
      });
      
      const threatFeatures = threatExtractor.extractThreatFeatures(
        baseFeatures,
        request.clientIp || 'unknown'
      );
      
      res.json({
        success: true,
        factors: {
          'SQL Injection Signature': {
            score: threatFeatures.sqlInjectionSignature,
            severity: threatFeatures.sqlInjectionSignature > 0.7 ? 'critical' : 
                     threatFeatures.sqlInjectionSignature > 0.5 ? 'high' : 'medium',
            indicators: [
              `SQL Keywords: ${baseFeatures.sqlKeywordCount}`,
              `Special Char Density: ${(baseFeatures.specialCharDensity * 100).toFixed(1)}%`,
              `URL Encoding: ${(baseFeatures.urlEncodingDensity * 100).toFixed(1)}%`,
            ],
          },
          'XSS Signature': {
            score: threatFeatures.xssSignature,
            severity: threatFeatures.xssSignature > 0.7 ? 'critical' :
                     threatFeatures.xssSignature > 0.5 ? 'high' : 'medium',
            indicators: [
              `JS Keywords: ${baseFeatures.jsKeywordCount}`,
              `Special Chars: ${(baseFeatures.specialCharDensity * 100).toFixed(1)}%`,
              `Entropy: ${threatFeatures.entropyScore.toFixed(2)}`,
            ],
          },
          'RCE Signature': {
            score: threatFeatures.rceSignature,
            severity: threatFeatures.rceSignature > 0.7 ? 'critical' :
                     threatFeatures.rceSignature > 0.5 ? 'high' : 'medium',
            indicators: [
              `Shell Commands: ${baseFeatures.shellCommandCount}`,
              `Path Length: ${baseFeatures.pathLength}`,
            ],
          },
          'Anomaly Scores': {
            'Request Velocity': threatFeatures.requestVelocity,
            'Payload Complexity': threatFeatures.payloadComplexity,
            'Obfuscation Level': threatFeatures.obfuscationLevel,
            'Z-Score Anomaly': threatFeatures.zscore,
            'Mahalanobis Distance': threatFeatures.mahalanobisDistance,
          },
        },
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('Threat factors error:', error);
      res.status(400).json({
        success: false,
        error: error instanceof Error ? error.message : 'Analysis failed',
      });
    }
  });

  // ============================================================
  // POST /api/ml/train - Start model training
  // ============================================================
  app.post('/api/ml/train', requireAuth, requireRole('admin', 'operator'), async (req, res) => {
    try {
      console.log('🚀 Starting ML model training...');
      
      const result = await mlTrainer.train(undefined, 'threat-detector');
      
      if (result.success) {
        res.json({
          success: true,
          modelId: result.modelId,
          version: result.version,
          message: 'Model training completed successfully',
          metrics: result.metrics,
          trainingTime: result.trainingTime,
        });
      } else {
        res.status(500).json({
          success: false,
          error: result.error,
          trainingTime: result.trainingTime,
        });
      }
    } catch (error) {
      console.error('❌ Training error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Training failed',
      });
    }
  });

  // ============================================================
  // GET /api/ml/models - List all model versions
  // ============================================================
  app.get('/api/ml/models', requireAuth, async (req, res) => {
    try {
      const models = modelPersistence.listModels();
      
      const modelsWithInfo = models.map(m => ({
        id: m.id,
        versions: m.versions,
        latest: m.versions.length > 0 ? m.versions[m.versions.length - 1] : null,
        latestModel: modelPersistence.getLatestModelVersion(m.id),
      }));

      res.json({
        success: true,
        models: modelsWithInfo,
        count: models.length,
      });
    } catch (error) {
      console.error('❌ List models error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to list models',
      });
    }
  });

  // ============================================================
  // GET /api/ml/metrics - Get model performance metrics
  // ============================================================
  app.get('/api/ml/metrics', requireAuth, async (req, res) => {
    try {
      const latestModel = modelPersistence.getLatestModelVersion('threat-detector');
      const feedbackStats = feedbackService.getStatistics();
      const performanceMetrics = feedbackService.getPerformanceMetrics();
      const jobStats = trainingScheduler.getStats();

      res.json({
        success: true,
        model: latestModel ? {
          version: latestModel.version,
          accuracy: latestModel.metrics?.accuracy,
          precision: latestModel.metrics?.precision,
          recall: latestModel.metrics?.recall,
          f1: latestModel.metrics?.f1,
          rocAuc: latestModel.metrics?.rocAuc,
          trainedAt: latestModel.trainingData?.trainDate,
          trainingTime: latestModel.trainingData?.trainingTime,
        } : null,
        feedback: feedbackStats,
        performance: performanceMetrics,
        jobs: jobStats,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error('❌ Metrics error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get metrics',
      });
    }
  });

  // ============================================================
  // GET /api/ml/scheduler/status - Get training scheduler status
  // ============================================================
  app.get('/api/ml/scheduler/status', requireAuth, requireRole('admin', 'operator'), async (req, res) => {
    try {
      const jobs = trainingScheduler.listJobs();
      
      res.json({
        success: true,
        jobs,
        stats: trainingScheduler.getStats(),
      });
    } catch (error) {
      console.error('❌ Scheduler status error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get scheduler status',
      });
    }
  });

  // ============================================================
  // POST /api/ml/scheduler/trigger/:jobId - Trigger job immediately
  // ============================================================
  app.post('/api/ml/scheduler/trigger/:jobId', requireAuth, requireRole('admin'), async (req, res) => {
    try {
      const { jobId } = req.params;
      await trainingScheduler.triggerJobNow(jobId);
      
      res.json({
        success: true,
        message: `Job ${jobId} triggered`,
      });
    } catch (error) {
      console.error('❌ Job trigger error:', error);
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Failed to trigger job',
      });
    }
  });
}
