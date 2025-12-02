/**
 * ML Integration Layer for WAF
 * Connects ML scoring to the WAF engine
 */

import { MLScoringEngine, SimpleLinearModel, type RequestFeatures, type MLPrediction } from './ml-scoring';

const mlEngine = new MLScoringEngine();
const simpleModel = new SimpleLinearModel();

// Register default model
mlEngine.registerModel(simpleModel);

export { mlEngine, simpleModel };
export type { RequestFeatures, MLPrediction };
