/**
 * Model Persistence Service
 * Saves and loads trained ML models to/from disk with versioning
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MODELS_DIR = path.join(__dirname, "../models");

export interface SavedModel {
  id: string;
  name: string;
  version: number;
  type: "RandomForest" | "LinearModel" | "Ensemble";
  algorithm: string;
  metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1?: number;
    rocAuc?: number;
    confusionMatrix?: number[][];
  };
  featureImportance?: Record<string, number>;
  weights?: Record<string, number>;
  parameters?: Record<string, any>;
  trainingData: {
    samplesCount: number;
    featuresCount: number;
    trainDate: string;
    trainingTime: number; // ms
  };
  metadata?: Record<string, any>;
}

export class ModelPersistenceService {
  private modelsDir: string;

  constructor() {
    this.modelsDir = MODELS_DIR;
    this.initializeDirectory();
  }

  /**
   * Initialize models directory if not exists
   */
  private initializeDirectory(): void {
    if (!fs.existsSync(this.modelsDir)) {
      fs.mkdirSync(this.modelsDir, { recursive: true });
      console.log(`✅ Models directory created: ${this.modelsDir}`);
    }
  }

  /**
   * Save model to disk
   */
  saveModel(model: SavedModel): { success: boolean; path: string } {
    try {
      const filename = `${model.id}_v${model.version}.json`;
      const filepath = path.join(this.modelsDir, filename);

      // Add timestamp
      const modelWithTimestamp = {
        ...model,
        savedAt: new Date().toISOString(),
      };

      fs.writeFileSync(filepath, JSON.stringify(modelWithTimestamp, null, 2));
      console.log(`✅ Model saved: ${filename}`);

      return { success: true, path: filepath };
    } catch (error) {
      console.error("❌ Failed to save model:", error);
      return { success: false, path: "" };
    }
  }

  /**
   * Load model from disk
   */
  loadModel(modelId: string, version?: number): SavedModel | null {
    try {
      let filename: string;

      if (version !== undefined) {
        filename = `${modelId}_v${version}.json`;
      } else {
        // Load latest version
        const files = fs
          .readdirSync(this.modelsDir)
          .filter((f) => f.startsWith(`${modelId}_v`))
          .sort();

        if (files.length === 0) {
          console.warn(`⚠️ No models found for: ${modelId}`);
          return null;
        }

        filename = files[files.length - 1]; // Latest version
      }

      const filepath = path.join(this.modelsDir, filename);

      if (!fs.existsSync(filepath)) {
        console.warn(`⚠️ Model file not found: ${filename}`);
        return null;
      }

      const data = fs.readFileSync(filepath, "utf-8");
      const model: SavedModel = JSON.parse(data);

      console.log(`✅ Model loaded: ${filename}`);
      return model;
    } catch (error) {
      console.error("❌ Failed to load model:", error);
      return null;
    }
  }

  /**
   * List all available models
   */
  listModels(): Array<{ id: string; versions: number[] }> {
    try {
      const files = fs.readdirSync(this.modelsDir).filter((f) => f.endsWith(".json"));

      const models: Map<string, number[]> = new Map();

      files.forEach((file) => {
        const match = file.match(/^(.+)_v(\d+)\.json$/);
        if (match) {
          const [, modelId, version] = match;
          const versionNum = parseInt(version);

          if (!models.has(modelId)) {
            models.set(modelId, []);
          }

          models.get(modelId)!.push(versionNum);
        }
      });

      return Array.from(models.entries()).map(([id, versions]) => ({
        id,
        versions: versions.sort((a, b) => a - b),
      }));
    } catch (error) {
      console.error("❌ Failed to list models:", error);
      return [];
    }
  }

  /**
   * Get latest model version
   */
  getLatestModelVersion(modelId: string): SavedModel | null {
    const models = this.listModels();
    const model = models.find((m) => m.id === modelId);

    if (!model || model.versions.length === 0) {
      return null;
    }

    const latestVersion = model.versions[model.versions.length - 1];
    return this.loadModel(modelId, latestVersion);
  }

  /**
   * Delete model version
   */
  deleteModel(modelId: string, version: number): boolean {
    try {
      const filename = `${modelId}_v${version}.json`;
      const filepath = path.join(this.modelsDir, filename);

      if (!fs.existsSync(filepath)) {
        console.warn(`⚠️ Model not found: ${filename}`);
        return false;
      }

      fs.unlinkSync(filepath);
      console.log(`✅ Model deleted: ${filename}`);
      return true;
    } catch (error) {
      console.error("❌ Failed to delete model:", error);
      return false;
    }
  }

  /**
   * Get model info
   */
  getModelInfo(modelId: string, version?: number): SavedModel | null {
    if (version !== undefined) {
      return this.loadModel(modelId, version);
    }
    return this.getLatestModelVersion(modelId);
  }

  /**
   * Backup all models
   */
  backupModels(): { success: boolean; backupPath?: string } {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const backupDir = path.join(this.modelsDir, `backup_${timestamp}`);

      fs.mkdirSync(backupDir, { recursive: true });

      const files = fs.readdirSync(this.modelsDir).filter((f) => f.endsWith(".json"));

      files.forEach((file) => {
        const source = path.join(this.modelsDir, file);
        const dest = path.join(backupDir, file);
        fs.copyFileSync(source, dest);
      });

      console.log(`✅ Models backed up: ${backupDir}`);
      return { success: true, backupPath: backupDir };
    } catch (error) {
      console.error("❌ Failed to backup models:", error);
      return { success: false };
    }
  }

  /**
   * Clear old model versions (keep last N)
   */
  pruneOldVersions(modelId: string, keepCount: number = 3): number {
    try {
      const models = this.listModels();
      const model = models.find((m) => m.id === modelId);

      if (!model || model.versions.length <= keepCount) {
        return 0;
      }

      const versionsToDelete = model.versions.slice(0, -keepCount);
      let deleted = 0;

      versionsToDelete.forEach((version) => {
        if (this.deleteModel(modelId, version)) {
          deleted++;
        }
      });

      console.log(`✅ Pruned ${deleted} old versions of ${modelId}`);
      return deleted;
    } catch (error) {
      console.error("❌ Failed to prune old versions:", error);
      return 0;
    }
  }
}

export const modelPersistence = new ModelPersistenceService();
