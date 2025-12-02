/**
 * Training Scheduler Service
 * Schedules and manages automated model retraining
 */

import cron from "node-cron";
import { mlTrainer } from "./ml-trainer.js";
import { modelPersistence } from "./model-persistence.js";

export interface TrainingJob {
  id: string;
  modelId: string;
  schedule: string; // cron expression
  lastRun?: Date;
  nextRun?: Date;
  status: "pending" | "running" | "completed" | "failed";
  lastResult?: {
    success: boolean;
    version?: number;
    error?: string;
    trainingTime?: number;
  };
  isActive: boolean;
}

export class TrainingSchedulerService {
  private jobs: Map<string, TrainingJob> = new Map();
  private tasks: Map<string, cron.ScheduledTask> = new Map();
  private readonly MAX_RETRIES = 3;
  private retryCount: Map<string, number> = new Map();

  /**
   * Initialize scheduler (runs after server startup)
   */
  initialize(): void {
    console.log("🔄 Training Scheduler initialized");
    this.setupDefaultJobs();
  }

  /**
   * Setup default training jobs
   */
  private setupDefaultJobs(): void {
    // Daily retraining at 2 AM
    this.createJob({
      id: "daily-training",
      modelId: "threat-detector",
      schedule: "0 2 * * *", // 2 AM daily
      isActive: true,
    });

    // Weekly comprehensive retraining at Sunday midnight
    this.createJob({
      id: "weekly-training",
      modelId: "threat-detector",
      schedule: "0 0 * * 0", // Sunday midnight
      isActive: true,
    });

    console.log("✅ Default training jobs created");
  }

  /**
   * Create a training job
   */
  createJob(job: TrainingJob): boolean {
    try {
      if (this.jobs.has(job.id)) {
        console.warn(`⚠️ Job ${job.id} already exists`);
        return false;
      }

      this.jobs.set(job.id, {
        ...job,
        status: "pending",
        nextRun: this.calculateNextRun(job.schedule),
      });

      if (job.isActive) {
        this.scheduleJob(job.id, job.schedule);
      }

      console.log(`✅ Training job created: ${job.id}`);
      return true;
    } catch (error) {
      console.error(`❌ Failed to create job ${job.id}:`, error);
      return false;
    }
  }

  /**
   * Schedule a job with cron
   */
  private scheduleJob(jobId: string, schedule: string): void {
    try {
      // Clear existing task if any
      if (this.tasks.has(jobId)) {
        this.tasks.get(jobId)?.stop();
        this.tasks.delete(jobId);
      }

      const task = cron.schedule(schedule, () => {
        this.runJob(jobId).catch((err) => console.error(`Job ${jobId} error:`, err));
      });

      this.tasks.set(jobId, task);
      console.log(`✅ Job scheduled: ${jobId} (${schedule})`);
    } catch (error) {
      console.error(`❌ Failed to schedule job ${jobId}:`, error);
    }
  }

  /**
   * Run a training job
   */
  private async runJob(jobId: string): Promise<void> {
    const job = this.jobs.get(jobId);
    if (!job) {
      console.error(`❌ Job not found: ${jobId}`);
      return;
    }

    try {
      job.status = "running";
      console.log(`▶️  Running training job: ${jobId}`);

      // Attempt training
      const result = await mlTrainer.train(undefined, job.modelId);

      if (result.success) {
        job.lastResult = {
          success: true,
          version: result.version,
          trainingTime: result.trainingTime,
        };
        job.status = "completed";
        this.retryCount.set(jobId, 0);

        console.log(`✅ Job completed successfully: ${jobId} (v${result.version})`);
      } else {
        throw new Error(result.error || "Training failed");
      }
    } catch (error) {
      const retries = (this.retryCount.get(jobId) || 0) + 1;
      this.retryCount.set(jobId, retries);

      console.error(`❌ Job failed (attempt ${retries}/${this.MAX_RETRIES}):`, error);

      job.lastResult = {
        success: false,
        error: error instanceof Error ? error.message : String(error),
      };

      if (retries < this.MAX_RETRIES) {
        console.log(`🔄 Retrying job in 5 minutes...`);
        setTimeout(() => this.runJob(jobId), 5 * 60 * 1000);
      } else {
        job.status = "failed";
        console.error(
          `❌ Job failed permanently: ${jobId} (max retries exceeded)`
        );

        // Fallback to previous model
        this.fallbackToPreviousModel(job.modelId);
      }
    } finally {
      job.lastRun = new Date();
      job.nextRun = this.calculateNextRun(
        this.jobs.get(jobId)?.schedule || "0 2 * * *"
      );
    }
  }

  /**
   * Fallback to previous model version on failure
   */
  private fallbackToPreviousModel(modelId: string): void {
    try {
      const models = modelPersistence.listModels();
      const model = models.find((m) => m.id === modelId);

      if (model && model.versions.length > 1) {
        const previousVersion = model.versions[model.versions.length - 2];
        const previousModel = modelPersistence.loadModel(modelId, previousVersion);

        if (previousModel) {
          console.log(
            `⚠️ Rolled back to model version ${previousVersion} for ${modelId}`
          );
        }
      }
    } catch (error) {
      console.error("❌ Fallback failed:", error);
    }
  }

  /**
   * Calculate next run time from cron expression (simplified)
   */
  private calculateNextRun(schedule: string): Date {
    // Simplified: return next occurrence based on schedule
    const now = new Date();

    if (schedule === "0 2 * * *") {
      // Daily 2 AM
      const next = new Date(now);
      next.setHours(2, 0, 0, 0);
      if (next <= now) next.setDate(next.getDate() + 1);
      return next;
    }

    if (schedule === "0 0 * * 0") {
      // Sunday midnight
      const next = new Date(now);
      const day = next.getDay();
      const daysUntilSunday = day === 0 ? 7 : 7 - day;
      next.setHours(0, 0, 0, 0);
      next.setDate(next.getDate() + daysUntilSunday);
      return next;
    }

    return new Date(now.getTime() + 24 * 60 * 60 * 1000);
  }

  /**
   * Get job status
   */
  getJobStatus(jobId: string): TrainingJob | null {
    return this.jobs.get(jobId) || null;
  }

  /**
   * List all jobs
   */
  listJobs(): TrainingJob[] {
    return Array.from(this.jobs.values());
  }

  /**
   * Enable job
   */
  enableJob(jobId: string): boolean {
    const job = this.jobs.get(jobId);
    if (!job) return false;

    job.isActive = true;
    this.scheduleJob(jobId, job.schedule);
    console.log(`✅ Job enabled: ${jobId}`);
    return true;
  }

  /**
   * Disable job
   */
  disableJob(jobId: string): boolean {
    const job = this.jobs.get(jobId);
    if (!job) return false;

    job.isActive = false;
    const task = this.tasks.get(jobId);
    if (task) {
      task.stop();
      this.tasks.delete(jobId);
    }

    console.log(`✅ Job disabled: ${jobId}`);
    return true;
  }

  /**
   * Trigger job immediately
   */
  triggerJobNow(jobId: string): Promise<void> {
    return this.runJob(jobId);
  }

  /**
   * Update job schedule
   */
  updateJobSchedule(jobId: string, newSchedule: string): boolean {
    const job = this.jobs.get(jobId);
    if (!job) return false;

    job.schedule = newSchedule;
    if (job.isActive) {
      this.scheduleJob(jobId, newSchedule);
    }

    console.log(`✅ Job schedule updated: ${jobId}`);
    return true;
  }

  /**
   * Delete job
   */
  deleteJob(jobId: string): boolean {
    const job = this.jobs.get(jobId);
    if (!job) return false;

    if (job.isActive) {
      this.disableJob(jobId);
    }

    this.jobs.delete(jobId);
    console.log(`✅ Job deleted: ${jobId}`);
    return true;
  }

  /**
   * Get job statistics
   */
  getStats(): {
    totalJobs: number;
    activeJobs: number;
    completedJobs: number;
    failedJobs: number;
  } {
    const jobs = Array.from(this.jobs.values());
    return {
      totalJobs: jobs.length,
      activeJobs: jobs.filter((j) => j.isActive).length,
      completedJobs: jobs.filter((j) => j.status === "completed").length,
      failedJobs: jobs.filter((j) => j.status === "failed").length,
    };
  }

  /**
   * Shutdown scheduler (stop all jobs)
   */
  shutdown(): void {
    this.tasks.forEach((task) => task.stop());
    this.tasks.clear();
    console.log("✅ Training Scheduler shut down");
  }
}

export const trainingScheduler = new TrainingSchedulerService();
