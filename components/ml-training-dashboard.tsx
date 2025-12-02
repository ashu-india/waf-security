import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { AlertCircle, Play, Zap, TrendingUp } from 'lucide-react';

export interface MLMetrics {
  model: {
    version: number;
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    rocAuc: number;
    trainedAt: string;
    trainingTime: number;
  } | null;
  feedback: {
    totalLabeled: number;
    falsePositives: number;
    falseNegatives: number;
    agreementRate: number;
  };
  performance: {
    totalFeedback: number;
    accuracyOnFeedback: number;
    falsePositiveRate: number;
    falseNegativeRate: number;
  };
  jobs: {
    totalJobs: number;
    activeJobs: number;
    completedJobs: number;
    failedJobs: number;
  };
}

export interface TrainingJob {
  id: string;
  modelId: string;
  schedule: string;
  lastRun?: Date;
  nextRun?: Date;
  status: 'pending' | 'running' | 'completed' | 'failed';
  isActive: boolean;
}

export function MLTrainingDashboard() {
  const [metrics, setMetrics] = useState<MLMetrics | null>(null);
  const [jobs, setJobs] = useState<TrainingJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [training, setTraining] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMetrics();
    fetchSchedulerStatus();
    const interval = setInterval(() => {
      fetchMetrics();
    }, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);

  const fetchMetrics = async () => {
    try {
      const res = await fetch('/api/ml/metrics', { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch metrics');
      const data = await res.json();
      setMetrics(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch metrics');
    }
  };

  const fetchSchedulerStatus = async () => {
    try {
      const res = await fetch('/api/ml/scheduler/status', { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch scheduler status');
      const data = await res.json();
      setJobs(data.jobs);
    } catch (err) {
      console.error('Failed to fetch scheduler status:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleTrainModel = async () => {
    setTraining(true);
    try {
      const res = await fetch('/api/ml/train', { method: 'POST', credentials: 'include' });
      if (!res.ok) throw new Error('Training failed');
      const result = await res.json();
      
      // Show success message
      alert(`✅ Training completed! Model v${result.version} trained in ${(result.trainingTime / 1000).toFixed(1)}s`);
      
      // Refresh metrics
      await fetchMetrics();
      await fetchSchedulerStatus();
    } catch (err) {
      alert(`❌ Training error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setTraining(false);
    }
  };

  const handleTriggerJob = async (jobId: string) => {
    try {
      const res = await fetch(`/api/ml/scheduler/trigger/${jobId}`, { method: 'POST', credentials: 'include' });
      if (!res.ok) throw new Error('Failed to trigger job');
      alert(`✅ Job ${jobId} triggered`);
      await fetchSchedulerStatus();
    } catch (err) {
      alert(`❌ Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  };

  if (loading) return <div className="p-8 text-center">Loading...</div>;

  const chartData = metrics ? [
    { name: 'Accuracy', value: (metrics.model?.accuracy || 0) * 100 },
    { name: 'Precision', value: (metrics.model?.precision || 0) * 100 },
    { name: 'Recall', value: (metrics.model?.recall || 0) * 100 },
    { name: 'F1', value: (metrics.model?.f1 || 0) * 100 },
  ] : [];

  return (
    <div className="space-y-6">
      {error && (
        <Card className="border-red-500 bg-red-50">
          <CardContent className="pt-6 flex items-center gap-2 text-red-700">
            <AlertCircle className="h-5 w-5" />
            {error}
          </CardContent>
        </Card>
      )}

      {/* Model Status Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Zap className="h-5 w-5" />
              Current Model
            </span>
            {metrics?.model && (
              <Badge variant="outline">v{metrics.model.version}</Badge>
            )}
          </CardTitle>
          <CardDescription>
            {metrics?.model ? `Trained ${new Date(metrics.model.trainedAt).toLocaleString()}` : 'No model trained yet'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {metrics?.model ? (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-blue-50 p-3 rounded">
                  <div className="text-xs text-gray-600">Accuracy</div>
                  <div className="text-xl font-bold text-blue-600">
                    {(metrics.model.accuracy * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="bg-green-50 p-3 rounded">
                  <div className="text-xs text-gray-600">Precision</div>
                  <div className="text-xl font-bold text-green-600">
                    {(metrics.model.precision * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="bg-purple-50 p-3 rounded">
                  <div className="text-xs text-gray-600">Recall</div>
                  <div className="text-xl font-bold text-purple-600">
                    {(metrics.model.recall * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="bg-orange-50 p-3 rounded">
                  <div className="text-xs text-gray-600">F1 Score</div>
                  <div className="text-xl font-bold text-orange-600">
                    {(metrics.model.f1 * 100).toFixed(1)}%
                  </div>
                </div>
              </div>
              
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis domain={[0, 100]} />
                    <Tooltip formatter={(value) => `${value.toFixed(1)}%`} />
                    <Bar dataKey="value" fill="#3b82f6" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <p className="text-sm text-gray-600">
                Training time: {(metrics.model.trainingTime / 1000).toFixed(1)}s
              </p>
            </>
          ) : (
            <p className="text-gray-600">No model has been trained yet. Click "Start Training" to train the first model.</p>
          )}
        </CardContent>
      </Card>

      {/* Training Control Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5" />
            Model Training
          </CardTitle>
          <CardDescription>Train or retrain the threat detection model</CardDescription>
        </CardHeader>
        <CardContent>
          <Button
            onClick={handleTrainModel}
            disabled={training}
            className="w-full md:w-auto"
            size="lg"
          >
            {training ? (
              <>
                <span className="animate-spin mr-2">⚙️</span>
                Training...
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" />
                Start Training
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Feedback Stats Card */}
      {metrics?.feedback && (
        <Card>
          <CardHeader>
            <CardTitle>Feedback Statistics</CardTitle>
            <CardDescription>Ground truth labels collected from security team</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-50 p-3 rounded">
                <div className="text-xs text-gray-600">Total Labeled</div>
                <div className="text-2xl font-bold">{metrics.feedback.totalLabeled}</div>
              </div>
              <div className="bg-red-50 p-3 rounded">
                <div className="text-xs text-gray-600">False Positives</div>
                <div className="text-2xl font-bold text-red-600">{metrics.feedback.falsePositives}</div>
              </div>
              <div className="bg-yellow-50 p-3 rounded">
                <div className="text-xs text-gray-600">False Negatives</div>
                <div className="text-2xl font-bold text-yellow-600">{metrics.feedback.falseNegatives}</div>
              </div>
              <div className="bg-green-50 p-3 rounded">
                <div className="text-xs text-gray-600">Agreement Rate</div>
                <div className="text-2xl font-bold text-green-600">
                  {(metrics.feedback.agreementRate * 100).toFixed(1)}%
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scheduler Status Card */}
      {jobs.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Training Schedule</CardTitle>
            <CardDescription>Automated model retraining jobs</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {jobs.map((job) => (
                <div key={job.id} className="flex items-center justify-between p-3 bg-slate-50 rounded">
                  <div className="flex-1">
                    <div className="font-medium">{job.id.replace('-', ' ').toUpperCase()}</div>
                    <div className="text-sm text-gray-600">
                      Schedule: {job.schedule} | Status: <Badge>{job.status}</Badge>
                    </div>
                  </div>
                  {job.isActive && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleTriggerJob(job.id)}
                    >
                      Trigger Now
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
