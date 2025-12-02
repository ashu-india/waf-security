import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Download, Copy, Info } from 'lucide-react';

export interface ModelInfo {
  id: string;
  versions: number[];
  latest: number | null;
  latestModel: any;
}

export function MLModelVersions() {
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedVersion, setSelectedVersion] = useState<{ modelId: string; version: number } | null>(null);

  useEffect(() => {
    fetchModels();
    const interval = setInterval(fetchModels, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, []);

  const fetchModels = async () => {
    try {
      const res = await fetch('/api/ml/models', { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch models');
      const data = await res.json();
      setModels(data.models || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load models');
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="p-8 text-center">Loading model versions...</div>;

  if (models.length === 0) {
    return (
      <Card>
        <CardContent className="pt-6">
          <p className="text-gray-600 text-center">No trained models yet. Start training to create the first model.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {error && (
        <Card className="border-red-500 bg-red-50">
          <CardContent className="pt-6 text-red-700">
            <Info className="h-4 w-4 inline mr-2" />
            {error}
          </CardContent>
        </Card>
      )}

      {models.map((model) => (
        <Card key={model.id}>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>{model.id}</span>
              {model.latest && <Badge variant="default">Latest: v{model.latest}</Badge>}
            </CardTitle>
            <CardDescription>
              {model.versions.length} version{model.versions.length !== 1 ? 's' : ''} trained
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Latest Model Metrics */}
            {model.latestModel && (
              <div className="bg-blue-50 p-4 rounded-lg space-y-2">
                <h4 className="font-semibold text-sm text-blue-900">Latest Model Performance (v{model.latestModel.version})</h4>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-sm">
                  <div>
                    <div className="text-gray-600">Accuracy</div>
                    <div className="font-bold text-blue-600">
                      {model.latestModel.metrics?.accuracy ? (model.latestModel.metrics.accuracy * 100).toFixed(1) : 'N/A'}%
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-600">Precision</div>
                    <div className="font-bold text-green-600">
                      {model.latestModel.metrics?.precision ? (model.latestModel.metrics.precision * 100).toFixed(1) : 'N/A'}%
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-600">Recall</div>
                    <div className="font-bold text-purple-600">
                      {model.latestModel.metrics?.recall ? (model.latestModel.metrics.recall * 100).toFixed(1) : 'N/A'}%
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-600">F1 Score</div>
                    <div className="font-bold text-orange-600">
                      {model.latestModel.metrics?.f1 ? (model.latestModel.metrics.f1 * 100).toFixed(1) : 'N/A'}%
                    </div>
                  </div>
                  <div>
                    <div className="text-gray-600">ROC-AUC</div>
                    <div className="font-bold text-red-600">
                      {model.latestModel.metrics?.rocAuc ? (model.latestModel.metrics.rocAuc * 100).toFixed(1) : 'N/A'}%
                    </div>
                  </div>
                </div>
                {model.latestModel.trainingData && (
                  <p className="text-xs text-gray-600 mt-2">
                    Trained on {model.latestModel.trainingData.samplesCount} samples with {model.latestModel.trainingData.featuresCount} features
                    ({(model.latestModel.trainingData.trainingTime / 1000).toFixed(1)}s)
                  </p>
                )}
              </div>
            )}

            {/* Version History */}
            <div>
              <h4 className="font-semibold text-sm mb-2">Version History</h4>
              <div className="flex flex-wrap gap-2">
                {model.versions.map((version) => (
                  <Button
                    key={version}
                    variant={selectedVersion?.version === version ? 'default' : 'outline'}
                    size="sm"
                    onClick={() =>
                      setSelectedVersion({ modelId: model.id, version })
                    }
                  >
                    v{version}
                  </Button>
                ))}
              </div>
            </div>

            {/* Feature Importance (if available) */}
            {model.latestModel?.featureImportance && (
              <div>
                <h4 className="font-semibold text-sm mb-2">Top Features</h4>
                <div className="space-y-1">
                  {Object.entries(model.latestModel.featureImportance)
                    .sort((a, b) => (b[1] as number) - (a[1] as number))
                    .slice(0, 5)
                    .map(([feature, importance]) => (
                      <div key={feature} className="flex items-center justify-between text-sm">
                        <span className="text-gray-600">{feature}</span>
                        <div className="flex items-center gap-2">
                          <div className="w-24 bg-gray-200 rounded h-2">
                            <div
                              className="bg-blue-500 h-2 rounded"
                              style={{
                                width: `${(importance as number) * 100}%`,
                              }}
                            />
                          </div>
                          <span className="text-xs text-gray-500 w-10">
                            {((importance as number) * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            )}

            <div className="flex gap-2 pt-2">
              <Button variant="outline" size="sm" className="flex-1">
                <Download className="h-4 w-4 mr-2" />
                Export
              </Button>
              <Button variant="outline" size="sm" className="flex-1">
                <Copy className="h-4 w-4 mr-2" />
                Compare
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
