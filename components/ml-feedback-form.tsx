import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Textarea } from './ui/textarea';
import { Label } from './ui/label';
import { Badge } from './ui/badge';
import { AlertCircle, Send, CheckCircle } from 'lucide-react';

export interface FeedbackFormProps {
  requestId?: string;
  defaultPredicted?: 0 | 1;
  onSubmitSuccess?: () => void;
}

export function MLFeedbackForm({
  requestId: initialRequestId,
  defaultPredicted,
  onSubmitSuccess,
}: FeedbackFormProps) {
  const [requestId, setRequestId] = useState(initialRequestId || '');
  const [actualLabel, setActualLabel] = useState<0 | 1 | null>(null);
  const [predictedLabel, setPredictedLabel] = useState(defaultPredicted || null);
  const [notes, setNotes] = useState('');
  const [confidence, setConfidence] = useState(0.95);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!requestId || actualLabel === null || predictedLabel === null) {
      setError('Please fill in all required fields');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(false);

    try {
      const res = await fetch('/api/ml/feedback', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestId,
          actualLabel,
          predictedLabel,
          notes: notes || undefined,
          confidence,
          tenantId: 'default',
        }),
      });

      if (!res.ok) throw new Error('Failed to submit feedback');

      const result = await res.json();
      setSuccess(true);

      // Reset form
      setRequestId('');
      setActualLabel(null);
      setPredictedLabel(null);
      setNotes('');
      setConfidence(0.95);

      // Call callback
      onSubmitSuccess?.();

      // Clear success message after 3s
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit feedback');
    } finally {
      setLoading(false);
    }
  };

  const isFalsePositive = actualLabel === 0 && predictedLabel === 1;
  const isFalseNegative = actualLabel === 1 && predictedLabel === 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Security Team Feedback</CardTitle>
        <CardDescription>
          Label requests to help the model learn. Mark false positives/negatives to improve accuracy.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="flex items-center gap-2 p-3 bg-red-50 text-red-700 rounded">
              <AlertCircle className="h-4 w-4" />
              {error}
            </div>
          )}

          {success && (
            <div className="flex items-center gap-2 p-3 bg-green-50 text-green-700 rounded">
              <CheckCircle className="h-4 w-4" />
              ✅ Feedback submitted successfully!
            </div>
          )}

          <div>
            <Label htmlFor="requestId">Request ID *</Label>
            <Input
              id="requestId"
              placeholder="Enter request ID to label"
              value={requestId}
              onChange={(e) => setRequestId(e.target.value)}
              disabled={loading}
            />
            <p className="text-xs text-gray-500 mt-1">The ID of the request you want to label</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Model Predicted *</Label>
              <div className="flex gap-2 mt-2">
                <Button
                  type="button"
                  variant={predictedLabel === 0 ? 'default' : 'outline'}
                  onClick={() => setPredictedLabel(0)}
                  disabled={loading}
                  className="flex-1"
                >
                  Legitimate
                </Button>
                <Button
                  type="button"
                  variant={predictedLabel === 1 ? 'default' : 'outline'}
                  onClick={() => setPredictedLabel(1)}
                  disabled={loading}
                  className="flex-1"
                >
                  Malicious
                </Button>
              </div>
            </div>

            <div>
              <Label>Actually Is *</Label>
              <div className="flex gap-2 mt-2">
                <Button
                  type="button"
                  variant={actualLabel === 0 ? 'default' : 'outline'}
                  onClick={() => setActualLabel(0)}
                  disabled={loading}
                  className="flex-1"
                >
                  Legitimate
                </Button>
                <Button
                  type="button"
                  variant={actualLabel === 1 ? 'default' : 'outline'}
                  onClick={() => setActualLabel(1)}
                  disabled={loading}
                  className="flex-1"
                >
                  Malicious
                </Button>
              </div>
            </div>
          </div>

          {isFalsePositive && (
            <div className="p-3 bg-red-50 border border-red-200 rounded flex items-center gap-2 text-red-700">
              <AlertCircle className="h-4 w-4" />
              False Positive: Model incorrectly flagged a legitimate request
            </div>
          )}

          {isFalseNegative && (
            <div className="p-3 bg-yellow-50 border border-yellow-200 rounded flex items-center gap-2 text-yellow-700">
              <AlertCircle className="h-4 w-4" />
              False Negative: Model missed a malicious request
            </div>
          )}

          <div>
            <Label htmlFor="notes">Notes (Optional)</Label>
            <Textarea
              id="notes"
              placeholder="Add any additional notes about this feedback..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              disabled={loading}
              rows={3}
            />
          </div>

          <div>
            <Label htmlFor="confidence">Confidence Level: {(confidence * 100).toFixed(0)}%</Label>
            <input
              id="confidence"
              type="range"
              min="0.5"
              max="1"
              step="0.05"
              value={confidence}
              onChange={(e) => setConfidence(parseFloat(e.target.value))}
              disabled={loading}
              className="w-full mt-2"
            />
            <p className="text-xs text-gray-500 mt-1">How confident are you in this label?</p>
          </div>

          <Button
            type="submit"
            disabled={loading || !requestId || actualLabel === null || predictedLabel === null}
            className="w-full"
            size="lg"
          >
            {loading ? (
              <>
                <span className="animate-spin mr-2">⚙️</span>
                Submitting...
              </>
            ) : (
              <>
                <Send className="mr-2 h-4 w-4" />
                Submit Feedback
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
