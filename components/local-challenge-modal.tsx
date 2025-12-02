import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertCircle, CheckCircle2, Loader, RefreshCw } from 'lucide-react';

interface LocalChallengeModalProps {
  requestId: string;
  onSuccess: (bypassToken: string) => void;
  onError?: (error: string) => void;
}

export function LocalChallengeModal({
  requestId,
  onSuccess,
  onError,
}: LocalChallengeModalProps) {
  const [challengeId, setChallengeId] = useState('');
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [attempts, setAttempts] = useState(0);

  // Load challenge on mount
  useEffect(() => {
    loadChallenge();
  }, []);

  const loadChallenge = async () => {
    try {
      setLoading(true);
      setError('');
      setAnswer('');
      
      const response = await fetch('/api/waf/challenge');
      const data = await response.json();

      if (!data.success) {
        throw new Error('Failed to load challenge');
      }

      setChallengeId(data.challengeId);
      setQuestion(data.question);
      setAttempts(0);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load challenge';
      setError(message);
      onError?.(message);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!answer.trim()) {
      setError('Please enter an answer');
      return;
    }

    setSubmitting(true);
    setError('');

    try {
      const response = await fetch('/api/waf/verify-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId,
          answer: answer.trim(),
          requestId,
        }),
      });

      const data = await response.json();

      if (!data.success) {
        setError(data.message || 'Verification failed');
        setAttempts(prev => prev + 1);
        setAnswer('');
        return;
      }

      setSuccess(true);

      // Redirect after 1.5 seconds
      setTimeout(() => {
        onSuccess(data.bypassToken);
      }, 1500);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Verification failed';
      setError(message);
      onError?.(message);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center">
          <Loader className="w-6 h-6 animate-spin mx-auto mb-2 text-blue-500" />
          <CardTitle>Loading Verification...</CardTitle>
        </CardHeader>
      </Card>
    );
  }

  if (success) {
    return (
      <Card className="w-full max-w-md mx-auto border-green-200 bg-green-50">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <CheckCircle2 className="w-12 h-12 text-green-500" />
          </div>
          <CardTitle className="text-green-900">Verification Successful!</CardTitle>
        </CardHeader>
        <CardContent className="text-center">
          <p className="text-sm text-green-700">
            You've been verified. Reloading your request...
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader>
        <div className="flex items-center gap-2">
          <AlertCircle className="w-5 h-5 text-yellow-500 flex-shrink-0" />
          <div>
            <CardTitle>Security Verification</CardTitle>
            <CardDescription>
              Please solve the math problem below
            </CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Your request was flagged for security verification. Solve the math problem below to continue.
        </p>

        {/* Challenge Question */}
        <div className="p-4 bg-blue-50 dark:bg-blue-950 border-2 border-blue-200 dark:border-blue-800 rounded-lg text-center">
          <p className="text-sm text-muted-foreground mb-2">What is:</p>
          <p className="text-2xl font-bold text-blue-600 dark:text-blue-400 font-mono">
            {question}
          </p>
          <p className="text-xs text-muted-foreground mt-2">
            Answer must be a whole number
          </p>
        </div>

        {/* Answer Input */}
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="text-sm font-medium mb-1 block">Your Answer</label>
            <Input
              type="number"
              inputMode="numeric"
              placeholder="Enter the answer"
              value={answer}
              onChange={(e) => setAnswer(e.target.value)}
              disabled={submitting}
              className="text-center text-lg"
              autoFocus
            />
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-3 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 rounded-lg">
              <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
              {attempts >= 3 && (
                <p className="text-xs text-red-600 dark:text-red-500 mt-1">
                  {5 - attempts} attempts remaining
                </p>
              )}
            </div>
          )}

          {/* Submit Button */}
          <Button
            type="submit"
            disabled={submitting || !answer.trim()}
            className="w-full"
          >
            {submitting ? (
              <>
                <Loader className="w-4 h-4 mr-2 animate-spin" />
                Verifying...
              </>
            ) : (
              'Submit Answer'
            )}
          </Button>

          {/* Reload Challenge Button */}
          <Button
            type="button"
            variant="outline"
            onClick={loadChallenge}
            disabled={submitting || loading}
            className="w-full"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            New Problem
          </Button>
        </form>

        {/* Info */}
        <div className="text-xs text-muted-foreground text-center border-t pt-3">
          <p>This is a local security verification.</p>
          <p>No data is sent to external services.</p>
        </div>
      </CardContent>
    </Card>
  );
}
