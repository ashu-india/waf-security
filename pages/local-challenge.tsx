import { LocalChallengeModal } from '@/components/local-challenge-modal';

export function LocalChallengePage() {
  // Get query params from URL
  const url = new URL(window.location.href);
  const requestId = url.searchParams.get('requestId') || '';
  const redirectUrl = url.searchParams.get('redirectUrl') || '/';

  const handleSuccess = (bypassToken: string) => {
    // Store token in sessionStorage for use on retry
    sessionStorage.setItem('challengeBypass', bypassToken);
    
    // Redirect back to original request or home
    window.location.href = redirectUrl;
  };

  const handleError = (error: string) => {
    console.error('Challenge error:', error);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-b from-background to-secondary/20 p-4">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold mb-2">Verify Your Request</h1>
          <p className="text-muted-foreground">
            To continue, please verify that you're not a bot
          </p>
        </div>

        <LocalChallengeModal
          requestId={requestId}
          onSuccess={handleSuccess}
          onError={handleError}
        />

        <div className="mt-8 text-center text-xs text-muted-foreground space-y-1">
          <p>🔒 Self-hosted verification system</p>
          <p>✓ No external service calls</p>
          <p>✓ Your data stays local</p>
          <p className="mt-3">
            Need help?{' '}
            <a href="/support" className="text-primary hover:underline">
              Contact support
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
