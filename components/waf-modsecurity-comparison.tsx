/**
 * WAF vs ModSecurity Comparison Component
 * Test traffic through both engines and compare results
 */

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { AlertCircle, CheckCircle, Shield, Zap } from 'lucide-react';

interface ComparisonResult {
  engine: 'waf' | 'modsecurity';
  blocked: boolean;
  severity: string;
  matches: any[];
  score: number;
  action: string;
  processingTimeMs: number;
  details: string;
}

export function WAFModSecurityComparison({ tenantId }: { tenantId: string }) {
  const [testMode, setTestMode] = useState<'waf' | 'modsecurity' | 'both'>('both');
  const [testPayload, setTestPayload] = useState('');
  const [wafResult, setWafResult] = useState<ComparisonResult | null>(null);
  const [modSecResult, setModSecResult] = useState<ComparisonResult | null>(null);
  const [testData, setTestData] = useState({
    method: 'POST',
    uri: '/api/test',
    headers: { 'Content-Type': 'application/json' },
    body: '',
  });

  const wafMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await fetch(`/api/tenants/${tenantId}/waf/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error('WAF test failed');
      return res.json();
    },
    onSuccess: (data) => setWafResult(data),
  });

  const modSecMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await fetch(`/api/tenants/${tenantId}/modsecurity/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error('ModSecurity test failed');
      return res.json();
    },
    onSuccess: (data) => setModSecResult(data),
  });

  const handleTestPayload = () => {
    const newTestData = {
      ...testData,
      body: testPayload,
    };
    setTestData(newTestData);
    
    if (testMode === 'waf' || testMode === 'both') {
      wafMutation.mutate(newTestData);
    }
    if (testMode === 'modsecurity' || testMode === 'both') {
      modSecMutation.mutate(newTestData);
    }
  };

  const presets = [
    {
      name: 'SQL Injection',
      payload: "' OR 1=1; --",
    },
    {
      name: 'XSS Attack',
      payload: '<script>alert("xss")</script>',
    },
    {
      name: 'Path Traversal',
      payload: '../../etc/passwd',
    },
    {
      name: 'Command Injection',
      payload: '; ls -la',
    },
    {
      name: 'XXE Attack',
      payload: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    },
    {
      name: 'Clean Request',
      payload: 'normal data',
    },
  ];

  const ResultCard = ({ result, title }: { result: ComparisonResult | null | undefined; title: string }) => {
    if (!result) return null;

    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold">{title}</h3>
          <Badge
            variant={result.blocked ? 'destructive' : 'default'}
            className="flex items-center gap-1"
          >
            {result.blocked ? (
              <>
                <AlertCircle className="w-3 h-3" />
                Blocked
              </>
            ) : (
              <>
                <CheckCircle className="w-3 h-3" />
                Allowed
              </>
            )}
          </Badge>
        </div>

        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <p className="text-muted-foreground">Action</p>
            <p className="font-mono font-semibold">{result.action}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Severity</p>
            <Badge variant="secondary" className="w-fit">
              {result.severity}
            </Badge>
          </div>
          <div>
            <p className="text-muted-foreground">Score</p>
            <p className="font-mono font-semibold">{result.score.toFixed(2)}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Processing</p>
            <p className="font-mono font-semibold">{result.processingTimeMs}ms</p>
          </div>
        </div>

        {result.matches && result.matches.length > 0 && (
          <div>
            <p className="text-sm font-semibold mb-2">
              Rules Triggered ({result.matches.length})
            </p>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {result.matches.map((match, i) => (
                <div key={i} className="text-xs bg-muted p-2 rounded">
                  <p className="font-mono">
                    [{match.id}] {match.name}
                  </p>
                  <p className="text-muted-foreground">{match.category}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {result.details && (
          <div className="text-sm text-muted-foreground italic border-l-2 border-primary pl-2">
            {result.details}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Control Section */}
      <Card>
        <CardHeader>
          <CardTitle>Test Traffic Analysis</CardTitle>
          <CardDescription>
            Compare how WAF Engine and ModSecurity handle the same traffic
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Engine Selection */}
          <div className="space-y-3">
            <label className="text-sm font-semibold">Select Engines to Test</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="both"
                  checked={testMode === 'both'}
                  onChange={(e) => setTestMode(e.target.value as any)}
                  className="w-4 h-4"
                />
                <span className="text-sm">Compare Both</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="waf"
                  checked={testMode === 'waf'}
                  onChange={(e) => setTestMode(e.target.value as any)}
                  className="w-4 h-4"
                />
                <span className="text-sm">WAF Engine Only</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  value="modsecurity"
                  checked={testMode === 'modsecurity'}
                  onChange={(e) => setTestMode(e.target.value as any)}
                  className="w-4 h-4"
                />
                <span className="text-sm">ModSecurity Only</span>
              </label>
            </div>
          </div>

          {/* Payload Input */}
          <div className="space-y-2">
            <label className="text-sm font-semibold">Test Payload</label>
            <div className="flex gap-2">
              <Input
                placeholder="Enter payload to test..."
                value={testPayload}
                onChange={(e) => setTestPayload(e.target.value)}
                className="flex-1"
              />
              <Button onClick={handleTestPayload} disabled={!testPayload}>
                Test
              </Button>
            </div>
          </div>

          {/* Preset Payloads */}
          <div className="space-y-2">
            <label className="text-sm font-semibold">Quick Test Presets</label>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {presets.map((preset) => (
                <Button
                  key={preset.name}
                  variant="outline"
                  size="sm"
                  className="text-xs"
                  onClick={() => {
                    setTestPayload(preset.payload);
                    setTimeout(() => {
                      setTestData({
                        ...testData,
                        body: preset.payload,
                      });
                    }, 100);
                  }}
                >
                  {preset.name}
                </Button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Results Section */}
      {(wafResult || modSecResult) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {(testMode === 'waf' || testMode === 'both') && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Shield className="w-4 h-4" />
                  WAF Engine
                </CardTitle>
              </CardHeader>
              <CardContent>
                {wafMutation.isPending ? (
                  <div className="text-center text-muted-foreground">Testing...</div>
                ) : wafResult ? (
                  <ResultCard result={wafResult} title="Results" />
                ) : null}
              </CardContent>
            </Card>
          )}

          {(testMode === 'modsecurity' || testMode === 'both') && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Zap className="w-4 h-4" />
                  ModSecurity
                </CardTitle>
              </CardHeader>
              <CardContent>
                {modSecMutation.isPending ? (
                  <div className="text-center text-muted-foreground">Testing...</div>
                ) : modSecResult ? (
                  <ResultCard result={modSecResult} title="Results" />
                ) : null}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Comparison Analysis */}
      {wafResult && modSecResult && testMode === 'both' && (
        <Card className="border-2 border-chart-1">
          <CardHeader>
            <CardTitle className="text-base">Comparison Analysis</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Detection Agreement</p>
                <p className="text-2xl font-bold">
                  {wafResult.blocked === modSecResult.blocked ? (
                    <span className="text-green-600">✓ Match</span>
                  ) : (
                    <span className="text-amber-600">✗ Differ</span>
                  )}
                </p>
              </div>
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Speed Difference</p>
                <p className="text-2xl font-bold">
                  {Math.abs(wafResult.processingTimeMs - modSecResult.processingTimeMs)}ms
                </p>
                <p className="text-xs text-muted-foreground">
                  {wafResult.processingTimeMs < modSecResult.processingTimeMs
                    ? 'WAF faster'
                    : 'ModSec faster'}
                </p>
              </div>
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Rules Triggered</p>
                <p className="text-2xl font-bold">
                  WAF: {wafResult.matches?.length || 0} | ModSec: {modSecResult.matches?.length || 0}
                </p>
              </div>
            </div>

            {wafResult.blocked !== modSecResult.blocked && (
              <div className="bg-amber-50 border border-amber-200 rounded p-3 text-sm">
                <p className="font-semibold text-amber-900">Detection Difference</p>
                <p className="text-amber-800 mt-1">
                  {wafResult.blocked
                    ? 'WAF Engine blocked this request while ModSecurity allowed it'
                    : 'ModSecurity blocked this request while WAF Engine allowed it'}
                </p>
              </div>
            )}

            <div className="space-y-2">
              <p className="text-sm font-semibold">Recommendation</p>
              <p className="text-sm text-muted-foreground">
                {wafResult.blocked && modSecResult.blocked
                  ? 'Both engines agree this is a threat. Recommended: BLOCK'
                  : wafResult.blocked || modSecResult.blocked
                    ? 'One engine detected a threat. Recommended: CHALLENGE (CAPTCHA)'
                    : 'Both engines allow this traffic. Recommended: ALLOW'}
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
