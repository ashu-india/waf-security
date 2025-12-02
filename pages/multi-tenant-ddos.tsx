/**
 * Multi-Tenant DDoS Dashboard
 * Shows DDoS metrics and status across all tenants
 */

import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';

interface TenantDDoSData {
  tenantId: string;
  tenantName: string;
  requestsPerSecond: number;
  uniqueIPs: number;
  volumetricScore: number;
  detectionConfidence: number;
  topAttackerIPs: { ip: string; count: number }[];
}

export default function MultiTenantDDoSDashboard() {
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d'>('1h');
  const [chartData, setChartData] = useState<any[]>([]);

  // Fetch multi-tenant metrics
  const { data: allMetrics, isLoading } = useQuery({
    queryKey: ['/api/ddos/metrics-all'],
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  useEffect(() => {
    if (allMetrics?.metrics) {
      // Transform metrics for chart
      const transformed = Object.entries(allMetrics.metrics).map(([tenantId, metrics]: any) => ({
        name: tenantId.substring(0, 8),
        rps: metrics.requestsPerSecond,
        ips: metrics.uniqueIPs,
        volumetric: (metrics.volumetricScore * 100).toFixed(1),
      }));
      setChartData(transformed);
    }
  }, [allMetrics]);

  if (isLoading) {
    return <div className="p-6">Loading multi-tenant DDoS data...</div>;
  }

  const metrics = allMetrics?.metrics || {};
  const tenants = Object.entries(metrics) as [string, any][];

  // Calculate aggregate stats
  const totalRPS = tenants.reduce((sum, [_, m]) => sum + (m.requestsPerSecond || 0), 0);
  const totalIPs = tenants.reduce((sum, [_, m]) => sum + (m.uniqueIPs || 0), 0);
  const avgConfidence = tenants.length > 0 
    ? tenants.reduce((sum, [_, m]) => sum + (m.detectionConfidence || 0), 0) / tenants.length 
    : 0;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Multi-Tenant DDoS Monitoring</h1>
        <p className="text-muted-foreground mt-1">Real-time DDoS metrics across all protected tenants</p>
      </div>

      {/* Aggregate Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total RPS</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalRPS.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">Across all tenants</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Unique IPs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalIPs.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">Distinct sources</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Avg Confidence</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{(avgConfidence * 100).toFixed(1)}%</div>
            <p className="text-xs text-muted-foreground">Detection accuracy</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Active Tenants</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{tenants.length}</div>
            <p className="text-xs text-muted-foreground">Under monitoring</p>
          </CardContent>
        </Card>
      </div>

      {/* RPS Chart */}
      <Card>
        <CardHeader>
          <CardTitle>Requests Per Second by Tenant</CardTitle>
          <CardDescription>Real-time traffic volume</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="rps" fill="#ef4444" name="RPS" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Tenants Table */}
      <Card>
        <CardHeader>
          <CardTitle>Tenant Status</CardTitle>
          <CardDescription>DDoS metrics per tenant</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2 px-3">Tenant ID</th>
                  <th className="text-right py-2 px-3">RPS</th>
                  <th className="text-right py-2 px-3">Unique IPs</th>
                  <th className="text-right py-2 px-3">Volumetric Score</th>
                  <th className="text-right py-2 px-3">Confidence</th>
                  <th className="text-left py-2 px-3">Top Attacker</th>
                </tr>
              </thead>
              <tbody>
                {tenants.map(([tenantId, metrics]) => (
                  <tr key={tenantId} className="border-b hover:bg-muted/50">
                    <td className="py-2 px-3 font-mono text-xs">{tenantId.substring(0, 12)}...</td>
                    <td className="text-right py-2 px-3">{metrics.requestsPerSecond}</td>
                    <td className="text-right py-2 px-3">{metrics.uniqueIPs}</td>
                    <td className="text-right py-2 px-3">
                      {(metrics.volumetricScore * 100).toFixed(1)}%
                    </td>
                    <td className="text-right py-2 px-3">
                      <Badge 
                        variant={metrics.detectionConfidence > 0.7 ? 'destructive' : 'secondary'}
                      >
                        {(metrics.detectionConfidence * 100).toFixed(0)}%
                      </Badge>
                    </td>
                    <td className="py-2 px-3 font-mono text-xs">
                      {metrics.topAttackerIPs?.[0]?.ip || 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
