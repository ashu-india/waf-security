import { useQuery } from "@tanstack/react-query";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle } from "lucide-react";

interface DDoSMetrics {
  requestsPerSecond: number;
  uniqueIPs: number;
  volumetricScore: number;
  detectionConfidence: number;
  protocolAnomalies: number;
  topAttackerIPs: { ip: string; count: number }[];
}

interface TenantDDoSAnalyticsProps {
  tenantId: string;
}

export function TenantDDoSAnalytics({ tenantId }: TenantDDoSAnalyticsProps) {
  const { data: metrics, isLoading } = useQuery<DDoSMetrics>({
    queryKey: [`/api/tenants/${tenantId}/ddos/metrics`],
    refetchInterval: 10000, // Update every 10 seconds for tenant view
    staleTime: 3000,
  });

  const getSeverity = (score: number) => {
    if (score >= 0.9) return { label: "CRITICAL", color: "text-red-600", badge: "destructive" };
    if (score >= 0.8) return { label: "HIGH", color: "text-orange-600", badge: "secondary" };
    if (score >= 0.7) return { label: "MEDIUM", color: "text-yellow-600", badge: "outline" };
    return { label: "LOW", color: "text-green-600", badge: "outline" };
  };

  const severity = getSeverity(metrics?.detectionConfidence || 0);

  const chartData = (metrics?.topAttackerIPs || []).slice(0, 5).map((item) => ({
    ip: item.ip.split(".").slice(2).join("."),
    count: item.count,
  }));

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-32" />
        <Skeleton className="h-48" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Metrics Grid */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Requests/sec</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{metrics?.requestsPerSecond || 0}</p>
            <p className="text-xs text-muted-foreground">This tenant</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Unique IPs</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{metrics?.uniqueIPs || 0}</p>
            <p className="text-xs text-muted-foreground">Attacking sources</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Threat Score</CardTitle>
          </CardHeader>
          <CardContent>
            <p className={`text-2xl font-bold ${severity.color}`}>
              {((metrics?.volumetricScore || 0) * 100).toFixed(0)}%
            </p>
            <p className="text-xs text-muted-foreground">
              <Badge variant={severity.badge as any} className="text-xs">
                {severity.label}
              </Badge>
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Anomalies</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{metrics?.protocolAnomalies || 0}</p>
            <p className="text-xs text-muted-foreground">Protocol violations</p>
          </CardContent>
        </Card>
      </div>

      {/* Top Attackers Chart */}
      {chartData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top Attacking IPs</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" className="opacity-20" />
                <XAxis dataKey="ip" tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip formatter={(value) => `${value} req`} />
                <Bar dataKey="count" fill="#ef4444" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      {/* Status */}
      {metrics?.detectionConfidence && metrics.detectionConfidence > 0.7 && (
        <Card className="border-yellow-200 bg-yellow-50">
          <CardContent className="pt-6 flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-600 mt-0.5" />
            <div>
              <p className="font-medium text-sm text-yellow-900">DDoS Threat Detected</p>
              <p className="text-sm text-yellow-800 mt-1">
                This tenant is experiencing elevated attack patterns. Consider reviewing your security policies.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {(!metrics?.topAttackerIPs || metrics.topAttackerIPs.length === 0) && metrics?.detectionConfidence === 0 && (
        <Card>
          <CardContent className="pt-6 text-center">
            <p className="text-muted-foreground text-sm">No DDoS activity detected for this tenant</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
