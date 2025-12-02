import { useQuery } from "@tanstack/react-query";
import { Activity, TrendingUp, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

interface DDoSMetrics {
  requestsPerSecond: number;
  uniqueIPs: number;
  volumetricScore: number;
  detectionConfidence: number;
  protocolAnomalies: number;
  topAttackerIPs: { ip: string; count: number }[];
}

export function DDoSMetricsCard() {
  const { data: metrics, isLoading } = useQuery<DDoSMetrics>({
    queryKey: ["/api/ddos/metrics"],
    refetchInterval: 5000, // Update every 5 seconds
    staleTime: 2000,
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
      <Card>
        <CardHeader>
          <CardTitle className="text-base">DDoS Detection</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-32" />
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base">DDoS Detection</CardTitle>
          <Badge variant={severity.badge as any}>{severity.label}</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Metrics Grid */}
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Requests/sec</p>
            <p className="text-2xl font-bold">{metrics?.requestsPerSecond || 0}</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Unique IPs</p>
            <p className="text-2xl font-bold">{metrics?.uniqueIPs || 0}</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Threat Score</p>
            <p className="text-2xl font-bold">{((metrics?.volumetricScore || 0) * 100).toFixed(0)}%</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Anomalies</p>
            <p className="text-2xl font-bold">{metrics?.protocolAnomalies || 0}</p>
          </div>
        </div>

        {/* Top Attackers Chart */}
        {chartData.length > 0 && (
          <div className="space-y-2 pt-2">
            <p className="text-xs font-semibold text-muted-foreground">Top 5 Attackers</p>
            <ResponsiveContainer width="100%" height={120}>
              <BarChart data={chartData} margin={{ top: 0, right: 0, left: -30, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" className="opacity-20" />
                <XAxis dataKey="ip" tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip formatter={(value) => `${value} req`} />
                <Bar dataKey="count" fill="#ef4444" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Status */}
        <div className="flex items-center gap-2 text-xs">
          <AlertTriangle className="h-3 w-3 text-yellow-600" />
          <span className="text-muted-foreground">
            {metrics?.detectionConfidence && metrics.detectionConfidence > 0.7
              ? "Active threat detected - graduated response enabled"
              : "System operating normally"}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
