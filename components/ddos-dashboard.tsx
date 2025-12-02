import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, Zap } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

interface DDoSMetrics {
  requestsPerSecond: number;
  uniqueIPs: number;
  volumetricScore: number;
  detectionConfidence: number;
  protocolAnomalies: number;
  topAttackerIPs: { ip: string; count: number }[];
}

interface TenantMetricsMap {
  [tenantId: string]: DDoSMetrics;
}

export function DDoSDashboard() {
  const [searchTenant, setSearchTenant] = useState("");

  const { data: allMetrics, isLoading } = useQuery<TenantMetricsMap>({
    queryKey: ["/api/ddos/metrics-all"],
    refetchInterval: 10000,
    staleTime: 3000,
  });

  const getSeverityColor = (score: number) => {
    if (score >= 0.9) return { text: "text-red-600", badge: "destructive" };
    if (score >= 0.8) return { text: "text-orange-600", badge: "secondary" };
    if (score >= 0.7) return { text: "text-yellow-600", badge: "outline" };
    return { text: "text-green-600", badge: "outline" };
  };

  const getSeverityLabel = (score: number) => {
    if (score >= 0.9) return "CRITICAL";
    if (score >= 0.8) return "HIGH";
    if (score >= 0.7) return "MEDIUM";
    return "LOW";
  };

  // Filter tenants by search
  const filteredTenants = Object.entries(allMetrics || {})
    .filter(([tenantId]) => tenantId.toLowerCase().includes(searchTenant.toLowerCase()))
    .sort((a, b) => (b[1]?.volumetricScore || 0) - (a[1]?.volumetricScore || 0));

  // Calculate aggregate stats
  const aggregateStats = {
    totalTenantsUnderAttack: Object.values(allMetrics || {}).filter((m) => (m?.volumetricScore || 0) > 0.7).length,
    maxThreatScore: Math.max(...Object.values(allMetrics || {}).map((m) => m?.volumetricScore || 0)),
    totalUniqueIPs: Object.values(allMetrics || {}).reduce((sum, m) => sum + (m?.uniqueIPs || 0), 0),
    totalRPS: Object.values(allMetrics || {}).reduce((sum, m) => sum + (m?.requestsPerSecond || 0), 0),
  };

  const chartData = filteredTenants.slice(0, 10).map(([tenantId, metrics]) => ({
    tenant: tenantId.substring(0, 12),
    fullTenantId: tenantId,
    score: ((metrics?.volumetricScore || 0) * 100).toFixed(1),
  }));

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-32" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (!allMetrics || Object.keys(allMetrics).length === 0) {
    return (
      <Card>
        <CardContent className="pt-6 text-center">
          <p className="text-muted-foreground">No tenant DDoS data available yet. Metrics will appear as traffic is processed.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Tabs defaultValue="overview" className="space-y-6">
      <TabsList className="grid w-full grid-cols-2">
        <TabsTrigger value="overview" className="flex items-center gap-2">
          <Zap className="h-4 w-4" />
          <span>Overview</span>
        </TabsTrigger>
        <TabsTrigger value="tenants" className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          <span>All Tenants</span>
        </TabsTrigger>
      </TabsList>

      {/* Overview Tab */}
      <TabsContent value="overview" className="space-y-4">
        {/* Aggregate Stats */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Tenants Under Attack</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{aggregateStats.totalTenantsUnderAttack}</p>
              <p className="text-xs text-muted-foreground">With threat score {'>'} 70%</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Max Threat Score</CardTitle>
            </CardHeader>
            <CardContent>
              <p className={`text-2xl font-bold ${getSeverityColor(aggregateStats.maxThreatScore).text}`}>
                {(aggregateStats.maxThreatScore * 100).toFixed(1)}%
              </p>
              <p className="text-xs text-muted-foreground">
                <Badge variant={getSeverityColor(aggregateStats.maxThreatScore).badge as any} className="text-xs">
                  {getSeverityLabel(aggregateStats.maxThreatScore)}
                </Badge>
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Unique Attack IPs</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{aggregateStats.totalUniqueIPs}</p>
              <p className="text-xs text-muted-foreground">Across all tenants</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Requests/sec</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-bold">{aggregateStats.totalRPS}</p>
              <p className="text-xs text-muted-foreground">Aggregate traffic</p>
            </CardContent>
          </Card>
        </div>

        {/* Threat Distribution Chart */}
        {chartData.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Threat Scores by Tenant (Top 10)</CardTitle>
              <CardDescription>DDoS volumetric scores across all tenants</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" className="opacity-20" />
                  <XAxis dataKey="tenant" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 10 }} domain={[0, 100]} />
                  <Tooltip 
                    formatter={(value) => `${value}%`}
                    labelFormatter={() => "Threat Score"}
                  />
                  <Bar 
                    dataKey="score" 
                    fill="#ef4444" 
                    radius={[4, 4, 0, 0]} 
                    onClick={(data) => {
                      console.log("Tenant:", data.fullTenantId);
                    }}
                  />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        )}
      </TabsContent>

      {/* All Tenants Tab */}
      <TabsContent value="tenants" className="space-y-4">
        <div className="flex gap-2">
          <Input
            placeholder="Search tenants..."
            value={searchTenant}
            onChange={(e) => setSearchTenant(e.target.value)}
            className="max-w-sm"
          />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>DDoS Metrics by Tenant</CardTitle>
            <CardDescription>Real-time DDoS detection metrics for all tenants ({filteredTenants.length} tenants)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Tenant ID</TableHead>
                    <TableHead className="text-right">Requests/sec</TableHead>
                    <TableHead className="text-right">Unique IPs</TableHead>
                    <TableHead className="text-right">Threat Score</TableHead>
                    <TableHead className="text-right">Severity</TableHead>
                    <TableHead className="text-right">Anomalies</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredTenants.map(([tenantId, metrics]) => {
                    const severity = getSeverityColor(metrics?.volumetricScore || 0);
                    return (
                      <TableRow key={tenantId}>
                        <TableCell className="font-mono text-sm">{tenantId.substring(0, 16)}...</TableCell>
                        <TableCell className="text-right">{metrics?.requestsPerSecond || 0}</TableCell>
                        <TableCell className="text-right">{metrics?.uniqueIPs || 0}</TableCell>
                        <TableCell className={`text-right font-semibold ${severity.text}`}>
                          {((metrics?.volumetricScore || 0) * 100).toFixed(1)}%
                        </TableCell>
                        <TableCell className="text-right">
                          <Badge variant={severity.badge as any}>
                            {getSeverityLabel(metrics?.volumetricScore || 0)}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">{metrics?.protocolAnomalies || 0}</TableCell>
                      </TableRow>
                    );
                  })}
                  {filteredTenants.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                        No tenants match your search
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  );
}
