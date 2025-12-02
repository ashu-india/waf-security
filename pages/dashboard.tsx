import { useQuery } from "@tanstack/react-query";
import { Activity, Shield, AlertTriangle, Globe, TrendingUp, Clock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { MetricCard } from "@/components/ui/metric-card";
import { StatusBadge, SeverityBadge } from "@/components/ui/status-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Link } from "wouter";
import type { Tenant, Alert, DashboardStats } from "@shared/schema";
import { BehavioralAnalytics, type BehavioralStats } from "@/components/behavioral-analytics";
import { GeoAnalytics, type GeoStats } from "@/components/geo-analytics";
import { DDoSMetricsCard } from "@/components/ddos-metrics-card";
// Dashboard data helpers
const calculateMetrics = (stats: DashboardStats | undefined) => {
  return {
    requestDistribution: [
      { label: "Allowed", value: stats?.allowedRequests || 0, percentage: stats && stats.totalRequests > 0 ? ((stats.allowedRequests / stats.totalRequests) * 100).toFixed(1) : 0 },
      { label: "Monitored", value: stats?.flaggedRequests || 0, percentage: stats && stats.totalRequests > 0 ? ((stats.flaggedRequests / stats.totalRequests) * 100).toFixed(1) : 0 },
      { label: "Blocked", value: stats?.blockedRequests || 0, percentage: stats && stats.totalRequests > 0 ? ((stats.blockedRequests / stats.totalRequests) * 100).toFixed(1) : 0 },
    ]
  };
};

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>({
    queryKey: ["/api/dashboard/stats"],
    staleTime: 15000, // 15 seconds
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  const { data: tenants, isLoading: tenantsLoading } = useQuery<Tenant[]>({
    queryKey: ["/api/tenants"],
    staleTime: 5 * 60 * 1000, // 5 minutes for tenants
    refetchInterval: 2 * 60 * 1000, // Refetch every 2 minutes
  });

  const { data: alerts, isLoading: alertsLoading } = useQuery<Alert[]>({
    queryKey: ["/api/alerts/recent"],
    staleTime: 10000, // 10 seconds
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  const { data: analytics } = useQuery<any>({
    queryKey: ["/api/analytics/dashboard"],
    staleTime: 30000, // 30 seconds
    refetchInterval: 60000, // Refetch every 60 seconds
  });

  const metrics = calculateMetrics(stats);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Real-time overview of your WAF protection status and security metrics
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className="gap-1.5">
            <Clock className="h-3 w-3" />
            <span>Last updated: just now</span>
          </Badge>
          <Button variant="default" size="sm" asChild>
            <Link href="/traffic">View Live Traffic</Link>
          </Button>
        </div>
      </div>

      {/* Metric Cards - KPI Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Total Requests"
          value={stats?.totalRequests || 0}
          description="Last 24 hours"
          icon={Activity}
          trend={{ value: 12.5, isPositive: true }}
          isLoading={statsLoading}
        />
        <MetricCard
          title="Blocked Requests"
          value={stats?.blockedRequests || 0}
          description={`${stats?.blockPercentage?.toFixed(1) || 0}% of total`}
          icon={Shield}
          variant="danger"
          trend={{ value: 8.2, isPositive: false }}
          isLoading={statsLoading}
        />
        <MetricCard
          title="Flagged Requests"
          value={stats?.flaggedRequests || 0}
          description="Requires review"
          icon={AlertTriangle}
          variant="warning"
          trend={{ value: 3.1, isPositive: false }}
          isLoading={statsLoading}
        />
        <MetricCard
          title="Active Tenants"
          value={stats?.activeTenants || 0}
          description={`${stats?.activeRules || 0} active rules`}
          icon={Globe}
          variant="success"
          isLoading={statsLoading}
        />
      </div>

      {/* DDoS Metrics Card */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">Security Threats</h2>
          <Button variant="outline" size="sm" asChild>
            <Link href="/ddos-protection">View Details</Link>
          </Button>
        </div>
        <DDoSMetricsCard />
      </div>

      {/* Charts Section */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Traffic Overview */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base font-semibold">Traffic Overview (24 Hours)</CardTitle>
              <div className="flex items-center gap-4 text-sm">
                <div className="flex items-center gap-2">
                  <div className="h-3 w-3 rounded-full bg-green-500" />
                  <span className="text-muted-foreground">Allowed: {stats?.allowedRequests || 0}</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="h-3 w-3 rounded-full bg-destructive" />
                  <span className="text-muted-foreground">Blocked: {stats?.blockedRequests || 0}</span>
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {statsLoading ? (
              <Skeleton className="h-[280px] w-full" />
            ) : (
              <div className="h-[280px] flex flex-col items-center justify-center">
                <div className="w-full space-y-4">
                  {metrics.requestDistribution.map((item) => (
                    <div key={item.label} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium">{item.label}</span>
                        <span className="text-sm text-muted-foreground">{item.value} ({item.percentage}%)</span>
                      </div>
                      <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
                        <div
                          className={`h-full transition-all ${
                            item.label === "Allowed"
                              ? "bg-green-500"
                              : item.label === "Blocked"
                                ? "bg-red-500"
                                : "bg-yellow-500"
                          }`}
                          style={{ width: `${item.percentage}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Request Summary */}
        <Card>
          <CardHeader className="pb-4">
            <CardTitle className="text-base font-semibold">Request Summary</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Allowed</span>
              <span className="font-semibold">{stats?.allowedRequests || 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Monitored</span>
              <span className="font-semibold">{stats?.flaggedRequests || 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Blocked</span>
              <span className="font-semibold text-destructive">{stats?.blockedRequests || 0}</span>
            </div>
            <div className="pt-2 border-t">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold">Block Rate</span>
                <span className="text-lg font-bold text-destructive">{stats?.blockPercentage?.toFixed(1) || 0}%</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Behavioral & Geo-Location Analytics */}
      <div className="grid gap-6 lg:grid-cols-2">
        <BehavioralAnalytics stats={analytics?.behavioral || null} />
        <GeoAnalytics stats={analytics?.geo || null} />
      </div>

      {/* Alerts & Health */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Recent Alerts */}
        <Card>
          <CardHeader className="pb-4 flex flex-row items-center justify-between">
            <CardTitle className="text-base font-semibold">Recent Alerts</CardTitle>
            <Button variant="ghost" size="sm" asChild>
              <Link href="/alerts">View All</Link>
            </Button>
          </CardHeader>
          <CardContent>
            {alertsLoading ? (
              <div className="space-y-3">
                {[1, 2, 3].map((i) => (
                  <Skeleton key={i} className="h-16 w-full" />
                ))}
              </div>
            ) : alerts && alerts.length > 0 ? (
              <div className="space-y-3">
                {alerts.slice(0, 5).map((alert) => (
                  <div
                    key={alert.id}
                    className="flex items-start gap-3 p-3 rounded-lg bg-muted/50 hover:bg-muted transition-colors"
                  >
                    <AlertTriangle className="h-5 w-5 text-yellow-500 mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-sm truncate">{alert.title}</span>
                        <SeverityBadge severity={alert.severity} />
                      </div>
                      <p className="text-sm text-muted-foreground truncate mt-1">
                        {alert.message}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 text-center">
                <Shield className="h-10 w-10 text-muted-foreground/50 mb-3" />
                <p className="text-sm font-semibold">No alerts</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Your systems are running smoothly
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* System Health */}
        <Card>
          <CardHeader className="pb-4">
            <CardTitle className="text-base font-semibold">System Health</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
              <span className="text-sm font-medium">Active Tenants</span>
              <span className="text-2xl font-bold">{stats?.activeTenants || 0}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
              <span className="text-sm font-medium">Active Rules</span>
              <span className="text-2xl font-bold">{stats?.activeRules || 0}</span>
            </div>
            <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
              <span className="text-sm font-medium">Open Alerts</span>
              <span className="text-2xl font-bold">{(alerts?.filter(a => !a.isDismissed) || []).length}</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Protected Sites */}
      <Card>
        <CardHeader className="pb-4 flex flex-row items-center justify-between">
          <CardTitle className="text-base font-semibold">Protected Sites</CardTitle>
          <Button variant="outline" size="sm" asChild>
            <Link href="/tenants">Manage All</Link>
          </Button>
        </CardHeader>
        <CardContent>
          {tenantsLoading ? (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-24 w-full" />
              ))}
            </div>
          ) : tenants && tenants.length > 0 ? (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {tenants.slice(0, 6).map((tenant) => (
                <Link key={tenant.id} href={`/tenants/${tenant.id}`}>
                  <div className="p-4 rounded-lg border border-border hover:border-primary hover:shadow-md transition-all cursor-pointer">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-semibold truncate">{tenant.name}</span>
                      <Badge variant={tenant.isActive ? "default" : "secondary"}>
                        {tenant.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground truncate">{tenant.domain}</p>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Globe className="h-12 w-12 text-muted-foreground/50 mb-4" />
              <h3 className="text-lg font-semibold mb-2">No sites configured</h3>
              <p className="text-sm text-muted-foreground max-w-md mb-4">
                Add your first website to start protecting it with WAF rules and monitoring.
              </p>
              <Button asChild>
                <Link href="/tenants/new">Add Your First Site</Link>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
