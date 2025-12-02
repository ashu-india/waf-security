import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertCircle, CheckCircle, AlertTriangle, Zap, Clock } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart, Area } from "recharts";

interface ComplianceStatus {
  frameworkName: string;
  score: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  status: "compliant" | "at_risk" | "non_compliant";
  lastCheck: string;
  alerts: any[];
}

interface ComplianceAlert {
  id: string;
  frameworkName: string;
  severity: "low" | "medium" | "high" | "critical";
  type: string;
  message: string;
  currentScore: number;
  createdAt: string;
  isRead: boolean;
}

export default function ComplianceMonitoring() {
  const [selectedTenant] = useState("tenant-1");
  const [liveData, setLiveData] = useState<ComplianceStatus[]>([]);

  const { data: statusesResponse, isLoading } = useQuery<{ statuses: ComplianceStatus[] }>({
    queryKey: [`/api/compliance-monitoring/tenant/${selectedTenant}/status`],
    staleTime: 10000,
    refetchInterval: 30000,
  });

  const { data: alertsResponse, isLoading: alertsLoading } = useQuery<{ alerts: ComplianceAlert[] }>({
    queryKey: [`/api/compliance-monitoring/tenant/${selectedTenant}/alerts`],
    staleTime: 10000,
    refetchInterval: 30000,
  });

  const statuses = statusesResponse?.statuses || [];
  const alerts = alertsResponse?.alerts || [];

  useEffect(() => {
    // Connect to SSE stream for real-time updates
    const eventSource = new EventSource(`/api/compliance-monitoring/stream/${selectedTenant}`);

    eventSource.addEventListener("status-update", (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.statuses) {
          setLiveData(data.statuses);
        }
      } catch (error) {
        console.error("Error parsing status update:", error);
      }
    });

    return () => eventSource.close();
  }, [selectedTenant]);

  const getRiskIcon = (level: string) => {
    switch (level) {
      case "critical":
        return <Zap className="h-5 w-5 text-red-600" />;
      case "high":
        return <AlertTriangle className="h-5 w-5 text-orange-600" />;
      case "medium":
        return <AlertCircle className="h-5 w-5 text-yellow-600" />;
      default:
        return <CheckCircle className="h-5 w-5 text-green-600" />;
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case "critical":
        return "destructive";
      case "high":
        return "secondary";
      case "medium":
        return "outline";
      default:
        return "default";
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-800 border-red-300";
      case "high":
        return "bg-orange-100 text-orange-800 border-orange-300";
      case "medium":
        return "bg-yellow-100 text-yellow-800 border-yellow-300";
      default:
        return "bg-blue-100 text-blue-800 border-blue-300";
    }
  };

  const displayStatuses = liveData.length > 0 ? liveData : statuses || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Real-time Compliance Monitoring</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Live compliance status tracking and instant alerts
          </p>
        </div>
        <Badge variant="outline" className="gap-1">
          <Clock className="h-3 w-3" />
          <span>Live Updates</span>
        </Badge>
      </div>

      {/* Overall Status Grid */}
      {isLoading ? (
        <>
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </>
      ) : (
        <>
          {/* Status Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Total Frameworks</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold">{displayStatuses.length}</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Compliant</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-green-600">
                  {displayStatuses.filter((s) => s.status === "compliant").length}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">At Risk</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-yellow-600">
                  {displayStatuses.filter((s) => s.status === "at_risk").length}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Non-Compliant</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-red-600">
                  {displayStatuses.filter((s) => s.status === "non_compliant").length}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Framework Status Cards */}
          <Card>
            <CardHeader>
              <CardTitle>Framework Status</CardTitle>
              <CardDescription>Real-time compliance status for each framework</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {displayStatuses.map((status) => (
                  <div key={status.frameworkName} className="flex items-center justify-between p-4 border rounded-lg hover:bg-slate-50 transition-colors">
                    <div className="flex items-center gap-3">
                      {getRiskIcon(status.riskLevel)}
                      <div>
                        <h3 className="font-semibold">{status.frameworkName}</h3>
                        <p className="text-xs text-muted-foreground">
                          Updated: {new Date(status.lastCheck).toLocaleTimeString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="text-2xl font-bold">{status.score}%</p>
                        <Badge className={getRiskColor(status.riskLevel)}>
                          {status.riskLevel.toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Active Alerts */}
          {alertsLoading ? (
            <Skeleton className="h-96" />
          ) : alerts && alerts.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5" />
                  Active Alerts ({alerts.length})
                </CardTitle>
                <CardDescription>Real-time compliance violations and warnings</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {alerts.map((alert) => (
                    <div key={alert.id} className={`p-4 border-l-4 rounded-lg ${getSeverityColor(alert.severity)}`}>
                      <div className="flex items-start justify-between">
                        <div>
                          <p className="font-semibold">{alert.frameworkName}</p>
                          <p className="text-sm mt-1">{alert.message}</p>
                          <p className="text-xs mt-2 opacity-75">
                            Score: {alert.currentScore}% | {new Date(alert.createdAt).toLocaleString()}
                          </p>
                        </div>
                        <Badge className={alert.severity} variant="outline">
                          {alert.type.replace(/_/g, " ").toUpperCase()}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="pt-6 text-center">
                <CheckCircle className="h-12 w-12 mx-auto mb-4 text-green-600" />
                <p className="text-muted-foreground">All frameworks compliant - No active alerts</p>
              </CardContent>
            </Card>
          )}

          {/* Score Trend */}
          <Card>
            <CardHeader>
              <CardTitle>Compliance Score Trend</CardTitle>
              <CardDescription>Simulated trend of compliance scores over time</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart
                  data={displayStatuses.map((s, i) => ({
                    name: s.frameworkName,
                    score: s.score,
                    time: i,
                  }))}
                >
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis domain={[0, 100]} />
                  <Tooltip formatter={(value) => `${value}%`} />
                  <Area type="monotone" dataKey="score" fill="#3b82f6" stroke="#3b82f6" />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
