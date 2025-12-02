import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, CheckCircle, Clock, Shield, TrendingUp } from "lucide-react";
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { Link } from "wouter";

interface ComplianceDashboard {
  tenantId: string;
  tenantName: string;
  overallScore: number;
  riskLevel: "low" | "medium" | "high" | "critical";
  selectedFrameworks: number;
  totalRules: number;
  compliantRules: number;
  nonCompliantRules: number;
  frameworkBreakdown: Array<{
    frameworkName: string;
    score: number;
    totalRules: number;
    compliantRules: number;
  }>;
}

interface ComplianceMetrics {
  totalFrameworks: number;
  totalRules: number;
  avgComplianceScore: number;
  tenantsAboveThreshold: number;
  criticalRiskTenants: number;
  mandatoryRulesCovered: number;
  complianceTrendDirection: "improving" | "declining" | "stable";
}

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

export default function ComplianceDashboard() {
  const [selectedTenant, setSelectedTenant] = useState("tenant-1");

  const { data: tenantDashboard, isLoading: dashboardLoading } = useQuery<ComplianceDashboard>({
    queryKey: [`/api/compliance-dashboard/tenant/${selectedTenant}/overview`],
    staleTime: 30000,
    refetchInterval: 60000,
  });

  const { data: metrics, isLoading: metricsLoading } = useQuery<ComplianceMetrics>({
    queryKey: ["/api/compliance-dashboard/metrics"],
    staleTime: 30000,
    refetchInterval: 60000,
  });

  const { data: frameworksResponse, isLoading: frameworksLoading } = useQuery<{ frameworks: any[] }>({
    queryKey: ["/api/compliance/frameworks"],
    staleTime: 5 * 60 * 1000,
  });

  const frameworks = frameworksResponse?.frameworks || [];

  const riskColors: Record<string, string> = {
    critical: "text-red-600",
    high: "text-orange-600",
    medium: "text-yellow-600",
    low: "text-green-600",
  };

  const complianceData = tenantDashboard?.frameworkBreakdown.map((fw) => ({
    name: fw.frameworkName,
    compliant: fw.compliantRules,
    nonCompliant: fw.totalRules - fw.compliantRules,
  })) || [];

  const scoreChartData = tenantDashboard?.frameworkBreakdown.map((fw) => ({
    name: fw.frameworkName,
    score: fw.score,
  })) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Monitor compliance status across frameworks and manage security policies
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="gap-1">
            <Clock className="h-3 w-3" />
            Last updated: just now
          </Badge>
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="frameworks">Frameworks</TabsTrigger>
          <TabsTrigger value="system">System Metrics</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          {/* Overall Score Card */}
          {dashboardLoading ? (
            <Skeleton className="h-32" />
          ) : (
            <Card className="bg-gradient-to-br from-slate-50 to-slate-100">
              <CardHeader>
                <CardTitle>Overall Compliance Score</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-5xl font-bold text-slate-900">
                      {tenantDashboard?.overallScore}%
                    </p>
                    <p className="text-sm text-muted-foreground mt-2">
                      {tenantDashboard?.compliantRules} of {tenantDashboard?.totalRules} rules compliant
                    </p>
                  </div>
                  <div className="text-right">
                    <Badge className={getRiskColor(tenantDashboard?.riskLevel || "")}>
                      {tenantDashboard?.riskLevel.toUpperCase()}
                    </Badge>
                    <p className="text-xs text-muted-foreground mt-2">
                      {tenantDashboard?.selectedFrameworks} frameworks selected
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Metrics Grid */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  <CheckCircle className="h-4 w-4 mr-1 inline" />
                  Compliant Rules
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold">{tenantDashboard?.compliantRules || 0}</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  <AlertTriangle className="h-4 w-4 mr-1 inline text-red-600" />
                  Non-Compliant Rules
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-red-600">{tenantDashboard?.nonCompliantRules || 0}</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  <Shield className="h-4 w-4 mr-1 inline" />
                  Frameworks Active
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold">{tenantDashboard?.selectedFrameworks || 0}</p>
              </CardContent>
            </Card>
          </div>

          {/* Compliance by Framework Chart */}
          {dashboardLoading ? (
            <Skeleton className="h-80" />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Compliance by Framework</CardTitle>
                <CardDescription>Rules compliant vs non-compliant per framework</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={complianceData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="compliant" fill="#10b981" name="Compliant" />
                    <Bar dataKey="nonCompliant" fill="#ef4444" name="Non-Compliant" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Score Trend Chart */}
          {dashboardLoading ? (
            <Skeleton className="h-80" />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Compliance Scores</CardTitle>
                <CardDescription>Score percentage for each framework</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={scoreChartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis domain={[0, 100]} />
                    <Tooltip formatter={(value) => `${value}%`} />
                    <Legend />
                    <Line
                      type="monotone"
                      dataKey="score"
                      stroke="#3b82f6"
                      strokeWidth={2}
                      dot={{ fill: "#3b82f6", r: 5 }}
                      name="Compliance %"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Frameworks Tab */}
        <TabsContent value="frameworks" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Framework Selection</CardTitle>
              <CardDescription>Manage compliance frameworks for your organization</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Button asChild>
                  <Link href="/compliance/frameworks">Manage Frameworks</Link>
                </Button>
                <div className="grid gap-4">
                  {frameworksLoading ? (
                    <>
                      <Skeleton className="h-20" />
                      <Skeleton className="h-20" />
                    </>
                  ) : (
                    frameworks?.map((fw: any) => (
                      <Card key={fw.id} className="border">
                        <CardContent className="pt-6">
                          <div className="flex justify-between items-start">
                            <div>
                              <h3 className="font-semibold">{fw.name}</h3>
                              <p className="text-sm text-muted-foreground">{fw.ruleCount} rules</p>
                            </div>
                            <Badge variant="outline">Available</Badge>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* System Metrics Tab */}
        <TabsContent value="system" className="space-y-4">
          {metricsLoading ? (
            <>
              <Skeleton className="h-32" />
              <Skeleton className="h-32" />
            </>
          ) : (
            <>
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium">Total Frameworks</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold">{metrics?.totalFrameworks}</p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium">Total Rules</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold">{metrics?.totalRules}</p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium">Avg Compliance</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold">{metrics?.avgComplianceScore}%</p>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium">Critical Risk</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-bold text-red-600">{metrics?.criticalRiskTenants}</p>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle>System Overview</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Tenants Above Threshold (80%)</span>
                      <span className="font-semibold">{metrics?.tenantsAboveThreshold}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Mandatory Rules Covered</span>
                      <span className="font-semibold">{metrics?.mandatoryRulesCovered}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Trend Direction</span>
                      <Badge variant="outline">
                        <TrendingUp className="h-3 w-3 mr-1" />
                        {metrics?.complianceTrendDirection}
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
