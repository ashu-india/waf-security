import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from "recharts";
import { Shield, AlertCircle } from "lucide-react";

interface FrameworkComparison {
  framework: string;
  totalRules: number;
  mandatoryRules: number;
  mandatoryCompliance: number;
  recommendedRules: number;
  recommendedCompliance: number;
  overallCompliance: number;
}

export default function ComplianceComparison() {
  const [selectedTenant] = useState("tenant-1");

  const { data: comparison, isLoading } = useQuery<FrameworkComparison[]>({
    queryKey: [`/api/compliance-dashboard/tenant/${selectedTenant}/framework-comparison`],
    staleTime: 30000,
    refetchInterval: 60000,
  });

  const comparianceChartData = comparison?.map((fc) => ({
    name: fc.framework,
    mandatory: fc.mandatoryCompliance,
    recommended: fc.recommendedCompliance,
    overall: fc.overallCompliance,
  })) || [];

  const complianceBreakdown = comparison?.map((fc) => ({
    name: fc.framework,
    mandatoryRules: fc.mandatoryRules,
    recommendedRules: fc.recommendedRules,
  })) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Framework Comparison</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Compare compliance requirements across all selected frameworks
          </p>
        </div>
      </div>

      {/* Comparison Overview */}
      {isLoading ? (
        <>
          <Skeleton className="h-32" />
          <Skeleton className="h-96" />
        </>
      ) : comparison && comparison.length > 0 ? (
        <>
          {/* Metrics Grid */}
          <div className="grid gap-4">
            {comparison.map((fc) => (
              <Card key={fc.framework}>
                <CardHeader className="pb-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-blue-600" />
                      <div>
                        <CardTitle className="text-lg">{fc.framework}</CardTitle>
                        <CardDescription>{fc.totalRules} total rules</CardDescription>
                      </div>
                    </div>
                    <Badge variant={fc.overallCompliance >= 80 ? "default" : "destructive"}>
                      {fc.overallCompliance}% Compliant
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* Mandatory Rules */}
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm font-medium">Mandatory Rules</span>
                        <span className="text-sm text-muted-foreground">
                          {fc.mandatoryRules} rules
                        </span>
                      </div>
                      <div className="w-full bg-slate-200 rounded-full h-2">
                        <div
                          className="bg-green-600 h-2 rounded-full"
                          style={{ width: `${fc.mandatoryCompliance}%` }}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {fc.mandatoryCompliance}% compliance
                      </p>
                    </div>

                    {/* Recommended Rules */}
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm font-medium">Recommended Rules</span>
                        <span className="text-sm text-muted-foreground">
                          {fc.recommendedRules} rules
                        </span>
                      </div>
                      <div className="w-full bg-slate-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full"
                          style={{ width: `${fc.recommendedCompliance}%` }}
                        />
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        {fc.recommendedCompliance}% compliance
                      </p>
                    </div>

                    {/* Overall Compliance */}
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm font-medium">Overall Compliance</span>
                        <span className="text-sm font-semibold text-muted-foreground">
                          {fc.overallCompliance}%
                        </span>
                      </div>
                      <div className="w-full bg-slate-200 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${
                            fc.overallCompliance >= 80 ? "bg-green-600" : "bg-yellow-600"
                          }`}
                          style={{ width: `${fc.overallCompliance}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Comparison Charts */}
          <Card>
            <CardHeader>
              <CardTitle>Compliance Comparison</CardTitle>
              <CardDescription>Compliance percentage by category across frameworks</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={comparianceChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis domain={[0, 100]} />
                  <Tooltip formatter={(value) => `${value}%`} />
                  <Legend />
                  <Bar dataKey="mandatory" fill="#10b981" name="Mandatory %" />
                  <Bar dataKey="recommended" fill="#3b82f6" name="Recommended %" />
                  <Bar dataKey="overall" fill="#8b5cf6" name="Overall %" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Rule Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>Rule Distribution</CardTitle>
              <CardDescription>Mandatory vs Recommended rules per framework</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={complianceBreakdown}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="mandatoryRules" fill="#ef4444" name="Mandatory Rules" />
                  <Bar dataKey="recommendedRules" fill="#f59e0b" name="Recommended Rules" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </>
      ) : (
        <Card>
          <CardContent className="pt-6 text-center">
            <AlertCircle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <p className="text-muted-foreground">No frameworks selected for comparison</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
