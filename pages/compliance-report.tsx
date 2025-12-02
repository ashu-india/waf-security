import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Download, FileText, AlertCircle, CheckCircle } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";

interface ComplianceReport {
  generatedAt: string;
  tenant: {
    id: string;
    name: string;
  };
  summary: {
    overallScore: number;
    riskLevel: "low" | "medium" | "high" | "critical";
    selectedFrameworks: number;
    totalRules: number;
    compliantRules: number;
    nonCompliantRules: number;
  };
  frameworkDetails: Array<{
    framework: string;
    totalRules: number;
    mandatoryRules: number;
    mandatoryCompliance: number;
    recommendedRules: number;
    recommendedCompliance: number;
    overallCompliance: number;
  }>;
}

export default function ComplianceReport() {
  const [selectedTenant] = useState("tenant-1");

  const { data: report, isLoading } = useQuery<ComplianceReport>({
    queryKey: [`/api/compliance-dashboard/tenant/${selectedTenant}/report`],
    staleTime: 30000,
    refetchInterval: 60000,
  });

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

  const riskTextColor: Record<string, string> = {
    critical: "text-red-600",
    high: "text-orange-600",
    medium: "text-yellow-600",
    low: "text-green-600",
  };

  const handleExportPDF = () => {
    if (!report) return;
    // Generate simple PDF-like content
    const content = `
COMPLIANCE REPORT
Generated: ${new Date(report.generatedAt).toLocaleString()}

TENANT INFORMATION
==================
Name: ${report.tenant.name}
ID: ${report.tenant.id}

EXECUTIVE SUMMARY
=================
Overall Compliance Score: ${report.summary.overallScore}%
Risk Level: ${report.summary.riskLevel.toUpperCase()}
Selected Frameworks: ${report.summary.selectedFrameworks}
Total Rules: ${report.summary.totalRules}
Compliant Rules: ${report.summary.compliantRules}
Non-Compliant Rules: ${report.summary.nonCompliantRules}

FRAMEWORK DETAILS
==================
${report.frameworkDetails
  .map(
    (fd) => `
${fd.framework}
- Total Rules: ${fd.totalRules}
- Mandatory Rules: ${fd.mandatoryRules} (${fd.mandatoryCompliance}% compliant)
- Recommended Rules: ${fd.recommendedRules} (${fd.recommendedCompliance}% compliant)
- Overall Compliance: ${fd.overallCompliance}%
`
  )
  .join("\n")}
    `;

    const blob = new Blob([content], { type: "text/plain" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `compliance-report-${report.tenant.id}.txt`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance Report</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Detailed compliance assessment and framework breakdown
          </p>
        </div>
        <Button onClick={handleExportPDF} variant="outline" size="sm" disabled={isLoading || !report}>
          <Download className="h-4 w-4 mr-2" />
          Export Report
        </Button>
      </div>

      {isLoading ? (
        <>
          <Skeleton className="h-32" />
          <Skeleton className="h-64" />
          <Skeleton className="h-96" />
        </>
      ) : report ? (
        <>
          {/* Header Card */}
          <Card className="bg-gradient-to-br from-slate-50 to-slate-100">
            <CardHeader>
              <div className="flex justify-between items-start">
                <div>
                  <CardTitle className="text-2xl">{report.tenant.name}</CardTitle>
                  <CardDescription className="mt-1">
                    Generated: {new Date(report.generatedAt).toLocaleString()}
                  </CardDescription>
                </div>
                <FileText className="h-8 w-8 text-slate-600" />
              </div>
            </CardHeader>
          </Card>

          {/* Summary Metrics */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Overall Score</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{report.summary.overallScore}%</div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Risk Level</CardTitle>
              </CardHeader>
              <CardContent>
                <Badge className={getRiskColor(report.summary.riskLevel)}>
                  {report.summary.riskLevel.toUpperCase()}
                </Badge>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Compliant Rules</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-green-600">
                  {report.summary.compliantRules}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  of {report.summary.totalRules} total
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium">Frameworks</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{report.summary.selectedFrameworks}</div>
              </CardContent>
            </Card>
          </div>

          {/* Framework Comparison Chart */}
          <Card>
            <CardHeader>
              <CardTitle>Framework Compliance Overview</CardTitle>
              <CardDescription>Overall compliance percentage per framework</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart
                  data={report.frameworkDetails.map((fd) => ({
                    name: fd.framework,
                    compliance: fd.overallCompliance,
                  }))}
                >
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis domain={[0, 100]} />
                  <Tooltip formatter={(value) => `${value}%`} />
                  <Bar dataKey="compliance" fill="#3b82f6" name="Compliance %" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Framework Details */}
          <Card>
            <CardHeader>
              <CardTitle>Framework Details</CardTitle>
              <CardDescription>Comprehensive breakdown of each framework</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {report.frameworkDetails.map((fd) => (
                <div key={fd.framework} className="border-b pb-6 last:border-b-0 last:pb-0">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold">{fd.framework}</h3>
                    <Badge variant="outline">{fd.totalRules} rules</Badge>
                  </div>

                  <div className="space-y-3">
                    {/* Mandatory Rules */}
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span className="font-medium">Mandatory Rules</span>
                        <span className="text-muted-foreground">
                          {fd.mandatoryRules} rules ({fd.mandatoryCompliance}% compliant)
                        </span>
                      </div>
                      <div className="w-full bg-slate-200 rounded-full h-2">
                        <div
                          className="bg-red-600 h-2 rounded-full"
                          style={{ width: `${fd.mandatoryCompliance}%` }}
                        />
                      </div>
                    </div>

                    {/* Recommended Rules */}
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span className="font-medium">Recommended Rules</span>
                        <span className="text-muted-foreground">
                          {fd.recommendedRules} rules ({fd.recommendedCompliance}% compliant)
                        </span>
                      </div>
                      <div className="w-full bg-slate-200 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full"
                          style={{ width: `${fd.recommendedCompliance}%` }}
                        />
                      </div>
                    </div>

                    {/* Overall */}
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span className="font-semibold">Overall Compliance</span>
                        <span className={`font-semibold ${riskTextColor[fd.overallCompliance >= 80 ? "low" : "high"]}`}>
                          {fd.overallCompliance}%
                        </span>
                      </div>
                      <div className="w-full bg-slate-200 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${fd.overallCompliance >= 80 ? "bg-green-600" : "bg-orange-600"}`}
                          style={{ width: `${fd.overallCompliance}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Recommendations */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {report.summary.overallScore >= 80 ? (
                  <CheckCircle className="h-5 w-5 text-green-600" />
                ) : (
                  <AlertCircle className="h-5 w-5 text-yellow-600" />
                )}
                Recommendations
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm">
                {report.summary.overallScore < 80 && (
                  <li className="flex gap-2">
                    <span className="text-red-600">•</span>
                    <span>Address {report.summary.nonCompliantRules} non-compliant rules</span>
                  </li>
                )}
                {report.summary.riskLevel === "critical" && (
                  <li className="flex gap-2">
                    <span className="text-red-600">•</span>
                    <span>Critical compliance issues require immediate attention</span>
                  </li>
                )}
                {report.summary.selectedFrameworks < 3 && (
                  <li className="flex gap-2">
                    <span className="text-blue-600">•</span>
                    <span>Consider adding more compliance frameworks for broader coverage</span>
                  </li>
                )}
                {report.summary.overallScore >= 80 && (
                  <li className="flex gap-2">
                    <span className="text-green-600">•</span>
                    <span>Maintain current compliance score and monitor frameworks regularly</span>
                  </li>
                )}
              </ul>
            </CardContent>
          </Card>
        </>
      ) : (
        <Card>
          <CardContent className="pt-6 text-center">
            <AlertCircle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <p className="text-muted-foreground">Failed to load compliance report</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
