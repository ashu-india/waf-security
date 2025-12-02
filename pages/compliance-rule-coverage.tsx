import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { AlertCircle, Download, Filter } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface RuleDetail {
  ruleId: string;
  description: string;
  category: string;
  severity: string;
  compliantTenants: number;
  nonCompliantTenants: number;
  overallCoverage: number;
}

export default function ComplianceRuleCoverage() {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);

  const { data: coverage, isLoading } = useQuery<RuleDetail[]>({
    queryKey: ["/api/compliance-dashboard/rule-coverage"],
    staleTime: 30000,
    refetchInterval: 60000,
  });

  const filteredRules = coverage?.filter((rule) => {
    const matchesSearch = rule.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.category.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = !selectedCategory || rule.category === selectedCategory;
    return matchesSearch && matchesCategory;
  }) || [];

  const categories = Array.from(new Set(coverage?.map((r) => r.category) || []));

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
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

  const getCoverageColor = (coverage: number) => {
    if (coverage >= 90) return "text-green-600";
    if (coverage >= 70) return "text-yellow-600";
    return "text-red-600";
  };

  const handleExport = () => {
    const csv = [
      ["Rule ID", "Description", "Category", "Severity", "Compliant Tenants", "Non-Compliant Tenants", "Coverage %"],
      ...filteredRules.map((rule) => [
        rule.ruleId,
        rule.description,
        rule.category,
        rule.severity,
        rule.compliantTenants.toString(),
        rule.nonCompliantTenants.toString(),
        rule.overallCoverage.toString(),
      ]),
    ];

    const csvContent = csv.map((row) => row.map((cell) => `"${cell}"`).join(",")).join("\n");
    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "rule-coverage.csv";
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Rule Coverage Analysis</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Monitor compliance rule implementation across all tenants
          </p>
        </div>
        <Button onClick={handleExport} variant="outline" size="sm" disabled={filteredRules.length === 0}>
          <Download className="h-4 w-4 mr-2" />
          Export CSV
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Search Rules</label>
              <Input
                placeholder="Search by rule ID, description, or category..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="mt-2"
              />
            </div>
            <div>
              <label className="text-sm font-medium flex items-center gap-2">
                <Filter className="h-4 w-4" />
                Filter by Category
              </label>
              <div className="flex flex-wrap gap-2 mt-2">
                <Button
                  variant={selectedCategory === null ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSelectedCategory(null)}
                >
                  All Categories
                </Button>
                {categories.map((cat) => (
                  <Button
                    key={cat}
                    variant={selectedCategory === cat ? "default" : "outline"}
                    size="sm"
                    onClick={() => setSelectedCategory(cat)}
                  >
                    {cat}
                  </Button>
                ))}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Rules Table */}
      {isLoading ? (
        <>
          <Skeleton className="h-12" />
          <Skeleton className="h-96" />
        </>
      ) : filteredRules.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Coverage Details</CardTitle>
            <CardDescription>
              Showing {filteredRules.length} of {coverage?.length || 0} rules
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rule ID</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead className="text-center">Compliant</TableHead>
                    <TableHead className="text-center">Non-Compliant</TableHead>
                    <TableHead className="text-right">Coverage</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRules.map((rule) => (
                    <TableRow key={rule.ruleId}>
                      <TableCell className="font-mono text-sm">{rule.ruleId}</TableCell>
                      <TableCell className="max-w-xs">
                        <div className="truncate text-sm">{rule.description}</div>
                      </TableCell>
                      <TableCell className="text-sm">{rule.category}</TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(rule.severity)}>
                          {rule.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-center text-sm font-medium">
                        {rule.compliantTenants}
                      </TableCell>
                      <TableCell className="text-center text-sm font-medium">
                        {rule.nonCompliantTenants}
                      </TableCell>
                      <TableCell className={`text-right font-semibold ${getCoverageColor(rule.overallCoverage)}`}>
                        {rule.overallCoverage}%
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="pt-6 text-center">
            <AlertCircle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <p className="text-muted-foreground">No rules match your filters</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
