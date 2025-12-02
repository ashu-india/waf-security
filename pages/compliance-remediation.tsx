import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckCircle, AlertTriangle, Play, Zap, Clock } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface RemediationAction {
  id: string;
  tenantId: string;
  frameworkId: string;
  type: "enable_rule" | "update_policy" | "enforce_strict" | "manual_review";
  status: "pending" | "in_progress" | "completed" | "failed";
  description: string;
  affectedRules: number[];
  executedAt?: string;
  result?: string;
  createdAt: string;
}

export default function ComplianceRemediation() {
  const [selectedTenant] = useState("tenant-1");
  const queryClient = useQueryClient();

  // Query remediation history
  const { data: history, isLoading: historyLoading } = useQuery<RemediationAction[]>({
    queryKey: [`/api/compliance-remediation/tenant/${selectedTenant}/history`],
    staleTime: 30000,
    refetchInterval: 60000,
  });

  // Execute remediation mutation
  const executeRemediation = useMutation({
    mutationFn: async (action: RemediationAction) => {
      const res = await fetch("/api/compliance-remediation/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(action),
      });
      if (!res.ok) throw new Error("Failed to execute remediation");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/compliance-remediation/tenant/${selectedTenant}/history`] });
    },
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "default";
      case "failed":
        return "destructive";
      case "in_progress":
        return "secondary";
      default:
        return "outline";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case "failed":
        return <AlertTriangle className="h-4 w-4 text-red-600" />;
      default:
        return <Clock className="h-4 w-4 text-yellow-600" />;
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case "enforce_strict":
        return "destructive";
      case "enable_rule":
        return "secondary";
      case "update_policy":
        return "outline";
      default:
        return "default";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance Remediation</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Automated compliance actions and policy enforcement
          </p>
        </div>
      </div>

      {/* Info Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Total Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{history?.length || 0}</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Completed</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-green-600">
              {history?.filter((a) => a.status === "completed").length || 0}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Pending</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-yellow-600">
              {history?.filter((a) => a.status === "pending").length || 0}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Actions Table */}
      {historyLoading ? (
        <>
          <Skeleton className="h-12" />
          <Skeleton className="h-96" />
        </>
      ) : history && history.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Remediation Actions</CardTitle>
            <CardDescription>History of automated compliance remediation</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Status</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Result</TableHead>
                    <TableHead className="text-right">Date</TableHead>
                    <TableHead className="text-center">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.map((action) => (
                    <TableRow key={action.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getStatusIcon(action.status)}
                          <Badge className={getStatusColor(action.status)}>
                            {action.status}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={getTypeColor(action.type)}>
                          {action.type.replace(/_/g, " ").toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <div className="truncate text-sm">{action.description}</div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {action.result || "-"}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground text-right">
                        {new Date(action.createdAt).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-center">
                        {action.status === "pending" && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => executeRemediation.mutate(action)}
                            disabled={executeRemediation.isPending}
                          >
                            <Play className="h-3 w-3 mr-1" />
                            Execute
                          </Button>
                        )}
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
            <Zap className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <p className="text-muted-foreground">No remediation actions yet</p>
          </CardContent>
        </Card>
      )}

      {/* Info Box */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5" />
            Remediation Types
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div>
              <p className="font-semibold text-sm">Enable Rules</p>
              <p className="text-xs text-muted-foreground">Auto-enable missing compliance rules</p>
            </div>
            <div>
              <p className="font-semibold text-sm">Update Policy</p>
              <p className="text-xs text-muted-foreground">Update security policy with compliance requirements</p>
            </div>
            <div>
              <p className="font-semibold text-sm">Enforce Strict Mode</p>
              <p className="text-xs text-muted-foreground">Activate strict compliance mode (critical situations)</p>
            </div>
            <div>
              <p className="font-semibold text-sm">Manual Review</p>
              <p className="text-xs text-muted-foreground">Flag for manual compliance review</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
