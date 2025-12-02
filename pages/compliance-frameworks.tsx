import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { CheckCircle, AlertCircle, Shield, Plus, Trash2, Clock } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface ComplianceFramework {
  id: string;
  name: string;
  description?: string;
  ruleCount: number;
}

interface TenantFramework {
  id: string;
  tenantId: string;
  frameworkId: string;
  status: "pending_assessment" | "compliant" | "non_compliant";
  complianceScore: number;
  selectedAt: string;
  framework: ComplianceFramework;
}

interface AuditLog {
  id: string;
  tenantId: string;
  action: string;
  frameworkId?: string;
  frameworkName?: string;
  userEmail: string;
  timestamp: string;
  details?: string;
}

export default function ComplianceFrameworks() {
  const [selectedTenant] = useState("tenant-1");
  const queryClient = useQueryClient();

  // Get available frameworks
  const { data: availableFrameworks, isLoading: frameworksLoading } = useQuery<ComplianceFramework[]>({
    queryKey: ["/api/compliance/frameworks"],
    staleTime: 5 * 60 * 1000,
  });

  // Get selected frameworks for tenant
  const { data: selectedFrameworks, isLoading: selectedLoading } = useQuery<TenantFramework[]>({
    queryKey: [`/api/tenant-compliance/${selectedTenant}/frameworks`],
    staleTime: 30000,
    refetchInterval: 60000,
  });

  // Get audit trail
  const { data: auditTrail, isLoading: auditLoading } = useQuery<AuditLog[]>({
    queryKey: [`/api/compliance/tenant/${selectedTenant}/audit-trail`],
    staleTime: 30000,
    refetchInterval: 60000,
  });

  // Select framework mutation
  const selectFramework = useMutation({
    mutationFn: async (frameworkId: string) => {
      const res = await fetch("/api/tenant-compliance/select-framework", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ tenantId: selectedTenant, frameworkId }),
      });
      if (!res.ok) throw new Error("Failed to select framework");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/tenant-compliance/${selectedTenant}/frameworks`] });
      queryClient.invalidateQueries({ queryKey: [`/api/compliance/tenant/${selectedTenant}/audit-trail`] });
    },
  });

  // Deselect framework mutation
  const deselectFramework = useMutation({
    mutationFn: async (frameworkId: string) => {
      const res = await fetch("/api/tenant-compliance/deselect-framework", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ tenantId: selectedTenant, frameworkId }),
      });
      if (!res.ok) throw new Error("Failed to deselect framework");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/tenant-compliance/${selectedTenant}/frameworks`] });
      queryClient.invalidateQueries({ queryKey: [`/api/compliance/tenant/${selectedTenant}/audit-trail`] });
    },
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case "compliant":
        return "default";
      case "non_compliant":
        return "destructive";
      default:
        return "outline";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "compliant":
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case "non_compliant":
        return <AlertCircle className="h-4 w-4 text-red-600" />;
      default:
        return <Shield className="h-4 w-4 text-yellow-600" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance Frameworks</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Manage compliance frameworks and track your compliance status
          </p>
        </div>
      </div>

      <Tabs defaultValue="selected" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="selected">Selected ({selectedFrameworks?.length || 0})</TabsTrigger>
          <TabsTrigger value="available">Available</TabsTrigger>
          <TabsTrigger value="audit">Audit Trail</TabsTrigger>
        </TabsList>

        {/* Selected Frameworks Tab */}
        <TabsContent value="selected" className="space-y-4">
          {selectedLoading ? (
            <>
              <Skeleton className="h-32" />
              <Skeleton className="h-32" />
            </>
          ) : selectedFrameworks && selectedFrameworks.length > 0 ? (
            <div className="space-y-4">
              {selectedFrameworks.map((sf) => (
                <Card key={sf.id}>
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(sf.status)}
                        <div>
                          <CardTitle className="text-lg">{sf.framework.name}</CardTitle>
                          <CardDescription className="text-xs">
                            {sf.framework.ruleCount} rules
                          </CardDescription>
                        </div>
                      </div>
                      <Badge className={getStatusColor(sf.status)}>
                        {sf.status.replace(/_/g, " ").toUpperCase()}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-muted-foreground">Compliance Score</span>
                        <span className="font-semibold">{sf.complianceScore}%</span>
                      </div>
                      <div className="flex justify-between items-center text-sm">
                        <span className="text-muted-foreground">Selected</span>
                        <span className="text-xs text-muted-foreground">
                          {new Date(sf.selectedAt).toLocaleDateString()}
                        </span>
                      </div>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => deselectFramework.mutate(sf.frameworkId)}
                        disabled={deselectFramework.isPending}
                        className="mt-4 w-full"
                      >
                        <Trash2 className="h-4 w-4 mr-2" />
                        Remove Framework
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="pt-6 text-center">
                <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">No frameworks selected yet</p>
                <p className="text-xs text-muted-foreground mt-2">
                  Add frameworks to start compliance tracking
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Available Frameworks Tab */}
        <TabsContent value="available" className="space-y-4">
          {frameworksLoading ? (
            <>
              <Skeleton className="h-32" />
              <Skeleton className="h-32" />
            </>
          ) : availableFrameworks && availableFrameworks.length > 0 ? (
            <div className="space-y-3">
              {availableFrameworks.map((fw) => {
                const isSelected = selectedFrameworks?.some((sf) => sf.frameworkId === fw.id);
                return (
                  <Card key={fw.id} className={isSelected ? "opacity-50" : ""}>
                    <CardContent className="pt-6">
                      <div className="flex items-start justify-between">
                        <div>
                          <h3 className="font-semibold">{fw.name}</h3>
                          <p className="text-sm text-muted-foreground">
                            {fw.ruleCount} compliance rules
                          </p>
                          {fw.description && (
                            <p className="text-xs text-muted-foreground mt-2">{fw.description}</p>
                          )}
                        </div>
                        <Button
                          onClick={() => selectFramework.mutate(fw.id)}
                          disabled={isSelected || selectFramework.isPending}
                          size="sm"
                        >
                          <Plus className="h-4 w-4 mr-1" />
                          {isSelected ? "Selected" : "Add"}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          ) : (
            <Card>
              <CardContent className="pt-6 text-center">
                <AlertCircle className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">No available frameworks</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Audit Trail Tab */}
        <TabsContent value="audit" className="space-y-4">
          {auditLoading ? (
            <>
              <Skeleton className="h-12" />
              <Skeleton className="h-12" />
            </>
          ) : auditTrail && auditTrail.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle>Compliance Audit Trail</CardTitle>
                <CardDescription>All compliance-related actions and changes</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Action</TableHead>
                        <TableHead>Framework</TableHead>
                        <TableHead>User</TableHead>
                        <TableHead>Timestamp</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {auditTrail.map((log) => (
                        <TableRow key={log.id}>
                          <TableCell className="font-medium">{log.action}</TableCell>
                          <TableCell>{log.frameworkName || "-"}</TableCell>
                          <TableCell className="text-sm">{log.userEmail}</TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {new Date(log.timestamp).toLocaleString()}
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
                <Clock className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">No audit trail events yet</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
