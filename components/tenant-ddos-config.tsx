import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Shield, Zap, RotateCcw } from "lucide-react";

interface DDoSConfig {
  maxConnections: number;
  maxConnectionsPerIP: number;
  maxRequestsPerSecond: number;
  maxRequestsPerIPPerSecond: number;
  volumetricThreshold: number;
  uniqueIPThreshold: number;
  anomalyThreshold: number;
  enableAutomaticMitigation: boolean;
  graduatedResponseEnabled: boolean;
  enableNormalization: boolean;
}

interface TenantDDoSConfigProps {
  tenantId: string;
}

export function TenantDDoSConfig({ tenantId }: TenantDDoSConfigProps) {
  const [editMode, setEditMode] = useState(false);
  const [config, setConfig] = useState<Partial<DDoSConfig>>({});

  const { data: currentConfig, isLoading } = useQuery<DDoSConfig>({
    queryKey: [`/api/tenants/${tenantId}/ddos/config`],
    staleTime: 30000,
    onSuccess: (data) => {
      setConfig(data);
    },
  });

  const configMutation = useMutation({
    mutationFn: async (newConfig: Partial<DDoSConfig>) => {
      const res = await fetch(`/api/tenants/${tenantId}/ddos/config`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config: newConfig }),
      });
      if (!res.ok) throw new Error("Failed to update config");
      return res.json();
    },
    onSuccess: () => {
      alert("✅ Configuration updated for tenant");
      setEditMode(false);
    },
  });

  const resetMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch(`/api/tenants/${tenantId}/ddos/reset`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to reset");
      return res.json();
    },
    onSuccess: () => {
      alert("✅ DDoS detection state reset for tenant");
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <Tabs defaultValue="settings" className="space-y-6">
      <TabsList className="grid w-full grid-cols-2">
        <TabsTrigger value="settings" className="flex items-center gap-2">
          <Shield className="h-4 w-4" />
          <span>Configuration</span>
        </TabsTrigger>
        <TabsTrigger value="actions" className="flex items-center gap-2">
          <Zap className="h-4 w-4" />
          <span>Actions</span>
        </TabsTrigger>
      </TabsList>

      {/* Settings Tab */}
      <TabsContent value="settings" className="space-y-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>DDoS Detection Configuration</CardTitle>
              <CardDescription>Per-tenant thresholds and response settings</CardDescription>
            </div>
            <div className="flex gap-2">
              {editMode ? (
                <>
                  <Button
                    size="sm"
                    variant="default"
                    onClick={() => {
                      configMutation.mutate(config);
                    }}
                    disabled={configMutation.isPending}
                  >
                    Save
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => {
                    setConfig(currentConfig || {});
                    setEditMode(false);
                  }}>
                    Cancel
                  </Button>
                </>
              ) : (
                <Button size="sm" variant="outline" onClick={() => setEditMode(true)}>
                  Edit
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="grid gap-6 md:grid-cols-2">
              {/* Rate Limits */}
              <div className="space-y-4 p-4 border rounded-lg">
                <h4 className="font-semibold flex items-center gap-2">
                  <Zap className="h-4 w-4" />
                  Rate Limits
                </h4>
                <div className="space-y-3">
                  <div>
                    <Label className="text-xs">Tenant: Requests/sec</Label>
                    <Input
                      type="number"
                      value={config.maxRequestsPerSecond || 5000}
                      onChange={(e) => setConfig({ ...config, maxRequestsPerSecond: parseInt(e.target.value) })}
                      disabled={!editMode}
                      className="text-sm"
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Per-IP: Requests/sec</Label>
                    <Input
                      type="number"
                      value={config.maxRequestsPerIPPerSecond || 50}
                      onChange={(e) => setConfig({ ...config, maxRequestsPerIPPerSecond: parseInt(e.target.value) })}
                      disabled={!editMode}
                      className="text-sm"
                    />
                  </div>
                </div>
              </div>

              {/* Connection Limits */}
              <div className="space-y-4 p-4 border rounded-lg">
                <h4 className="font-semibold flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Connection Limits
                </h4>
                <div className="space-y-3">
                  <div>
                    <Label className="text-xs">Tenant: Max Connections</Label>
                    <Input
                      type="number"
                      value={config.maxConnections || 10000}
                      onChange={(e) => setConfig({ ...config, maxConnections: parseInt(e.target.value) })}
                      disabled={!editMode}
                      className="text-sm"
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Per-IP: Max Connections</Label>
                    <Input
                      type="number"
                      value={config.maxConnectionsPerIP || 100}
                      onChange={(e) => setConfig({ ...config, maxConnectionsPerIP: parseInt(e.target.value) })}
                      disabled={!editMode}
                      className="text-sm"
                    />
                  </div>
                </div>
              </div>

              {/* Thresholds */}
              <div className="space-y-4 p-4 border rounded-lg">
                <h4 className="font-semibold">Detection Thresholds</h4>
                <div className="space-y-3">
                  <div>
                    <Label className="text-xs">Volumetric Threshold (req/sec)</Label>
                    <Input
                      type="number"
                      value={config.volumetricThreshold || 3000}
                      onChange={(e) => setConfig({ ...config, volumetricThreshold: parseInt(e.target.value) })}
                      disabled={!editMode}
                      className="text-sm"
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Unique IP Threshold</Label>
                    <Input
                      type="number"
                      value={config.uniqueIPThreshold || 500}
                      onChange={(e) => setConfig({ ...config, uniqueIPThreshold: parseInt(e.target.value) })}
                      disabled={!editMode}
                      className="text-sm"
                    />
                  </div>
                  <div>
                    <Label className="text-xs">Anomaly Threshold (0-1)</Label>
                    <Input
                      type="number"
                      step="0.1"
                      min="0"
                      max="1"
                      value={config.anomalyThreshold || 0.7}
                      onChange={(e) => setConfig({ ...config, anomalyThreshold: parseFloat(e.target.value) })}
                      disabled={!editMode}
                      className="text-sm"
                    />
                  </div>
                </div>
              </div>

              {/* Features */}
              <div className="space-y-4 p-4 border rounded-lg">
                <h4 className="font-semibold">Features</h4>
                <div className="space-y-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span>Graduated Response</span>
                    <Badge variant={config.graduatedResponseEnabled !== false ? "default" : "outline"}>
                      {config.graduatedResponseEnabled !== false ? "Enabled" : "Disabled"}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Traffic Normalization</span>
                    <Badge variant={config.enableNormalization !== false ? "default" : "outline"}>
                      {config.enableNormalization !== false ? "Enabled" : "Disabled"}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span>Auto-Mitigation</span>
                    <Badge variant={config.enableAutomaticMitigation !== false ? "default" : "outline"}>
                      {config.enableAutomaticMitigation !== false ? "Enabled" : "Disabled"}
                    </Badge>
                  </div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </TabsContent>

      {/* Actions Tab */}
      <TabsContent value="actions" className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle>Maintenance Actions</CardTitle>
            <CardDescription>Reset and manage DDoS detection state for this tenant</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button
              variant="outline"
              size="lg"
              onClick={() => {
                if (confirm("Reset DDoS detection state for this tenant? This will clear all tracking data.")) {
                  resetMutation.mutate();
                }
              }}
              disabled={resetMutation.isPending}
              className="gap-2 w-full justify-start"
            >
              <RotateCcw className="h-4 w-4" />
              Reset Detection State
            </Button>
            <p className="text-sm text-muted-foreground">
              Clears all IP tracking, request history, and resets detection metrics to zero. Useful after testing or to recover from stuck states.
            </p>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  );
}
