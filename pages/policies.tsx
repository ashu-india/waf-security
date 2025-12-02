import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Link } from "wouter";
import {
  FileText,
  Plus,
  Search,
  MoreVertical,
  Globe,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { EnhancedGeoPolicyForm } from "@/components/enhanced-geo-policy-form";
import { BehavioralPolicyConfig } from "@/components/behavioral-policy-config";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { EnforcementBadge } from "@/components/ui/status-badge";
import { useToast } from "@/hooks/use-toast";
import { queryClient, apiRequest } from "@/lib/queryClient";
import type { Policy, Tenant } from "@shared/schema";

export default function Policies() {
  const { toast } = useToast();
  const [searchQuery, setSearchQuery] = useState("");
  const [tenantFilter, setTenantFilter] = useState("all");
  const [addDialogOpen, setAddDialogOpen] = useState(false);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null);
  const [duplicateData, setDuplicateData] = useState<Policy | null>(null);

  const { data: policies, isLoading } = useQuery<Policy[]>({
    queryKey: ["/api/policies"],
    staleTime: 10000, // 10 seconds
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  const { data: tenants } = useQuery<Tenant[]>({
    queryKey: ["/api/tenants"],
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  const createPolicyMutation = useMutation({
    mutationFn: async (data: any) => {
      await apiRequest("POST", `/api/policies`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policies"] });
      toast({
        title: "Policy created",
        description: "Your new policy has been successfully created.",
      });
      setAddDialogOpen(false);
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to create policy. Please try again.",
        variant: "destructive",
      });
    },
  });

  const updatePolicyMutation = useMutation({
    mutationFn: async ({
      id,
      data,
    }: {
      id: string;
      data: Partial<Policy>;
    }) => {
      await apiRequest("PATCH", `/api/policies/${id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policies"] });
      toast({
        title: "Policy updated",
        description: "The policy settings have been saved.",
      });
      setEditDialogOpen(false);
      setSelectedPolicy(null);
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update policy. Please try again.",
        variant: "destructive",
      });
    },
  });

  const duplicatePolicyMutation = useMutation({
    mutationFn: async (data: any) => {
      await apiRequest("POST", `/api/policies`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policies"] });
      toast({
        title: "Policy created",
        description: "Duplicated policy has been successfully created.",
      });
      setAddDialogOpen(false);
      setDuplicateData(null);
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to duplicate policy. Please try again.",
        variant: "destructive",
      });
    },
  });

  const deletePolicyMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/policies/${id}`);
    },
    onSuccess: (_, deletedId) => {
      queryClient.setQueryData(["/api/policies"], (oldData: Policy[] | undefined) => {
        return oldData?.filter((p) => p.id !== deletedId) || [];
      });
      toast({
        title: "Policy deleted",
        description: "The policy has been successfully deleted.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete policy. Please try again.",
        variant: "destructive",
      });
    },
  });

  const setDefaultPolicyMutation = useMutation({
    mutationFn: async (policyId: string) => {
      await apiRequest("PATCH", `/api/policies/${policyId}`, { isDefault: true });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/policies"] });
      toast({
        title: "Policy activated",
        description: "This policy is now the default for its website.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to set default policy. Please try again.",
        variant: "destructive",
      });
    },
  });

  const filteredPolicies = policies?.filter((policy) => {
    const matchesSearch = policy.name
      .toLowerCase()
      .includes(searchQuery.toLowerCase());
    const matchesTenant =
      tenantFilter === "all" || policy.tenantId === tenantFilter;
    return matchesSearch && matchesTenant;
  });

  const getTenantName = (tenantId: string) => {
    const tenant = tenants?.find((t) => t.id === tenantId);
    return tenant?.name || "Unknown";
  };

  const handleEditClick = (policy: Policy) => {
    setSelectedPolicy(policy);
    setEditDialogOpen(true);
  };

  const handleDuplicateClick = (policy: Policy) => {
    setDuplicateData(policy);
    setAddDialogOpen(true);
  };

  const handleDeleteClick = (policy: Policy) => {
    if (confirm(`Are you sure you want to delete policy "${policy.name}"?`)) {
      deletePolicyMutation.mutate(policy.id);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            Policies
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Configure enforcement modes and thresholds per site
          </p>
        </div>
        <Button onClick={() => setAddDialogOpen(true)} data-testid="button-add-policy">
          <Plus className="h-4 w-4 mr-2" />
          Create Policy
        </Button>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search policies..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9"
            data-testid="input-search"
          />
        </div>
        <Select value={tenantFilter} onValueChange={setTenantFilter}>
          <SelectTrigger className="w-[180px]" data-testid="select-tenant">
            <Globe className="h-4 w-4 mr-2" />
            <SelectValue placeholder="All Sites" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Sites</SelectItem>
            {tenants?.map((tenant) => (
              <SelectItem key={tenant.id} value={tenant.id}>
                {tenant.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Policies Grid */}
      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-64 w-full" />
          ))}
        </div>
      ) : filteredPolicies && filteredPolicies.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3" data-testid="grid-policies">
          {filteredPolicies.map((policy) => (
            <Card key={policy.id} className="overflow-visible" data-testid={`policy-card-${policy.id}`}>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <CardTitle className="text-base flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      {policy.name}
                    </CardTitle>
                    <div className="flex items-center gap-2 mt-2">
                      <Badge variant="outline">
                        {getTenantName(policy.tenantId)}
                      </Badge>
                      {policy.isDefault && (
                        <Badge variant="secondary">Default</Badge>
                      )}
                    </div>
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" data-testid={`button-policy-menu-${policy.id}`}>
                        <MoreVertical className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem onClick={() => handleEditClick(policy)}>
                        Edit Policy
                      </DropdownMenuItem>
                      {!policy.isDefault && (
                        <DropdownMenuItem onClick={() => setDefaultPolicyMutation.mutate(policy.id)}>
                          Set as Default
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem onClick={() => handleDuplicateClick(policy)}>
                        Duplicate
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => handleDeleteClick(policy)} className="text-destructive focus:text-destructive">
                        Delete Policy
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Enforcement</span>
                  <EnforcementBadge mode={policy.enforcementMode} />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Block Threshold</span>
                    <span className="font-medium">{policy.blockThreshold}</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-destructive rounded-full"
                      style={{ width: `${policy.blockThreshold}%` }}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Challenge Threshold</span>
                    <span className="font-medium">{policy.challengeThreshold}</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-yellow-500 rounded-full"
                      style={{ width: `${policy.challengeThreshold}%` }}
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Rate Limit</span>
                  <span className="font-medium">
                    {policy.rateLimit} req/{policy.rateLimitWindow}s
                  </span>
                </div>

                <Button
                  variant="outline"
                  className="w-full"
                  onClick={() => handleEditClick(policy)}
                  data-testid={`button-edit-policy-${policy.id}`}
                >
                  Configure Policy
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-16 text-center" data-testid="empty-policies">
            <FileText className="h-16 w-16 text-muted-foreground/50 mb-4" />
            <h3 className="text-xl font-semibold mb-2">No policies found</h3>
            <p className="text-muted-foreground max-w-md mb-6">
              Create your first policy to configure enforcement settings for your sites.
            </p>
            <Button onClick={() => setAddDialogOpen(true)} data-testid="button-create-first-policy">
              <Plus className="h-4 w-4 mr-2" />
              Create Policy
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Add Policy Dialog */}
      <Dialog open={addDialogOpen} onOpenChange={(open) => {
        setAddDialogOpen(open);
        if (!open) setDuplicateData(null);
      }}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Plus className="h-5 w-5" />
              {duplicateData ? "Duplicate Policy" : "Create New Policy"}
            </DialogTitle>
            <DialogDescription>
              {duplicateData ? "Create a copy of this policy with custom settings" : "Set up a new security policy with custom thresholds and enforcement rules"}
            </DialogDescription>
          </DialogHeader>
          <PolicyAddForm
            tenants={tenants || []}
            initialData={duplicateData}
            onSave={(data) => {
              if (duplicateData) {
                duplicatePolicyMutation.mutate(data);
              } else {
                createPolicyMutation.mutate(data);
              }
            }}
            isPending={createPolicyMutation.isPending || duplicatePolicyMutation.isPending}
            onClose={() => {
              setAddDialogOpen(false);
              setDuplicateData(null);
            }}
          />
        </DialogContent>
      </Dialog>

      {/* Edit Policy Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Edit Policy</DialogTitle>
            <DialogDescription>
              Configure enforcement settings for {selectedPolicy?.name}
            </DialogDescription>
          </DialogHeader>
          {selectedPolicy && (
            <PolicyEditForm
              policy={selectedPolicy}
              onSave={(data) =>
                updatePolicyMutation.mutate({ id: selectedPolicy.id, data })
              }
              isPending={updatePolicyMutation.isPending}
              onClose={() => setEditDialogOpen(false)}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface PolicyAddFormProps {
  tenants: Tenant[];
  initialData?: Policy | null;
  onSave: (data: any) => void;
  isPending: boolean;
  onClose: () => void;
}

function PolicyAddForm({ tenants, initialData, onSave, isPending, onClose }: PolicyAddFormProps) {
  const [activeTab, setActiveTab] = useState("general");
  const [formData, setFormData] = useState({
    tenantId: initialData?.tenantId || tenants[0]?.id || "",
    name: initialData ? `${initialData.name} (Copy)` : "",
    enforcementMode: (initialData?.enforcementMode || "monitor") as "monitor" | "block",
    blockThreshold: initialData?.blockThreshold || 70,
    challengeThreshold: initialData?.challengeThreshold || 50,
    rateLimit: initialData?.rateLimit || 100,
    rateLimitWindow: initialData?.rateLimitWindow || 60,
    allowedCountries: initialData?.allowedCountries || [],
    blockedCountries: initialData?.blockedCountries || [],
    geoRateLimitByCountry: initialData?.geoRateLimitByCountry || {},
    vpnDetectionEnabled: initialData?.vpnDetectionEnabled || false,
    vpnBlockAction: (initialData?.vpnBlockAction || "monitor") as "block" | "challenge" | "monitor",
    credentialStuffingThreshold: initialData?.credentialStuffingThreshold || 60,
    failedLoginAttempts: initialData?.failedLoginAttempts || 5,
    lockoutDurationMinutes: initialData?.lockoutDurationMinutes || 15,
    botDetectionThreshold: initialData?.botDetectionThreshold || 75,
    anomalySensitivity: initialData?.anomalySensitivity || "medium",
    highRiskThreshold: initialData?.highRiskThreshold || 70,
    criticalRiskThreshold: initialData?.criticalRiskThreshold || 85,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.tenantId || !formData.name.trim()) {
      return;
    }
    onSave(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium">Site</label>
          <Select value={formData.tenantId} onValueChange={(value) => setFormData({ ...formData, tenantId: value })}>
            <SelectTrigger data-testid="select-tenant-add">
              <Globe className="h-4 w-4 mr-2" />
              <SelectValue placeholder="Select a site" />
            </SelectTrigger>
            <SelectContent>
              {tenants.map((tenant) => (
                <SelectItem key={tenant.id} value={tenant.id}>
                  {tenant.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium">Policy Name</label>
          <Input
            placeholder="e.g., Strict Security, Balanced Protection"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            data-testid="input-policy-name"
          />
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="behavior">Behavioral</TabsTrigger>
          <TabsTrigger value="geo">Geo-Location</TabsTrigger>
        </TabsList>

        <TabsContent value="general" className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium">Enforcement Mode</label>
          <div className="flex items-center gap-4 p-4 rounded-lg border bg-card hover:bg-accent/50 transition-colors">
            <div className="flex-1">
              <p className="font-medium text-sm">
                {formData.enforcementMode === "block" ? "🛑 Blocking" : "👁️ Monitoring"}
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                {formData.enforcementMode === "block"
                  ? "Actively blocks malicious requests"
                  : "Logs threats without blocking"}
              </p>
            </div>
            <Switch
              checked={formData.enforcementMode === "block"}
              onCheckedChange={(checked) =>
                setFormData({
                  ...formData,
                  enforcementMode: checked ? "block" : "monitor",
                })
              }
              data-testid="switch-enforcement-add"
            />
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium">Block Threshold</label>
            <span className="text-xs bg-destructive/10 text-destructive px-2 py-1 rounded">{formData.blockThreshold}</span>
          </div>
          <Slider
            value={[formData.blockThreshold]}
            onValueChange={([value]) =>
              setFormData({ ...formData, blockThreshold: value })
            }
            min={0}
            max={100}
            step={1}
            data-testid="slider-block-add"
          />
          <p className="text-xs text-muted-foreground">Requests scoring above this are blocked</p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium">Challenge Threshold</label>
            <span className="text-xs bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 px-2 py-1 rounded">{formData.challengeThreshold}</span>
          </div>
          <Slider
            value={[formData.challengeThreshold]}
            onValueChange={([value]) =>
              setFormData({ ...formData, challengeThreshold: value })
            }
            min={0}
            max={100}
            step={1}
            data-testid="slider-challenge-add"
          />
          <p className="text-xs text-muted-foreground">Requests scoring above this require verification</p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Rate Limit</label>
            <Input
              type="number"
              value={formData.rateLimit}
              onChange={(e) =>
                setFormData({ ...formData, rateLimit: parseInt(e.target.value) || 0 })
              }
              min={1}
              data-testid="input-rate-limit-add"
            />
            <p className="text-xs text-muted-foreground">requests</p>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">Per Window</label>
            <Input
              type="number"
              value={formData.rateLimitWindow}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  rateLimitWindow: parseInt(e.target.value) || 0,
                })
              }
              min={1}
              data-testid="input-rate-window-add"
            />
            <p className="text-xs text-muted-foreground">seconds</p>
          </div>
        </div>
        </TabsContent>

        <TabsContent value="behavior">
          <BehavioralPolicyConfig policy={formData} onChange={setFormData} />
        </TabsContent>

        <TabsContent value="geo">
          <EnhancedGeoPolicyForm policy={formData} onChange={setFormData} />
        </TabsContent>
      </Tabs>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" disabled={isPending || !formData.tenantId || !formData.name.trim()} data-testid="button-create-policy">
          {isPending ? "Creating..." : "Create Policy"}
        </Button>
      </DialogFooter>
    </form>
  );
}

interface PolicyEditFormProps {
  policy: Policy;
  onSave: (data: Partial<Policy>) => void;
  isPending: boolean;
  onClose: () => void;
}

function PolicyEditForm({ policy, onSave, isPending, onClose }: PolicyEditFormProps) {
  const [activeTab, setActiveTab] = useState("general");
  const [formData, setFormData] = useState({
    enforcementMode: policy.enforcementMode,
    blockThreshold: policy.blockThreshold || 70,
    challengeThreshold: policy.challengeThreshold || 50,
    rateLimit: policy.rateLimit || 100,
    rateLimitWindow: policy.rateLimitWindow || 60,
    allowedCountries: policy.allowedCountries,
    blockedCountries: policy.blockedCountries,
    geoRateLimitByCountry: policy.geoRateLimitByCountry,
    vpnDetectionEnabled: policy.vpnDetectionEnabled,
    vpnBlockAction: policy.vpnBlockAction,
    credentialStuffingThreshold: policy.credentialStuffingThreshold || 60,
    failedLoginAttempts: policy.failedLoginAttempts || 5,
    lockoutDurationMinutes: policy.lockoutDurationMinutes || 15,
    botDetectionThreshold: policy.botDetectionThreshold || 75,
    anomalySensitivity: policy.anomalySensitivity || "medium",
    highRiskThreshold: policy.highRiskThreshold || 70,
    criticalRiskThreshold: policy.criticalRiskThreshold || 85,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="behavior">Behavioral</TabsTrigger>
          <TabsTrigger value="geo">Geo-Location</TabsTrigger>
        </TabsList>
        <TabsContent value="general" className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Enforcement Mode</label>
            <div className="flex items-center gap-4 p-4 rounded-lg border">
              <div className="flex-1">
                <p className="font-medium">{formData.enforcementMode === "block" ? "Blocking" : "Monitoring"}</p>
                <p className="text-sm text-muted-foreground">{formData.enforcementMode === "block" ? "Actively blocking malicious requests" : "Logging threats without blocking"}</p>
              </div>
              <Switch checked={formData.enforcementMode === "block"} onCheckedChange={(checked) => setFormData({ ...formData, enforcementMode: checked ? "block" : "monitor" })} data-testid="switch-enforcement-mode" />
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Block Threshold</label>
              <span className="text-sm text-muted-foreground">{formData.blockThreshold}</span>
            </div>
            <Slider value={[formData.blockThreshold]} onValueChange={([value]) => setFormData({ ...formData, blockThreshold: value })} min={0} max={100} step={1} data-testid="slider-block-threshold" />
            <p className="text-xs text-muted-foreground">Requests with scores above this will be blocked</p>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-sm font-medium">Challenge Threshold</label>
              <span className="text-sm text-muted-foreground">{formData.challengeThreshold}</span>
            </div>
            <Slider value={[formData.challengeThreshold]} onValueChange={([value]) => setFormData({ ...formData, challengeThreshold: value })} min={0} max={100} step={1} data-testid="slider-challenge-threshold" />
            <p className="text-xs text-muted-foreground">Requests with scores above this may require verification</p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Rate Limit</label>
              <Input type="number" value={formData.rateLimit} onChange={(e) => setFormData({ ...formData, rateLimit: parseInt(e.target.value) })} min={1} data-testid="input-rate-limit" />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Window (seconds)</label>
              <Input type="number" value={formData.rateLimitWindow} onChange={(e) => setFormData({ ...formData, rateLimitWindow: parseInt(e.target.value) })} min={1} data-testid="input-rate-window" />
            </div>
          </div>
        </TabsContent>
        <TabsContent value="behavior">
          <BehavioralPolicyConfig policy={formData} onChange={setFormData} />
        </TabsContent>
        <TabsContent value="geo">
          <EnhancedGeoPolicyForm policy={formData} onChange={setFormData} />
        </TabsContent>
      </Tabs>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
        <Button type="submit" disabled={isPending} data-testid="button-save-policy">{isPending ? "Saving..." : "Save Changes"}</Button>
      </DialogFooter>
    </form>
  );
}

