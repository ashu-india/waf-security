import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Plus,
  Shield,
  Search,
  Filter,
  MoreVertical,
  Upload,
  Download,
  Power,
  PowerOff,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
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
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge } from "@/components/ui/status-badge";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { ChevronLeft, ChevronRight } from "lucide-react";

type WafRule = any;
type Tenant = any;

export default function Rules() {
  const { toast } = useToast();
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [ruleTypeFilter, setRuleTypeFilter] = useState("all");
  const [tenantFilter, setTenantFilter] = useState("all");
  const [selectedRuleIds, setSelectedRuleIds] = useState<Set<string>>(new Set());
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<WafRule | null>(null);
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [viewPatternRule, setViewPatternRule] = useState<WafRule | null>(null);
  const [viewPatternOpen, setViewPatternOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage] = useState(10);

  const { data: rules, isLoading } = useQuery<WafRule[]>({
    queryKey: ["/api/rules"],
    staleTime: 30000, // 30 seconds
    refetchInterval: 60000, // Refetch every minute
  });

  const { data: tenants } = useQuery<Tenant[]>({
    queryKey: ["/api/tenants"],
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  const toggleRuleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      await apiRequest("PATCH", `/api/rules/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rules"] });
      toast({
        title: "Rule updated",
        description: "The rule has been toggled successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update rule. Please try again.",
        variant: "destructive",
      });
    },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/rules/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rules"] });
      toast({
        title: "Rule deleted",
        description: "The rule has been removed.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete rule. Please try again.",
        variant: "destructive",
      });
    },
  });

  const editRuleMutation = useMutation({
    mutationFn: async (data: { id: string; name: string; description: string; pattern: string; targetField: string; score: number; severity: string }) => {
      await apiRequest("PATCH", `/api/rules/${data.id}`, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rules"] });
      setEditDialogOpen(false);
      setEditingRule(null);
      toast({
        title: "Rule updated",
        description: "The rule has been updated successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update rule. Please try again.",
        variant: "destructive",
      });
    },
  });

  const batchToggleMutation = useMutation({
    mutationFn: async ({ ids, enabled }: { ids: string[]; enabled: boolean }) => {
      await Promise.all(ids.map(id => apiRequest("PATCH", `/api/rules/${id}`, { enabled })));
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rules"] });
      setSelectedRuleIds(new Set());
      toast({
        title: "Rules updated",
        description: "Rules have been toggled successfully.",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update rules. Please try again.",
        variant: "destructive",
      });
    },
  });

  const dynamicCategories = [
    { value: "all", label: "All Categories" },
    ...(rules
      ? Array.from(new Set(rules.map((r) => r.category)))
          .sort()
          .map((cat: string) => ({
            value: cat,
            label: cat.replace("-", " ").replace(/\b\w/g, (l: string) => l.toUpperCase()),
          }))
      : []),
  ];

  const filteredRules = rules?.filter((rule) => {
    const matchesSearch =
      rule.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.description?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory =
      categoryFilter === "all" || rule.category === categoryFilter;
    const matchesRuleType = 
      ruleTypeFilter === "all" ||
      (ruleTypeFilter === "builtin" && rule.isBuiltIn) ||
      (ruleTypeFilter === "custom" && !rule.isBuiltIn);
    const matchesTenant =
      tenantFilter === "all" ||
      (tenantFilter === "global" && rule.tenantId === null) ||
      rule.tenantId === tenantFilter;
    return matchesSearch && matchesCategory && matchesRuleType && matchesTenant;
  });

  const totalPages = Math.ceil((filteredRules?.length || 0) / itemsPerPage);
  const paginatedRules = filteredRules?.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const getTenantName = (tenantId: string | null) => {
    if (!tenantId) return "Global";
    const tenant = tenants?.find((t) => t.id === tenantId);
    return tenant?.name || "Unknown";
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold" data-testid="text-page-title">
            WAF Rules
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Manage security rules and detection patterns
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="outline" data-testid="button-import">
            <Upload className="h-4 w-4 mr-2" />
            Import
          </Button>
          <Button variant="outline" data-testid="button-export">
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button data-testid="button-add-rule">
                <Plus className="h-4 w-4 mr-2" />
                Add Rule
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Create New Rule</DialogTitle>
                <DialogDescription>
                  Define a custom WAF rule to detect malicious patterns.
                </DialogDescription>
              </DialogHeader>
              <CreateRuleForm onClose={() => setCreateDialogOpen(false)} />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Filters & Batch Actions */}
      <div className="space-y-3">
        <div className="flex flex-col lg:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search rules by name or description..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9"
              data-testid="input-search"
            />
          </div>
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger className="w-[180px]" data-testid="select-category">
              <SelectValue placeholder="Category" />
            </SelectTrigger>
            <SelectContent>
              {dynamicCategories.map((cat) => (
                <SelectItem key={cat.value} value={cat.value}>
                  {cat.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={ruleTypeFilter} onValueChange={setRuleTypeFilter}>
            <SelectTrigger className="w-[140px]">
              <SelectValue placeholder="Rule Type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              <SelectItem value="builtin">Built-in</SelectItem>
              <SelectItem value="custom">Custom</SelectItem>
            </SelectContent>
          </Select>
          <Select value={tenantFilter} onValueChange={setTenantFilter}>
            <SelectTrigger className="w-[150px]" data-testid="select-tenant">
              <SelectValue placeholder="All Sites" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Sites</SelectItem>
              <SelectItem value="global">Global Only</SelectItem>
              {tenants?.map((tenant) => (
                <SelectItem key={tenant.id} value={tenant.id}>
                  {tenant.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {selectedRuleIds.size > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between bg-blue-50 p-3 rounded-lg border border-blue-200">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-blue-900">
                  {selectedRuleIds.size === filteredRules?.length 
                    ? `All ${selectedRuleIds.size} rules selected` 
                    : `${selectedRuleIds.size} of ${filteredRules?.length} rules selected`}
                </span>
                {selectedRuleIds.size < (filteredRules?.length || 0) && (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-xs text-blue-600 hover:text-blue-700 h-auto p-1"
                    onClick={() => setSelectedRuleIds(new Set(filteredRules?.map((r) => r.id) || []))}
                  >
                    Select all {filteredRules?.length}
                  </Button>
                )}
              </div>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => batchToggleMutation.mutate({ ids: Array.from(selectedRuleIds), enabled: true })}
                  disabled={batchToggleMutation.isPending}
                >
                  <Power className="h-3 w-3 mr-1" />
                  Enable All
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => batchToggleMutation.mutate({ ids: Array.from(selectedRuleIds), enabled: false })}
                  disabled={batchToggleMutation.isPending}
                >
                  <PowerOff className="h-3 w-3 mr-1" />
                  Disable All
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setSelectedRuleIds(new Set())}
                >
                  Clear
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Total Rules</span>
              <Badge variant="outline">{rules?.length || 0}</Badge>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Enabled</span>
              <Badge className="bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20">
                {rules?.filter((r) => r.enabled).length || 0}
              </Badge>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Built-in</span>
              <Badge variant="outline">
                {rules?.filter((r) => r.isBuiltIn).length || 0}
              </Badge>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Custom</span>
              <Badge variant="outline">
                {rules?.filter((r) => !r.isBuiltIn).length || 0}
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Rules Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[50px]">
                    <input
                      type="checkbox"
                      checked={selectedRuleIds.size === paginatedRules?.length && paginatedRules.length > 0}
                      onChange={(e) => {
                        if (e.target.checked && paginatedRules) {
                          setSelectedRuleIds(new Set(paginatedRules.map(r => r.id)));
                        } else {
                          setSelectedRuleIds(new Set());
                        }
                      }}
                      className="rounded"
                    />
                  </TableHead>
                  <TableHead className="w-[60px]">Status</TableHead>
                  <TableHead className="w-[280px]">Rule Name</TableHead>
                  <TableHead className="w-[100px]">Category</TableHead>
                  <TableHead className="w-[80px] text-right">Severity</TableHead>
                  <TableHead className="w-[70px] text-right">Score</TableHead>
                  <TableHead className="w-[70px] text-right">Hits</TableHead>
                  <TableHead className="w-[80px]">Scope</TableHead>
                  <TableHead className="w-[60px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody data-testid="table-rules">
                {isLoading ? (
                  Array(5)
                    .fill(0)
                    .map((_, i) => (
                      <TableRow key={i}>
                        {Array(9)
                          .fill(0)
                          .map((_, j) => (
                            <TableCell key={j}>
                              <Skeleton className="h-4 w-full" />
                            </TableCell>
                          ))}
                      </TableRow>
                    ))
                ) : paginatedRules && paginatedRules.length > 0 ? (
                  paginatedRules.map((rule) => (
                    <TableRow key={rule.id} data-testid={`rule-row-${rule.id}`} className={selectedRuleIds.has(rule.id) ? "bg-blue-50" : ""}>
                      <TableCell>
                        <input
                          type="checkbox"
                          checked={selectedRuleIds.has(rule.id)}
                          onChange={(e) => {
                            const newSet = new Set(selectedRuleIds);
                            if (e.target.checked) {
                              newSet.add(rule.id);
                            } else {
                              newSet.delete(rule.id);
                            }
                            setSelectedRuleIds(newSet);
                          }}
                          className="rounded"
                        />
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={rule.enabled ?? false}
                          onCheckedChange={(checked) =>
                            toggleRuleMutation.mutate({ id: rule.id, enabled: checked })
                          }
                          disabled={toggleRuleMutation.isPending}
                          data-testid={`switch-rule-${rule.id}`}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="w-[280px]">
                          <div className="flex items-center gap-2">
                            <span className="font-medium truncate">{rule.name}</span>
                            {rule.isBuiltIn && (
                              <Badge variant="default" className="text-xs whitespace-nowrap flex-shrink-0">
                                Built-in
                              </Badge>
                            )}
                          </div>
                          {rule.description && (
                            <p className="text-xs text-muted-foreground mt-1 truncate">
                              {rule.description}
                            </p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize whitespace-nowrap">
                          {rule.category.replace("-", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={rule.severity || "medium"} />
                      </TableCell>
                      <TableCell className="font-mono text-sm text-right">
                        +{rule.score}
                      </TableCell>
                      <TableCell className="font-mono text-sm text-right">
                        {rule.hitCount?.toLocaleString() || 0}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="whitespace-nowrap">
                          {getTenantName(rule.tenantId)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              data-testid={`button-rule-menu-${rule.id}`}
                            >
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onClick={() => {
                                setEditingRule(rule);
                                setEditDialogOpen(true);
                              }}
                              disabled={rule.isBuiltIn ?? false}
                            >
                              Edit Rule
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => {
                                setViewPatternRule(rule);
                                setViewPatternOpen(true);
                              }}
                            >
                              View Pattern
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive focus:text-destructive"
                              onClick={() => deleteRuleMutation.mutate(rule.id)}
                              disabled={rule.isBuiltIn ?? false}
                            >
                              Delete Rule
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={9} className="h-48 text-center">
                      <div className="flex flex-col items-center justify-center text-muted-foreground">
                        <Shield className="h-12 w-12 mb-4 opacity-50" />
                        <p className="text-lg font-medium">No rules found</p>
                        <p className="text-sm mt-1">
                          Create a custom rule or adjust your filters
                        </p>
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
          {filteredRules && filteredRules.length > 0 && (
            <div className="flex items-center justify-between px-4 py-3 border-t">
              <span className="text-sm text-muted-foreground">
                Showing {(currentPage - 1) * itemsPerPage + 1} to{" "}
                {Math.min(currentPage * itemsPerPage, filteredRules.length)} of{" "}
                {filteredRules.length}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <div className="flex items-center gap-1 px-2">
                  {Array.from({ length: totalPages }, (_, i) => i + 1)
                    .filter((p) => Math.abs(p - currentPage) <= 1 || p === 1 || p === totalPages)
                    .map((page, i, arr) => [
                      i > 0 && arr[i - 1] !== page - 1 ? (
                        <span key={`dots-${i}`} className="px-1 text-muted-foreground">
                          ...
                        </span>
                      ) : null,
                      <Button
                        key={page}
                        variant={currentPage === page ? "default" : "outline"}
                        size="sm"
                        className="w-8 h-8 p-0"
                        onClick={() => setCurrentPage(page)}
                      >
                        {page}
                      </Button>,
                    ])}
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Edit Rule Dialog */}
      <Dialog open={editDialogOpen} onOpenChange={setEditDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Edit Rule</DialogTitle>
            <DialogDescription>
              Update the rule details and pattern matching
            </DialogDescription>
          </DialogHeader>
          {editingRule && (
            <EditRuleForm
              rule={editingRule}
              onClose={() => setEditDialogOpen(false)}
              onSubmit={(data) => editRuleMutation.mutate(data)}
              isPending={editRuleMutation.isPending}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* View Pattern Dialog */}
      <Dialog open={viewPatternOpen} onOpenChange={setViewPatternOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>View Pattern</DialogTitle>
            <DialogDescription>
              Pattern details for {viewPatternRule?.name}
            </DialogDescription>
          </DialogHeader>
          {viewPatternRule && (
            <div className="space-y-4">
              <div>
                <Label className="font-semibold">Pattern Type</Label>
                <p className="text-sm text-muted-foreground mt-1">
                  {viewPatternRule.patternType || "regex"}
                </p>
              </div>
              <div>
                <Label className="font-semibold">Target Field</Label>
                <p className="text-sm text-muted-foreground mt-1 capitalize">
                  {viewPatternRule.targetField}
                </p>
              </div>
              <div>
                <Label className="font-semibold">Pattern</Label>
                <div className="mt-2 p-3 bg-muted rounded-md font-mono text-sm overflow-auto max-h-48 break-all">
                  {viewPatternRule.pattern}
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <Label className="font-semibold text-xs text-muted-foreground">Score</Label>
                  <p className="text-lg font-semibold">{viewPatternRule.score}</p>
                </div>
                <div>
                  <Label className="font-semibold text-xs text-muted-foreground">Hits</Label>
                  <p className="text-lg font-semibold">{viewPatternRule.hitCount?.toLocaleString() || 0}</p>
                </div>
                <div>
                  <Label className="font-semibold text-xs text-muted-foreground">Status</Label>
                  <p className="text-lg font-semibold">{viewPatternRule.enabled ? "Enabled" : "Disabled"}</p>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setViewPatternOpen(false)}>
                  Close
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function CreateRuleForm({ onClose }: { onClose: () => void }) {
  const { toast } = useToast();
  const { data: tenants } = useQuery<Tenant[]>({
    queryKey: ["/api/tenants"],
    staleTime: 5 * 60 * 1000,
  });
  
  const { data: rules } = useQuery<WafRule[]>({
    queryKey: ["/api/rules"],
    staleTime: 30000,
  });
  
  const formCategories = [
    { value: "custom", label: "Custom" },
    ...(rules
      ? Array.from(new Set(rules.map((r) => r.category)))
          .sort()
          .map((cat: string) => ({
            value: cat,
            label: cat.replace("-", " ").replace(/\b\w/g, (l: string) => l.toUpperCase()),
          }))
          .filter((cat) => cat.value !== "custom")
      : []),
  ];

  const [formData, setFormData] = useState({
    name: "",
    description: "",
    category: "custom",
    severity: "medium",
    pattern: "",
    targetField: "path",
    score: 10,
    tenantId: undefined as string | undefined,
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof formData) => {
      await apiRequest("POST", "/api/rules", { ...data, tenantId: data.tenantId || null });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/rules"] });
      toast({
        title: "Rule created",
        description: "The new rule has been added.",
      });
      onClose();
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to create rule. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="name">Rule Name</Label>
          <Input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            placeholder="My Custom Rule"
            required
            data-testid="input-rule-name"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="category">Category</Label>
          <Select
            value={formData.category}
            onValueChange={(v) => setFormData({ ...formData, category: v })}
          >
            <SelectTrigger id="category" data-testid="select-rule-category">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {formCategories.map((cat: any) => (
                <SelectItem key={cat.value} value={cat.value}>
                  {cat.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="description">Description</Label>
        <Input
          id="description"
          value={formData.description}
          onChange={(e) =>
            setFormData({ ...formData, description: e.target.value })
          }
          placeholder="What this rule detects..."
          data-testid="input-rule-description"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="pattern">Pattern (Regex)</Label>
        <Textarea
          id="pattern"
          value={formData.pattern}
          onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
          placeholder="(?i)(union|select|insert|update|delete|drop)"
          className="font-mono text-sm"
          rows={3}
          required
          data-testid="input-rule-pattern"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="tenant">Tenant (Optional - Global if not selected)</Label>
        <Select
          value={formData.tenantId || "global"}
          onValueChange={(v) => setFormData({ ...formData, tenantId: v === "global" ? undefined : v })}
        >
          <SelectTrigger id="tenant">
            <SelectValue placeholder="Select tenant..." />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="global">Global Rule</SelectItem>
            {tenants?.map((tenant) => (
              <SelectItem key={tenant.id} value={tenant.id}>
                {tenant.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="space-y-2">
          <Label htmlFor="targetField">Target Field</Label>
          <Select
            value={formData.targetField}
            onValueChange={(v) => setFormData({ ...formData, targetField: v })}
          >
            <SelectTrigger id="targetField" data-testid="select-rule-target">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="path">URL Path</SelectItem>
              <SelectItem value="query">Query String</SelectItem>
              <SelectItem value="body">Request Body</SelectItem>
              <SelectItem value="headers">Headers</SelectItem>
              <SelectItem value="user-agent">User Agent</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="severity">Severity</Label>
          <Select
            value={formData.severity}
            onValueChange={(v) => setFormData({ ...formData, severity: v })}
          >
            <SelectTrigger id="severity" data-testid="select-rule-severity">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="score">Score (+)</Label>
          <Input
            id="score"
            type="number"
            min={1}
            max={100}
            value={formData.score}
            onChange={(e) =>
              setFormData({ ...formData, score: parseInt(e.target.value) })
            }
            data-testid="input-rule-score"
          />
        </div>
      </div>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" disabled={createMutation.isPending} data-testid="button-create-rule">
          {createMutation.isPending ? "Creating..." : "Create Rule"}
        </Button>
      </DialogFooter>
    </form>
  );
}

function EditRuleForm({
  rule,
  onClose,
  onSubmit,
  isPending,
}: {
  rule: WafRule;
  onClose: () => void;
  onSubmit: (data: any) => void;
  isPending: boolean;
}) {
  const [formData, setFormData] = useState({
    id: rule.id,
    name: rule.name,
    description: rule.description || "",
    pattern: rule.pattern || "",
    targetField: rule.targetField || "path",
    score: rule.score || 10,
    severity: rule.severity || "medium",
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="name">Rule Name</Label>
        <Input
          id="name"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          required
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="description">Description</Label>
        <Input
          id="description"
          value={formData.description}
          onChange={(e) =>
            setFormData({ ...formData, description: e.target.value })
          }
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="pattern">Pattern (Regex)</Label>
        <Textarea
          id="pattern"
          value={formData.pattern}
          onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
          className="font-mono text-sm"
          rows={3}
          required
        />
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="space-y-2">
          <Label htmlFor="targetField">Target Field</Label>
          <Select
            value={formData.targetField}
            onValueChange={(v) => setFormData({ ...formData, targetField: v })}
          >
            <SelectTrigger id="targetField">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="path">URL Path</SelectItem>
              <SelectItem value="query">Query String</SelectItem>
              <SelectItem value="body">Request Body</SelectItem>
              <SelectItem value="headers">Headers</SelectItem>
              <SelectItem value="user-agent">User Agent</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="severity">Severity</Label>
          <Select
            value={formData.severity}
            onValueChange={(v) => setFormData({ ...formData, severity: v })}
          >
            <SelectTrigger id="severity">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="score">Score (+)</Label>
          <Input
            id="score"
            type="number"
            min={1}
            max={100}
            value={formData.score}
            onChange={(e) =>
              setFormData({ ...formData, score: parseInt(e.target.value) })
            }
          />
        </div>
      </div>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" disabled={isPending}>
          {isPending ? "Saving..." : "Save Changes"}
        </Button>
      </DialogFooter>
    </form>
  );
}
