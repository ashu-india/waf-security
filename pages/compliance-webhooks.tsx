import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Checkbox } from "@/components/ui/checkbox";
import { AlertCircle, CheckCircle, Plus, Trash2, TestTube, Copy } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface Webhook {
  id: string;
  tenantId: string;
  url: string;
  events: string[];
  isActive: boolean;
  retries: number;
  createdAt: string;
}

export default function ComplianceWebhooks() {
  const [selectedTenant] = useState("tenant-1");
  const [newWebhookUrl, setNewWebhookUrl] = useState("");
  const [selectedEvents, setSelectedEvents] = useState<string[]>(["compliance_alert"]);
  const queryClient = useQueryClient();

  const { data: webhooks, isLoading } = useQuery<Webhook[]>({
    queryKey: [`/api/compliance-webhooks/tenant/${selectedTenant}`],
    staleTime: 30000,
  });

  const registerMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/compliance-webhooks/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          tenantId: selectedTenant,
          url: newWebhookUrl,
          events: selectedEvents,
          isActive: true,
          retries: 3,
        }),
      });
      if (!res.ok) throw new Error("Failed to register webhook");
      return res.json();
    },
    onSuccess: () => {
      setNewWebhookUrl("");
      setSelectedEvents(["compliance_alert"]);
      queryClient.invalidateQueries({ queryKey: [`/api/compliance-webhooks/tenant/${selectedTenant}`] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (webhookId: string) => {
      const res = await fetch(`/api/compliance-webhooks/${webhookId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete webhook");
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`/api/compliance-webhooks/tenant/${selectedTenant}`] });
    },
  });

  const testMutation = useMutation({
    mutationFn: async (webhookId: string) => {
      const res = await fetch(`/api/compliance-webhooks/${webhookId}/test`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ tenantId: selectedTenant }),
      });
      if (!res.ok) throw new Error("Failed to test webhook");
      return res.json();
    },
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Webhook Integrations</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Send compliance events to external systems
          </p>
        </div>
      </div>

      {/* Register Webhook Card */}
      <Card>
        <CardHeader>
          <CardTitle>Register New Webhook</CardTitle>
          <CardDescription>Receive real-time compliance events</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-sm font-medium">Webhook URL</label>
            <Input
              placeholder="https://example.com/webhooks/compliance"
              value={newWebhookUrl}
              onChange={(e) => setNewWebhookUrl(e.target.value)}
              className="mt-2"
            />
          </div>

          <div>
            <label className="text-sm font-medium mb-3 block">Events to Subscribe</label>
            <div className="space-y-2">
              {["compliance_alert", "remediation_action", "audit_log"].map((event) => (
                <div key={event} className="flex items-center space-x-2">
                  <Checkbox
                    id={event}
                    checked={selectedEvents.includes(event)}
                    onCheckedChange={(checked) => {
                      if (checked) {
                        setSelectedEvents([...selectedEvents, event]);
                      } else {
                        setSelectedEvents(selectedEvents.filter((e) => e !== event));
                      }
                    }}
                  />
                  <label htmlFor={event} className="text-sm cursor-pointer">
                    {event.replace(/_/g, " ").toUpperCase()}
                  </label>
                </div>
              ))}
            </div>
          </div>

          <Button
            onClick={() => registerMutation.mutate()}
            disabled={!newWebhookUrl || registerMutation.isPending}
            className="w-full"
          >
            <Plus className="h-4 w-4 mr-2" />
            Register Webhook
          </Button>
        </CardContent>
      </Card>

      {/* Webhooks List */}
      {isLoading ? (
        <>
          <Skeleton className="h-12" />
          <Skeleton className="h-64" />
        </>
      ) : webhooks && webhooks.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Registered Webhooks</CardTitle>
            <CardDescription>{webhooks.length} webhook(s) configured</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Status</TableHead>
                    <TableHead>URL</TableHead>
                    <TableHead>Events</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {webhooks.map((webhook) => (
                    <TableRow key={webhook.id}>
                      <TableCell>
                        <Badge variant={webhook.isActive ? "default" : "outline"}>
                          {webhook.isActive ? "Active" : "Inactive"}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <div className="truncate text-sm font-mono">{webhook.url}</div>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1 flex-wrap">
                          {webhook.events.map((event) => (
                            <Badge key={event} variant="outline" className="text-xs">
                              {event.split("_")[0]}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="text-right space-x-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => testMutation.mutate(webhook.id)}
                          disabled={testMutation.isPending}
                        >
                          <TestTube className="h-3 w-3" />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => deleteMutation.mutate(webhook.id)}
                          disabled={deleteMutation.isPending}
                        >
                          <Trash2 className="h-3 w-3" />
                        </Button>
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
            <p className="text-muted-foreground">No webhooks registered</p>
          </CardContent>
        </Card>
      )}

      {/* Webhook Payload Info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Copy className="h-5 w-5" />
            Webhook Payload Format
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-slate-900 text-slate-50 p-4 rounded-lg font-mono text-xs overflow-x-auto">
            <pre>{`{
  "event": "compliance_alert",
  "tenantId": "tenant-1",
  "timestamp": "2025-12-02T07:41:00Z",
  "data": {
    "type": "alert",
    "framework": "GDPR",
    "severity": "high",
    "message": "Compliance score below threshold",
    "score": 65
  },
  "signature": "sha256_hash"
}`}</pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
