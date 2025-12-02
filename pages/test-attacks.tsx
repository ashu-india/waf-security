import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertTriangle, Zap, CheckCircle2, XCircle, Clock, Send } from "lucide-react";
import type { Tenant } from "@shared/schema";

interface AttackResult {
  attackType: string;
  payload: string;
  statusCode: number;
  message: string;
  timestamp: string;
  action: "allow" | "block" | "challenge";
  score: number;
}

const ATTACK_VECTORS = [
  {
    category: "Browser URL Attacks",
    attacks: [
      { name: "URL SQLi", payload: "search=admin' OR '1'='1" },
      { name: "URL XSS", payload: "name=<script>alert('xss')</script>" },
      { name: "URL Path Traversal", payload: "file=../../../../etc/passwd" },
      { name: "URL Encoded XSS", payload: "q=%3Cscript%3Ealert(1)%3C/script%3E" },
      { name: "URL LFI", payload: "file=/var/www/../../etc/passwd" },
      { name: "URL Command Injection", payload: "cmd=ls%20-la%20|%20cat" },
    ],
  },
  {
    category: "SQL Injection",
    attacks: [
      { name: "UNION-based SQLi", payload: "' UNION ALL SELECT NULL, NULL, NULL --" },
      { name: "Boolean-based SQLi", payload: "' OR 1=1 --" },
      { name: "Time-based SQLi", payload: "'; WAITFOR DELAY '00:00:05'--" },
      { name: "Stacked Queries", payload: "'; DROP TABLE users; --" },
    ],
  },
  {
    category: "XSS (Cross-Site Scripting)",
    attacks: [
      { name: "Basic XSS", payload: "<script>alert('XSS')</script>" },
      { name: "Image XSS", payload: '<img src=x onerror="alert(\'XSS\')">' },
      { name: "SVG XSS", payload: '<svg onload="alert(\'XSS\')">' },
      { name: "Event Handler", payload: '<body onload="alert(\'XSS\')">' },
    ],
  },
  {
    category: "Remote Code Execution",
    attacks: [
      { name: "Command Injection", payload: "'; exec('ls -la'); //" },
      { name: "Code Eval", payload: "eval(base64_decode($_POST['cmd']))" },
      { name: "Shellcode", payload: "\x90\x90\x90\x90\xeb\x1f" },
      { name: "PHP Code", payload: "<?php system($_GET['cmd']); ?>" },
    ],
  },
  {
    category: "Path Traversal",
    attacks: [
      { name: "Directory Traversal", payload: "../../etc/passwd" },
      { name: "Encoded Traversal", payload: "..%2F..%2Fetc%2Fpasswd" },
      { name: "Double Encoding", payload: "..%252F..%252Fetc%252Fpasswd" },
      { name: "Null Byte", payload: "....//....//etc/passwd%00" },
    ],
  },
  {
    category: "OWASP Top 10",
    attacks: [
      { name: "XXE Attack", payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' },
      { name: "LDAP Injection", payload: "*)(|(uid=*" },
      { name: "NoSQL Injection", payload: '{"$ne": null}' },
      { name: "Template Injection", payload: "${7*7}" },
    ],
  },
];

export default function TestAttacks() {
  const [selectedTenant, setSelectedTenant] = useState<string>("");
  const [targetUrl, setTargetUrl] = useState<string>("http://10.1.40.99");
  const [results, setResults] = useState<AttackResult[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>("SQL Injection");

  const { data: tenants } = useQuery<Tenant[]>({
    queryKey: ["/api/tenants"],
  });

  const executeMutation = useMutation({
    mutationFn: async (payload: string) => {
      const res = await fetch("/api/waf/test-attack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          targetUrl,
          payload,
          tenantId: selectedTenant || tenants?.[0]?.id,
        }),
      });
      return res.json();
    },
    onSuccess: (data) => {
      setResults([data, ...results.slice(0, 49)]);
    },
  });

  const executeAttack = (payload: string) => {
    executeMutation.mutate(payload);
  };

  const executeCategory = (category: string) => {
    const attacks = ATTACK_VECTORS.find((c) => c.category === category)?.attacks || [];
    attacks.forEach((attack) => {
      setTimeout(() => executeAttack(attack.payload), 200);
    });
  };

  const currentCategory = ATTACK_VECTORS.find((c) => c.category === selectedCategory);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">WAF Attack Testing</h1>
          <p className="text-muted-foreground text-sm mt-2">
            Test WAF security rules with simulated attack payloads. For URL attacks, copy the payload and append to your target URL.
          </p>
        </div>
        
        {/* URL Attack Instructions */}
        <div className="bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900 rounded-lg p-4 space-y-2">
          <p className="font-semibold text-sm text-blue-900 dark:text-blue-100">💡 How to Test URL Attacks in Browser:</p>
          <p className="text-xs text-blue-800 dark:text-blue-200 font-mono bg-white/50 dark:bg-black/30 p-2 rounded">
            Your target URL + "?" + attack payload
          </p>
          <p className="text-xs text-blue-800 dark:text-blue-200">
            Example: <code className="bg-white/50 dark:bg-black/30 px-1 rounded">http://10.1.40.99/?search=admin' OR '1'='1</code>
          </p>
          <p className="text-xs text-blue-800 dark:text-blue-200">
            The WAF will automatically detect and block these attacks!
          </p>
        </div>

        {/* Configuration */}
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-2">
            <label className="text-sm font-medium">Target Website</label>
            <Input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://10.1.40.99"
              className="font-mono text-xs"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">Tenant</label>
            <select
              value={selectedTenant}
              onChange={(e) => setSelectedTenant(e.target.value)}
              className="w-full px-3 py-2 border rounded-md bg-background text-sm"
            >
              <option value="">
                {tenants?.[0]?.name || "Select Tenant"}
              </option>
              {tenants?.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Attack Categories and Results */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Attack Vectors */}
        <div className="lg:col-span-1 space-y-4">
          {ATTACK_VECTORS.map((category) => (
            <Card key={category.category} className="cursor-pointer hover:border-primary transition-colors"
              onClick={() => setSelectedCategory(category.category)}>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Zap className="h-4 w-4" />
                  {category.category}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {category.attacks.map((attack) => (
                  <Button
                    key={attack.name}
                    variant="outline"
                    size="sm"
                    className="w-full justify-start text-xs"
                    onClick={() => executeAttack(attack.payload)}
                    disabled={executeMutation.isPending}
                  >
                    <AlertTriangle className="h-3 w-3 mr-1" />
                    {attack.name}
                  </Button>
                ))}
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Detailed Attack Execution & Results */}
        <div className="lg:col-span-2 space-y-4">
          {/* Quick Attack Cards */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Quick Test - {selectedCategory}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {currentCategory?.attacks.map((attack) => (
                <div key={attack.name} className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-sm">{attack.name}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate max-w-xs cursor-pointer hover:opacity-70" 
                        onClick={() => {
                          navigator.clipboard.writeText(targetUrl + "?" + attack.payload);
                        }}
                        title="Click to copy full URL">
                        {targetUrl}?{attack.payload}
                      </p>
                    </div>
                    <Button
                      size="sm"
                      onClick={() => executeAttack(attack.payload)}
                      disabled={executeMutation.isPending}
                    >
                      <Send className="h-3 w-3 mr-1" />
                      Test
                    </Button>
                  </div>
                </div>
              ))}
              <Button
                className="w-full"
                onClick={() => executeCategory(selectedCategory)}
                disabled={executeMutation.isPending}
              >
                <Zap className="h-4 w-4 mr-2" />
                Execute All {selectedCategory} Attacks
              </Button>
            </CardContent>
          </Card>

          {/* Results */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center justify-between">
                <span>Test Results ({results.length})</span>
                {results.length > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setResults([])}
                  >
                    Clear Results
                  </Button>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {results.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No attack results yet. Execute attacks to see responses.</p>
                </div>
              ) : (
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {results.map((result, idx) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-lg border text-sm font-mono ${
                        result.action === "block"
                          ? "bg-red-50 border-red-200 dark:bg-red-950/20 dark:border-red-900"
                          : result.action === "challenge"
                          ? "bg-yellow-50 border-yellow-200 dark:bg-yellow-950/20 dark:border-yellow-900"
                          : "bg-green-50 border-green-200 dark:bg-green-950/20 dark:border-green-900"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <p className="font-bold text-xs truncate">
                            {result.attackType}
                          </p>
                          <p className="text-xs text-muted-foreground truncate">
                            {result.payload.substring(0, 50)}...
                          </p>
                        </div>
                        <div className="flex items-center gap-2 whitespace-nowrap">
                          <Badge
                            variant={
                              result.action === "block"
                                ? "destructive"
                                : result.action === "challenge"
                                ? "secondary"
                                : "outline"
                            }
                            className="text-xs"
                          >
                            {result.action === "block" ? (
                              <XCircle className="h-3 w-3 mr-1" />
                            ) : result.action === "challenge" ? (
                              <Clock className="h-3 w-3 mr-1" />
                            ) : (
                              <CheckCircle2 className="h-3 w-3 mr-1" />
                            )}
                            {result.action}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {result.statusCode}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {result.score}/100
                          </Badge>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Statistics */}
      {results.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Attack Statistics</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-4">
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">Total Attacks</p>
                <p className="text-2xl font-bold">{results.length}</p>
              </div>
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">Blocked</p>
                <p className="text-2xl font-bold text-red-600">
                  {results.filter((r) => r.action === "block").length}
                </p>
              </div>
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">Challenged</p>
                <p className="text-2xl font-bold text-yellow-600">
                  {results.filter((r) => r.action === "challenge").length}
                </p>
              </div>
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">Avg Score</p>
                <p className="text-2xl font-bold">
                  {(
                    results.reduce((a, r) => a + r.score, 0) / results.length
                  ).toFixed(1)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
