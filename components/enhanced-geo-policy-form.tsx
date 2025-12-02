import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { X, AlertCircle, CheckCircle2 } from "lucide-react";
import { COUNTRIES, searchCountries, getCountryName } from "@/utils/countries";

interface EnhancedGeoPolicyFormProps {
  policy: any;
  onChange: (data: any) => void;
}

export function EnhancedGeoPolicyForm({ policy, onChange }: EnhancedGeoPolicyFormProps) {
  const [testIp, setTestIp] = useState("");
  const [testResult, setTestResult] = useState<any>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [allowedQuery, setAllowedQuery] = useState("");
  const [blockedQuery, setBlockedQuery] = useState("");
  const [showAllowedSuggestions, setShowAllowedSuggestions] = useState(false);
  const [showBlockedSuggestions, setShowBlockedSuggestions] = useState(false);
  const [jsonError, setJsonError] = useState("");

  const handleAddAllowed = (code: string) => {
    const current = policy.allowedCountries || [];
    if (!current.includes(code)) {
      onChange({
        ...policy,
        allowedCountries: [...current, code],
      });
    }
    setAllowedQuery("");
    setShowAllowedSuggestions(false);
  };

  const handleAddBlocked = (code: string) => {
    const current = policy.blockedCountries || [];
    if (!current.includes(code)) {
      onChange({
        ...policy,
        blockedCountries: [...current, code],
      });
    }
    setBlockedQuery("");
    setShowBlockedSuggestions(false);
  };

  const handleRemoveAllowed = (code: string) => {
    onChange({
      ...policy,
      allowedCountries: (policy.allowedCountries || []).filter((c: string) => c !== code),
    });
  };

  const handleRemoveBlocked = (code: string) => {
    onChange({
      ...policy,
      blockedCountries: (policy.blockedCountries || []).filter((c: string) => c !== code),
    });
  };

  const handleJsonChange = (value: string) => {
    setJsonError("");
    try {
      if (value.trim()) {
        JSON.parse(value);
      }
      onChange({
        ...policy,
        geoRateLimitByCountry: value.trim() ? JSON.parse(value) : {},
      });
    } catch (e) {
      setJsonError("Invalid JSON format");
    }
  };

  const handleTestGeo = async () => {
    if (!testIp || !policy.id) return;
    setTestLoading(true);
    try {
      const res = await fetch(`/api/policies/${policy.id}/test-geo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ testIp }),
      });
      const result = await res.json();
      setTestResult(result);
    } catch (error) {
      console.error("Test failed:", error);
      setTestResult({ error: "Test failed" });
    } finally {
      setTestLoading(false);
    }
  };

  const allowedCountries = policy.allowedCountries || [];
  const blockedCountries = policy.blockedCountries || [];
  const allowedSuggestions = searchCountries(allowedQuery);
  const blockedSuggestions = searchCountries(blockedQuery);

  return (
    <Card className="w-full bg-card border border-border">
      <CardHeader className="bg-gradient-to-r from-primary/5 to-primary/10 border-b sticky top-0 z-10">
        <CardTitle className="text-base flex items-center gap-2">
          🌍 Geo-Location & Security Settings
        </CardTitle>
        <p className="text-xs text-muted-foreground mt-1">Control traffic by geography, region, and VPN status</p>
      </CardHeader>

      <CardContent className="pt-4">
        <Tabs defaultValue="restrictions" className="w-full">
          <TabsList className="grid w-full grid-cols-3 mb-4">
            <TabsTrigger value="restrictions" className="text-xs">
              Country Rules
            </TabsTrigger>
            <TabsTrigger value="rate-limits" className="text-xs">
              Regional Limits
            </TabsTrigger>
            <TabsTrigger value="vpn" className="text-xs">
              VPN Detection
            </TabsTrigger>
          </TabsList>

          {/* TAB 1: Country Restrictions */}
          <TabsContent value="restrictions" className="space-y-5 mt-4">
            {/* Allowed Countries */}
            <div className="space-y-3 p-3 bg-muted/30 rounded-lg">
              <div>
                <Label className="text-sm font-semibold flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                  Allowed Countries
                </Label>
                <p className="text-xs text-muted-foreground mt-1">
                  Leave empty to allow all. Add countries to create a whitelist.
                </p>
              </div>

              <div className="relative">
                <Input
                  placeholder="Search: 'United States' or 'US' or 'japan'"
                  value={allowedQuery}
                  onChange={(e) => {
                    setAllowedQuery(e.target.value);
                    setShowAllowedSuggestions(true);
                  }}
                  onFocus={() => setShowAllowedSuggestions(true)}
                  className="text-xs"
                />

                {showAllowedSuggestions && allowedQuery && (
                  <div className="absolute top-full left-0 right-0 bg-background border border-border rounded-md shadow-lg z-20 max-h-48 overflow-y-auto mt-1">
                    {allowedSuggestions.length > 0 ? (
                      allowedSuggestions.map((country) => (
                        <button
                          key={country.code}
                          onClick={() => handleAddAllowed(country.code)}
                          className="w-full text-left px-3 py-2 hover:bg-accent transition-colors text-xs border-b last:border-0"
                        >
                          <span className="font-semibold text-primary">{country.code}</span> • {country.name}
                        </button>
                      ))
                    ) : (
                      <div className="px-3 py-2 text-xs text-muted-foreground">No countries found</div>
                    )}
                  </div>
                )}
              </div>

              <div className="flex flex-wrap gap-2 p-2 bg-background border border-border rounded-md min-h-10">
                {allowedCountries.length > 0 ? (
                  allowedCountries.map((code: string) => (
                    <Badge
                      key={code}
                      className="bg-green-600 hover:bg-green-700 cursor-pointer text-xs flex items-center gap-1"
                      onClick={() => handleRemoveAllowed(code)}
                    >
                      {code}
                      <X className="h-3 w-3" />
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-muted-foreground italic">No countries selected</span>
                )}
              </div>
            </div>

            {/* Blocked Countries */}
            <div className="space-y-3 p-3 bg-muted/30 rounded-lg">
              <div>
                <Label className="text-sm font-semibold flex items-center gap-2">
                  <AlertCircle className="h-4 w-4 text-red-600" />
                  Blocked Countries
                </Label>
                <p className="text-xs text-muted-foreground mt-1">
                  Permanently block all traffic from these countries.
                </p>
              </div>

              <div className="relative">
                <Input
                  placeholder="Search: 'North Korea' or 'KP' or 'iran'"
                  value={blockedQuery}
                  onChange={(e) => {
                    setBlockedQuery(e.target.value);
                    setShowBlockedSuggestions(true);
                  }}
                  onFocus={() => setShowBlockedSuggestions(true)}
                  className="text-xs"
                />

                {showBlockedSuggestions && blockedQuery && (
                  <div className="absolute top-full left-0 right-0 bg-background border border-border rounded-md shadow-lg z-20 max-h-48 overflow-y-auto mt-1">
                    {blockedSuggestions.length > 0 ? (
                      blockedSuggestions.map((country) => (
                        <button
                          key={country.code}
                          onClick={() => handleAddBlocked(country.code)}
                          className="w-full text-left px-3 py-2 hover:bg-destructive/20 transition-colors text-xs border-b last:border-0"
                        >
                          <span className="font-semibold text-destructive">{country.code}</span> • {country.name}
                        </button>
                      ))
                    ) : (
                      <div className="px-3 py-2 text-xs text-muted-foreground">No countries found</div>
                    )}
                  </div>
                )}
              </div>

              <div className="flex flex-wrap gap-2 p-2 bg-background border border-border rounded-md min-h-10">
                {blockedCountries.length > 0 ? (
                  blockedCountries.map((code: string) => (
                    <Badge
                      key={code}
                      variant="destructive"
                      className="cursor-pointer text-xs flex items-center gap-1"
                      onClick={() => handleRemoveBlocked(code)}
                    >
                      {code}
                      <X className="h-3 w-3" />
                    </Badge>
                  ))
                ) : (
                  <span className="text-xs text-muted-foreground italic">No countries blocked</span>
                )}
              </div>
            </div>
          </TabsContent>

          {/* TAB 2: Regional Rate Limits */}
          <TabsContent value="rate-limits" className="space-y-3 mt-4">
            <div>
              <Label className="text-sm font-semibold">⚡ Rate Limits by Country</Label>
              <p className="text-xs text-muted-foreground mt-1 mb-3">
                Set different rate limits per country. Format: {'{'}&#34;CN&#34;: 50, &#34;RU&#34;: 75{'}'}
              </p>
            </div>

            <div className="space-y-2">
              <textarea
                value={JSON.stringify(policy.geoRateLimitByCountry || {}, null, 2)}
                onChange={(e) => handleJsonChange(e.target.value)}
                className="w-full px-3 py-2 border border-border rounded-md font-mono text-xs bg-muted/50 h-24 resize-none"
                placeholder='{"CN": 50, "RU": 50, "KR": 75}'
              />
              {jsonError && <p className="text-xs text-destructive flex items-center gap-1"><AlertCircle className="h-3 w-3" /> {jsonError}</p>}
            </div>

            <div className="bg-blue-50 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-900 rounded p-2 space-y-1">
              <p className="text-xs font-semibold text-blue-900 dark:text-blue-100">Format Guide:</p>
              <ul className="text-xs text-blue-800 dark:text-blue-200 space-y-0.5">
                <li>• Use ISO country codes: "US", "CN", "RU", "KR"</li>
                <li>• Values = max requests per time window</li>
                <li>• Higher value = more permissive</li>
              </ul>
            </div>
          </TabsContent>

          {/* TAB 3: VPN Detection */}
          <TabsContent value="vpn" className="space-y-4 mt-4">
            <div>
              <Label className="text-sm font-semibold">🔐 VPN & Proxy Detection</Label>
              <p className="text-xs text-muted-foreground mt-1">
                Detect and respond to VPN/proxy traffic from cloud providers.
              </p>
            </div>

            <div className="flex items-center justify-between p-3 border border-border rounded-lg bg-muted/50">
              <div className="space-y-1">
                <p className="font-medium text-sm">Enable VPN Detection</p>
                <p className="text-xs text-muted-foreground">
                  Detect AWS, Google Cloud, Azure, and other cloud providers
                </p>
              </div>
              <Switch
                checked={policy.vpnDetectionEnabled || false}
                onCheckedChange={(checked) =>
                  onChange({
                    ...policy,
                    vpnDetectionEnabled: checked,
                  })
                }
              />
            </div>

            {policy.vpnDetectionEnabled && (
              <div className="space-y-3 p-3 bg-muted/30 rounded-lg border">
                <Label className="text-sm font-semibold">Response Action</Label>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { value: "monitor", label: "👁️ Monitor", desc: "Log only" },
                    { value: "challenge", label: "🤔 Challenge", desc: "CAPTCHA" },
                    { value: "block", label: "🛑 Block", desc: "Reject" },
                  ].map((action) => (
                    <button
                      key={action.value}
                      onClick={() =>
                        onChange({
                          ...policy,
                          vpnBlockAction: action.value,
                        })
                      }
                      className={`p-2 rounded border-2 transition-all text-center text-xs ${
                        policy.vpnBlockAction === action.value
                          ? "border-primary bg-primary/20"
                          : "border-border hover:border-primary/50"
                      }`}
                    >
                      <p className="font-medium">{action.label}</p>
                      <p className="text-xs text-muted-foreground">{action.desc}</p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 rounded p-2 space-y-1">
              <p className="text-xs font-semibold text-amber-900 dark:text-amber-100">Detected Providers:</p>
              <p className="text-xs text-amber-800 dark:text-amber-200">
                AWS, Google Cloud, Microsoft Azure, Linode, DigitalOcean, Vultr, OVH, Hetzner
              </p>
            </div>
          </TabsContent>
        </Tabs>

        {/* Test Tool - Below Tabs */}
        <div className="mt-6 pt-4 border-t space-y-3">
          <div>
            <Label className="text-sm font-semibold">🧪 Test Policy Against IP</Label>
            <p className="text-xs text-muted-foreground">
              Test your current settings with a real IP address.
            </p>
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="Enter IP: 8.8.8.8 or 1.1.1.1"
              value={testIp}
              onChange={(e) => setTestIp(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleTestGeo()}
              className="text-xs flex-1"
            />
            <Button onClick={handleTestGeo} size="sm" disabled={!testIp || testLoading}>
              {testLoading ? "Testing..." : "Test"}
            </Button>
          </div>

          {testResult && !testResult.error && (
            <div className="bg-card border border-border rounded-lg p-3 space-y-2 text-xs">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="font-semibold">Country:</span>
                  <Badge variant="outline" className="ml-2">
                    {testResult.geoCheck?.country || "Unknown"}
                  </Badge>
                </div>
                <div>
                  <span className="font-semibold">Status:</span>
                  {testResult.geoCheck?.allowed ? (
                    <Badge className="ml-2 bg-green-600">✅ Allowed</Badge>
                  ) : (
                    <Badge className="ml-2 bg-red-600">❌ Blocked</Badge>
                  )}
                </div>
              </div>
              {testResult.geoCheck?.reason && (
                <div className="pt-1 border-t">
                  <span className="font-semibold">Reason:</span>
                  <p className="text-muted-foreground mt-1">{testResult.geoCheck.reason}</p>
                </div>
              )}
              {testResult.vpnCheck !== undefined && (
                <div className="pt-1 border-t">
                  <span className="font-semibold">VPN Status:</span>
                  <Badge className={`ml-2 ${testResult.vpnCheck ? "bg-red-600" : "bg-green-600"}`}>
                    {testResult.vpnCheck ? "🔴 VPN Detected" : "✅ Clean"}
                  </Badge>
                </div>
              )}
            </div>
          )}

          {testResult?.error && (
            <div className="bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 rounded p-2 text-xs text-red-800 dark:text-red-200">
              {testResult.error}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
