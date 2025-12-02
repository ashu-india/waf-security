import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe, Shield, Wifi } from "lucide-react";

export interface GeoStats {
  totalCountries: number;
  topCountries: Array<{ code: string; name: string; requests: number }>;
  vpnDetectionsBlocked: number;
  geoblockedRequests: number;
  regionalRateLimitEnforced: number;
}

export function GeoAnalytics({ stats }: { stats: GeoStats | null }) {
  if (!stats) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Geo-Location Security</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">Loading geo-location data...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Geo-Location Security</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="p-3 rounded-lg bg-muted/50">
            <div className="flex items-center gap-2 mb-1">
              <Globe className="h-4 w-4 text-blue-500" />
              <span className="text-xs text-muted-foreground">Countries</span>
            </div>
            <p className="text-2xl font-bold">{stats.totalCountries}</p>
          </div>
          <div className="p-3 rounded-lg bg-muted/50">
            <div className="flex items-center gap-2 mb-1">
              <Wifi className="h-4 w-4 text-red-500" />
              <span className="text-xs text-muted-foreground">VPN Blocked</span>
            </div>
            <p className="text-2xl font-bold">{stats.vpnDetectionsBlocked}</p>
          </div>
          <div className="p-3 rounded-lg bg-muted/50">
            <div className="flex items-center gap-2 mb-1">
              <Shield className="h-4 w-4 text-green-500" />
              <span className="text-xs text-muted-foreground">Geo-Blocked</span>
            </div>
            <p className="text-2xl font-bold">{stats.geoblockedRequests}</p>
          </div>
          <div className="p-3 rounded-lg bg-muted/50">
            <div className="flex items-center gap-2 mb-1">
              <TrendingUp className="h-4 w-4 text-purple-500" />
              <span className="text-xs text-muted-foreground">Rate Limited</span>
            </div>
            <p className="text-2xl font-bold">{stats.regionalRateLimitEnforced}</p>
          </div>
        </div>

        {stats.topCountries.length > 0 && (
          <div className="pt-4 border-t">
            <p className="text-sm font-semibold mb-3">Traffic by Country</p>
            <div className="space-y-2">
              {stats.topCountries.map((country, idx) => (
                <div key={idx} className="flex items-center justify-between p-2 rounded bg-muted/50">
                  <span className="text-sm font-medium">{country.name}</span>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">{country.code}</Badge>
                    <span className="text-sm font-semibold">{country.requests}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Icon placeholder
function TrendingUp({ className }: { className: string }) {
  return <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" /></svg>;
}
