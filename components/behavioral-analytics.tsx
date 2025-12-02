import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Lock, TrendingUp, Zap } from "lucide-react";

export interface BehavioralStats {
  totalProfiles: number;
  lockedAccounts: number;
  riskProfiles: Array<{ email: string; riskLevel: string; failedAttempts: number }>;
  credentialStuffingDetected: number;
  botAttacksBlocked: number;
  anomaliesDetected: number;
}

export function BehavioralAnalytics({ stats }: { stats: BehavioralStats | null }) {
  if (!stats) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Behavioral Analysis</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">Loading behavioral data...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Behavioral Analysis</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="p-3 rounded-lg bg-muted/50">
            <div className="flex items-center gap-2 mb-1">
              <Zap className="h-4 w-4 text-yellow-500" />
              <span className="text-xs text-muted-foreground">Credential Stuffing</span>
            </div>
            <p className="text-2xl font-bold">{stats.credentialStuffingDetected}</p>
          </div>
          <div className="p-3 rounded-lg bg-muted/50">
            <div className="flex items-center gap-2 mb-1">
              <TrendingUp className="h-4 w-4 text-red-500" />
              <span className="text-xs text-muted-foreground">Bot Attacks Blocked</span>
            </div>
            <p className="text-2xl font-bold">{stats.botAttacksBlocked}</p>
          </div>
          <div className="p-3 rounded-lg bg-muted/50">
            <div className="flex items-center gap-2 mb-1">
              <Lock className="h-4 w-4 text-orange-500" />
              <span className="text-xs text-muted-foreground">Locked Accounts</span>
            </div>
            <p className="text-2xl font-bold">{stats.lockedAccounts}</p>
          </div>
          <div className="p-3 rounded-lg bg-muted/50">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="h-4 w-4 text-purple-500" />
              <span className="text-xs text-muted-foreground">Anomalies Detected</span>
            </div>
            <p className="text-2xl font-bold">{stats.anomaliesDetected}</p>
          </div>
        </div>

        {stats.riskProfiles.length > 0 && (
          <div className="pt-4 border-t">
            <p className="text-sm font-semibold mb-3">High Risk Profiles</p>
            <div className="space-y-2">
              {stats.riskProfiles.slice(0, 5).map((profile, idx) => (
                <div key={idx} className="flex items-center justify-between p-2 rounded bg-muted/50">
                  <span className="text-xs truncate font-mono">{profile.email}</span>
                  <div className="flex items-center gap-2">
                    <Badge 
                      variant="outline" 
                      className={
                        profile.riskLevel === "critical" ? "bg-red-100 text-red-800" :
                        profile.riskLevel === "high" ? "bg-orange-100 text-orange-800" :
                        "bg-yellow-100 text-yellow-800"
                      }
                    >
                      {profile.riskLevel}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{profile.failedAttempts} fails</span>
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
