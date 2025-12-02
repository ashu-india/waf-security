import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Info } from "lucide-react";

interface BehavioralPolicyConfigProps {
  policy: any;
  onChange: (data: any) => void;
}

export function BehavioralPolicyConfig({ policy, onChange }: BehavioralPolicyConfigProps) {
  const handleChange = (key: string, value: any) => {
    onChange({
      ...policy,
      [key]: value,
    });
  };

  return (
    <div className="space-y-6">
      {/* Credential Stuffing Detection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Credential Stuffing Detection</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-sm font-semibold">Sensitivity Threshold</Label>
              <Badge variant="outline">{policy.credentialStuffingThreshold || 60}%</Badge>
            </div>
            <Slider
              value={[policy.credentialStuffingThreshold || 60]}
              onValueChange={(value) => handleChange("credentialStuffingThreshold", value[0])}
              min={0}
              max={100}
              step={5}
              className="w-full"
            />
            <p className="text-xs text-muted-foreground mt-2">
              Block attacks with confidence score above this threshold. Lower = stricter detection.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Failed Login Attempts */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Account Lockout Policy</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-sm font-semibold">Failed Attempts Before Lockout</Label>
              <Badge variant="outline">{policy.failedLoginAttempts || 5}</Badge>
            </div>
            <Slider
              value={[policy.failedLoginAttempts || 5]}
              onValueChange={(value) => handleChange("failedLoginAttempts", value[0])}
              min={3}
              max={10}
              step={1}
              className="w-full"
            />
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-sm font-semibold">Lockout Duration (minutes)</Label>
              <Badge variant="outline">{policy.lockoutDurationMinutes || 15} min</Badge>
            </div>
            <Slider
              value={[policy.lockoutDurationMinutes || 15]}
              onValueChange={(value) => handleChange("lockoutDurationMinutes", value[0])}
              min={5}
              max={60}
              step={5}
              className="w-full"
            />
          </div>
        </CardContent>
      </Card>

      {/* Bot Detection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Bot Detection</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-sm font-semibold">Bot Score Threshold</Label>
              <Badge variant="outline">{policy.botDetectionThreshold || 75}%</Badge>
            </div>
            <Slider
              value={[policy.botDetectionThreshold || 75]}
              onValueChange={(value) => handleChange("botDetectionThreshold", value[0])}
              min={40}
              max={95}
              step={5}
              className="w-full"
            />
            <p className="text-xs text-muted-foreground mt-2">
              Block requests identified as bots above this score. Lower = more aggressive blocking.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Anomaly Detection */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Anomaly Detection</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-sm font-semibold">Anomaly Sensitivity</Label>
              <Badge variant="outline">{policy.anomalySensitivity || "medium"}</Badge>
            </div>
            <div className="flex gap-2">
              {["low", "medium", "high"].map((level) => (
                <button
                  key={level}
                  onClick={() => handleChange("anomalySensitivity", level)}
                  className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                    policy.anomalySensitivity === level
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  }`}
                >
                  {level.charAt(0).toUpperCase() + level.slice(1)}
                </button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              High = more pattern violations detected | Low = only obvious anomalies
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Risk Profile Thresholds */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Risk Profile Thresholds</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-sm font-semibold">High Risk Threshold</Label>
              <Badge variant="outline">{policy.highRiskThreshold || 70}%</Badge>
            </div>
            <Slider
              value={[policy.highRiskThreshold || 70]}
              onValueChange={(value) => handleChange("highRiskThreshold", value[0])}
              min={50}
              max={90}
              step={5}
              className="w-full"
            />
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <Label className="text-sm font-semibold">Critical Risk Threshold</Label>
              <Badge variant="outline">{policy.criticalRiskThreshold || 85}%</Badge>
            </div>
            <Slider
              value={[policy.criticalRiskThreshold || 85]}
              onValueChange={(value) => handleChange("criticalRiskThreshold", value[0])}
              min={60}
              max={100}
              step={5}
              className="w-full"
            />
          </div>
        </CardContent>
      </Card>

      {/* Info Banner */}
      <div className="flex gap-3 p-4 rounded-lg bg-blue-50 border border-blue-200">
        <Info className="h-5 w-5 text-blue-600 mt-0.5 flex-shrink-0" />
        <div className="text-sm text-blue-900">
          <p className="font-semibold mb-1">Behavioral Security Configuration</p>
          <p>Adjust these thresholds to fine-tune detection sensitivity for your organization. Lower thresholds = stricter security, higher thresholds = fewer false positives.</p>
        </div>
      </div>
    </div>
  );
}
