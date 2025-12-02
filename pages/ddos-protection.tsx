import { DDoSDashboard } from "@/components/ddos-dashboard";

export default function DDoSProtectionPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">DDoS Protection</h1>
        <p className="text-muted-foreground text-sm mt-2">
          Monitor real-time DDoS attacks, configure detection thresholds, and review top attacking IPs.
          Our graduated response system automatically escalates from monitoring to rate-limiting to CAPTCHA challenges.
        </p>
      </div>

      <DDoSDashboard />
    </div>
  );
}
