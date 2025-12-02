import { memo, useMemo } from 'react';
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "./card";
import { Badge } from "./badge";
import { 
  ShieldAlert, 
  Globe2, 
  TrendingUp, 
  TrendingDown,
  Activity,
  AlertTriangle
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend
} from "recharts";

interface AttackCategory {
  name: string;
  count: number;
  percentage: number;
  color: string;
}

interface AttackTimelineData {
  time: string;
  blocked: number;
  monitored: number;
  allowed: number;
}

interface GeoData {
  country: string;
  countryCode: string;
  count: number;
  percentage: number;
}

interface AttackPatternChartProps {
  data: AttackCategory[];
  className?: string;
}

const ATTACK_COLORS = {
  'sql-injection': '#ef4444',
  'xss': '#f97316',
  'path-traversal': '#eab308',
  'command-injection': '#dc2626',
  'ssrf': '#8b5cf6',
  'lfi': '#ec4899',
  'rfi': '#d946ef',
  'xxe': '#6366f1',
  'nosql-injection': '#14b8a6',
  'other': '#6b7280',
};

export const AttackPatternChart = memo(function AttackPatternChart({ 
  data, 
  className 
}: AttackPatternChartProps) {
  const chartData = useMemo(() => {
    return data.map(item => ({
      ...item,
      fill: ATTACK_COLORS[item.name.toLowerCase().replace(/\s+/g, '-') as keyof typeof ATTACK_COLORS] || ATTACK_COLORS.other
    }));
  }, [data]);

  return (
    <Card className={className}>
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-destructive" />
          Attack Categories
        </CardTitle>
      </CardHeader>
      <CardContent>
        {chartData.length > 0 ? (
          <div className="h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={90}
                  paddingAngle={2}
                  dataKey="count"
                  nameKey="name"
                >
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip 
                  formatter={(value: number, name: string) => [`${value} attacks`, name]}
                  contentStyle={{ 
                    backgroundColor: 'hsl(var(--popover))',
                    borderColor: 'hsl(var(--border))',
                    borderRadius: '0.5rem'
                  }}
                />
                <Legend 
                  verticalAlign="bottom" 
                  height={36}
                  formatter={(value) => <span className="text-xs">{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-[250px] flex items-center justify-center text-muted-foreground">
            <div className="text-center">
              <ShieldAlert className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No attack data available</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
});

interface AttackTimelineChartProps {
  data: AttackTimelineData[];
  className?: string;
}

export const AttackTimelineChart = memo(function AttackTimelineChart({ 
  data, 
  className 
}: AttackTimelineChartProps) {
  return (
    <Card className={className}>
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Activity className="h-4 w-4 text-primary" />
          Traffic Timeline
        </CardTitle>
      </CardHeader>
      <CardContent>
        {data.length > 0 ? (
          <div className="h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data}>
                <defs>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorMonitored" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#eab308" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#eab308" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis 
                  dataKey="time" 
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis 
                  tick={{ fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: 'hsl(var(--popover))',
                    borderColor: 'hsl(var(--border))',
                    borderRadius: '0.5rem'
                  }}
                />
                <Area 
                  type="monotone" 
                  dataKey="blocked" 
                  stackId="1"
                  stroke="#ef4444" 
                  fill="url(#colorBlocked)" 
                />
                <Area 
                  type="monotone" 
                  dataKey="monitored" 
                  stackId="1"
                  stroke="#eab308" 
                  fill="url(#colorMonitored)" 
                />
                <Area 
                  type="monotone" 
                  dataKey="allowed" 
                  stackId="1"
                  stroke="#22c55e" 
                  fill="url(#colorAllowed)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-[250px] flex items-center justify-center text-muted-foreground">
            <div className="text-center">
              <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No timeline data available</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
});

interface TopAttackersChartProps {
  data: { ip: string; count: number; country?: string }[];
  className?: string;
}

export const TopAttackersChart = memo(function TopAttackersChart({ 
  data, 
  className 
}: TopAttackersChartProps) {
  return (
    <Card className={className}>
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-orange-500" />
          Top Threat Sources
        </CardTitle>
      </CardHeader>
      <CardContent>
        {data.length > 0 ? (
          <div className="h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} layout="vertical">
                <XAxis type="number" tick={{ fontSize: 10 }} />
                <YAxis 
                  type="category" 
                  dataKey="ip" 
                  tick={{ fontSize: 10 }} 
                  width={100}
                />
                <Tooltip 
                  formatter={(value: number) => [`${value} requests`]}
                  contentStyle={{ 
                    backgroundColor: 'hsl(var(--popover))',
                    borderColor: 'hsl(var(--border))',
                    borderRadius: '0.5rem'
                  }}
                />
                <Bar 
                  dataKey="count" 
                  fill="#ef4444" 
                  radius={[0, 4, 4, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-[250px] flex items-center justify-center text-muted-foreground">
            <div className="text-center">
              <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No attacker data available</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
});

interface GeoDistributionProps {
  data: GeoData[];
  className?: string;
}

export const GeoDistribution = memo(function GeoDistribution({ 
  data, 
  className 
}: GeoDistributionProps) {
  const sortedData = useMemo(() => {
    return [...data].sort((a, b) => b.count - a.count).slice(0, 10);
  }, [data]);

  return (
    <Card className={className}>
      <CardHeader className="pb-2">
        <CardTitle className="text-base flex items-center gap-2">
          <Globe2 className="h-4 w-4 text-blue-500" />
          Geographic Distribution
        </CardTitle>
      </CardHeader>
      <CardContent>
        {sortedData.length > 0 ? (
          <div className="space-y-3">
            {sortedData.map((item, index) => (
              <div key={item.countryCode} className="flex items-center gap-3">
                <span className="w-6 text-lg">{getCountryFlag(item.countryCode)}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium truncate">{item.country}</span>
                    <span className="text-sm text-muted-foreground">{item.count}</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-primary rounded-full transition-all duration-300"
                      style={{ width: `${item.percentage}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="h-[200px] flex items-center justify-center text-muted-foreground">
            <div className="text-center">
              <Globe2 className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No geographic data available</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
});

function getCountryFlag(countryCode: string): string {
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

interface ThreatTrendIndicatorProps {
  current: number;
  previous: number;
  label: string;
  className?: string;
}

export const ThreatTrendIndicator = memo(function ThreatTrendIndicator({ 
  current, 
  previous, 
  label,
  className 
}: ThreatTrendIndicatorProps) {
  const change = previous > 0 ? ((current - previous) / previous) * 100 : 0;
  const isPositive = change > 0;
  const isNeutral = change === 0;

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <span className="text-sm text-muted-foreground">{label}:</span>
      <span className="font-semibold">{current.toLocaleString()}</span>
      {!isNeutral && (
        <Badge 
          variant="outline" 
          className={cn(
            "text-xs",
            isPositive 
              ? "text-red-600 dark:text-red-400 border-red-500/30" 
              : "text-green-600 dark:text-green-400 border-green-500/30"
          )}
        >
          {isPositive ? (
            <TrendingUp className="h-3 w-3 mr-1" />
          ) : (
            <TrendingDown className="h-3 w-3 mr-1" />
          )}
          {Math.abs(change).toFixed(1)}%
        </Badge>
      )}
    </div>
  );
});

interface SecurityScoreCardProps {
  score: number;
  maxScore?: number;
  trend?: { current: number; previous: number };
  className?: string;
}

export const SecurityScoreCard = memo(function SecurityScoreCard({ 
  score, 
  maxScore = 100, 
  trend,
  className 
}: SecurityScoreCardProps) {
  const percentage = (score / maxScore) * 100;
  const getScoreColor = () => {
    if (percentage >= 80) return 'text-green-600 dark:text-green-400';
    if (percentage >= 60) return 'text-yellow-600 dark:text-yellow-400';
    if (percentage >= 40) return 'text-orange-600 dark:text-orange-400';
    return 'text-red-600 dark:text-red-400';
  };

  const getGradientId = () => {
    if (percentage >= 80) return 'scoreGradientGreen';
    if (percentage >= 60) return 'scoreGradientYellow';
    if (percentage >= 40) return 'scoreGradientOrange';
    return 'scoreGradientRed';
  };

  return (
    <Card className={className}>
      <CardContent className="pt-6">
        <div className="flex items-center justify-center">
          <div className="relative">
            <svg className="h-32 w-32 -rotate-90">
              <defs>
                <linearGradient id="scoreGradientGreen" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#22c55e" />
                  <stop offset="100%" stopColor="#16a34a" />
                </linearGradient>
                <linearGradient id="scoreGradientYellow" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#eab308" />
                  <stop offset="100%" stopColor="#ca8a04" />
                </linearGradient>
                <linearGradient id="scoreGradientOrange" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#f97316" />
                  <stop offset="100%" stopColor="#ea580c" />
                </linearGradient>
                <linearGradient id="scoreGradientRed" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#ef4444" />
                  <stop offset="100%" stopColor="#dc2626" />
                </linearGradient>
              </defs>
              <circle
                cx="64"
                cy="64"
                r="56"
                fill="none"
                className="stroke-muted"
                strokeWidth="12"
              />
              <circle
                cx="64"
                cy="64"
                r="56"
                fill="none"
                stroke={`url(#${getGradientId()})`}
                strokeWidth="12"
                strokeDasharray={`${percentage * 3.52} 352`}
                strokeLinecap="round"
                className="transition-all duration-500"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={cn("text-3xl font-bold", getScoreColor())}>
                {score}
              </span>
              <span className="text-xs text-muted-foreground">Security Score</span>
            </div>
          </div>
        </div>
        {trend && (
          <div className="mt-4 text-center">
            <ThreatTrendIndicator
              current={trend.current}
              previous={trend.previous}
              label="vs last period"
            />
          </div>
        )}
      </CardContent>
    </Card>
  );
});
