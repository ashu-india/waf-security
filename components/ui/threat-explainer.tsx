import { memo } from 'react';
import { cn } from "@/lib/utils";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./card";
import { Badge } from "./badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "./accordion";
import { 
  AlertTriangle, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Info, 
  Target,
  Lightbulb,
  FileWarning,
  Activity
} from "lucide-react";

interface RuleMatch {
  ruleId: string;
  ruleName: string;
  field: string;
  value: string;
  severity: string;
  category: string;
  description?: string;
  matchedPattern?: string;
  recommendation?: string;
}

interface ScoreBreakdown {
  patternScore: number;
  anomalyScore: number;
  reputationScore: number;
  mlScore?: number;
  combinedScore?: number;
}

interface Explainability {
  summary: string;
  details: string[];
  recommendations: string[];
}

interface MLAnalysis {
  threatProbability: number;
  anomalyScore: number;
  confidence: number;
  topFactors: { factor: string; importance: number }[];
  reasoning: string[];
}

interface ThreatExplainerProps {
  action: "allow" | "block" | "challenge" | string;
  score: number;
  riskLevel: string;
  matches: RuleMatch[];
  breakdown?: ScoreBreakdown;
  mlAnalysis?: MLAnalysis;
  explainability?: Explainability;
  className?: string;
}

const categoryLabels: Record<string, { label: string; icon: React.ReactNode }> = {
  'sql-injection': { label: 'SQL Injection', icon: <FileWarning className="h-4 w-4" /> },
  'xss': { label: 'Cross-Site Scripting (XSS)', icon: <AlertTriangle className="h-4 w-4" /> },
  'path-traversal': { label: 'Path Traversal', icon: <Target className="h-4 w-4" /> },
  'lfi': { label: 'Local File Inclusion', icon: <FileWarning className="h-4 w-4" /> },
  'rfi': { label: 'Remote File Inclusion', icon: <FileWarning className="h-4 w-4" /> },
  'command-injection': { label: 'Command Injection', icon: <ShieldAlert className="h-4 w-4" /> },
  'ssrf': { label: 'Server-Side Request Forgery', icon: <Target className="h-4 w-4" /> },
  'xxe': { label: 'XML External Entity', icon: <FileWarning className="h-4 w-4" /> },
  'header-injection': { label: 'Header Injection', icon: <AlertTriangle className="h-4 w-4" /> },
  'nosql-injection': { label: 'NoSQL Injection', icon: <FileWarning className="h-4 w-4" /> },
  'ssti': { label: 'Server-Side Template Injection', icon: <ShieldAlert className="h-4 w-4" /> },
  'protocol-attack': { label: 'Protocol Attack', icon: <ShieldAlert className="h-4 w-4" /> },
  'reconnaissance': { label: 'Reconnaissance', icon: <Target className="h-4 w-4" /> },
  'malware': { label: 'Malware Detection', icon: <ShieldAlert className="h-4 w-4" /> },
  'auth': { label: 'Authentication Issue', icon: <Shield className="h-4 w-4" /> },
  'default': { label: 'Security Issue', icon: <AlertTriangle className="h-4 w-4" /> },
};

const severityColors: Record<string, string> = {
  low: 'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20',
  medium: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-500/20',
  high: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
  critical: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20',
};

const actionConfig: Record<string, { color: string; icon: React.ReactNode; text: string }> = {
  allow: { 
    color: 'text-green-600 dark:text-green-400', 
    icon: <ShieldCheck className="h-5 w-5" />,
    text: 'Request Allowed'
  },
  block: { 
    color: 'text-red-600 dark:text-red-400', 
    icon: <ShieldAlert className="h-5 w-5" />,
    text: 'Request Blocked'
  },
  challenge: { 
    color: 'text-blue-600 dark:text-blue-400', 
    icon: <Shield className="h-5 w-5" />,
    text: 'Challenge Required'
  },
  monitor: { 
    color: 'text-yellow-600 dark:text-yellow-400', 
    icon: <Activity className="h-5 w-5" />,
    text: 'Request Monitored'
  },
};

export const ThreatExplainer = memo(function ThreatExplainer({
  action,
  score,
  riskLevel,
  matches,
  breakdown,
  mlAnalysis,
  explainability,
  className
}: ThreatExplainerProps) {
  const config = actionConfig[action] || actionConfig.allow;
  
  return (
    <Card className={cn("overflow-hidden", className)}>
      <CardHeader className="pb-3 border-b">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={cn("p-2 rounded-lg", action === 'block' ? 'bg-red-500/10' : action === 'challenge' ? 'bg-blue-500/10' : 'bg-green-500/10')}>
              <span className={config.color}>{config.icon}</span>
            </div>
            <div>
              <CardTitle className="text-lg">{config.text}</CardTitle>
              <CardDescription>
                {explainability?.summary || `Threat score: ${score}`}
              </CardDescription>
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold">{score}</div>
            <Badge 
              variant="outline" 
              className={severityColors[riskLevel] || severityColors.low}
            >
              {riskLevel} risk
            </Badge>
          </div>
        </div>
      </CardHeader>
      
      <CardContent className="pt-4 space-y-4">
        {breakdown && (
          <div className={`grid ${breakdown.mlScore !== undefined ? 'grid-cols-4' : 'grid-cols-3'} gap-3`}>
            <div className="text-center p-3 rounded-lg bg-muted/50">
              <div className="text-lg font-semibold">{breakdown.patternScore}</div>
              <div className="text-xs text-muted-foreground">Pattern</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-muted/50">
              <div className="text-lg font-semibold">{breakdown.anomalyScore}</div>
              <div className="text-xs text-muted-foreground">Anomaly</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-muted/50">
              <div className="text-lg font-semibold">{breakdown.reputationScore}</div>
              <div className="text-xs text-muted-foreground">Reputation</div>
            </div>
            {breakdown.mlScore !== undefined && (
              <div className="text-center p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <div className="text-lg font-semibold text-blue-600 dark:text-blue-400">{breakdown.mlScore}</div>
                <div className="text-xs text-muted-foreground">ML Score</div>
              </div>
            )}
          </div>
        )}

        {mlAnalysis && (
          <div className="space-y-3 p-3 rounded-lg bg-purple-500/5 border border-purple-500/10">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-purple-600 dark:text-purple-400" />
              <h4 className="text-sm font-semibold text-purple-600 dark:text-purple-400">ML Analysis</h4>
              <Badge variant="outline" className="ml-auto text-xs">
                {(mlAnalysis.threatProbability * 100).toFixed(0)}% threat
              </Badge>
            </div>
            
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="space-y-1">
                <div className="text-muted-foreground">Confidence</div>
                <div className="text-sm font-semibold">{(mlAnalysis.confidence * 100).toFixed(0)}%</div>
              </div>
              <div className="space-y-1">
                <div className="text-muted-foreground">Anomaly</div>
                <div className="text-sm font-semibold">{mlAnalysis.anomalyScore.toFixed(0)}</div>
              </div>
            </div>

            {mlAnalysis.topFactors && mlAnalysis.topFactors.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs font-semibold text-muted-foreground">Top Factors</div>
                <div className="space-y-1">
                  {mlAnalysis.topFactors.slice(0, 3).map((factor, i) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">{factor.factor}</span>
                      <span className="text-purple-600 dark:text-purple-400 font-medium">
                        {(factor.importance * 100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {mlAnalysis.reasoning && mlAnalysis.reasoning.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs font-semibold text-muted-foreground">Reasoning</div>
                <div className="space-y-1">
                  {mlAnalysis.reasoning.slice(0, 2).map((reason, i) => (
                    <div key={i} className="text-xs text-muted-foreground">• {reason}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {matches.length > 0 && (
          <div>
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
              <Target className="h-4 w-4" />
              Matched Security Rules ({matches.length})
            </h4>
            <Accordion type="multiple" className="w-full">
              {matches.map((match, index) => {
                const category = categoryLabels[match.category] || categoryLabels.default;
                return (
                  <AccordionItem key={`${match.ruleId}-${index}`} value={`rule-${index}`}>
                    <AccordionTrigger className="text-sm hover:no-underline py-2">
                      <div className="flex items-center gap-2 text-left">
                        <span className="text-muted-foreground">{category.icon}</span>
                        <span className="font-medium">{match.ruleName}</span>
                        <Badge 
                          variant="outline" 
                          className={cn("ml-auto", severityColors[match.severity] || severityColors.medium)}
                        >
                          {match.severity}
                        </Badge>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent className="text-sm space-y-2 pb-3">
                      {match.description && (
                        <p className="text-muted-foreground">{match.description}</p>
                      )}
                      <div className="space-y-1">
                        <div className="flex items-start gap-2">
                          <span className="text-muted-foreground shrink-0">Field:</span>
                          <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{match.field}</code>
                        </div>
                        {match.matchedPattern && (
                          <div className="flex items-start gap-2">
                            <span className="text-muted-foreground shrink-0">Matched:</span>
                            <code className="text-xs bg-muted px-1.5 py-0.5 rounded break-all">{match.matchedPattern}</code>
                          </div>
                        )}
                        {match.value && (
                          <div className="flex items-start gap-2">
                            <span className="text-muted-foreground shrink-0">Context:</span>
                            <code className="text-xs bg-muted px-1.5 py-0.5 rounded break-all max-w-full overflow-hidden">{match.value}</code>
                          </div>
                        )}
                      </div>
                      {match.recommendation && (
                        <div className="flex items-start gap-2 p-2 rounded-lg bg-blue-500/10 border border-blue-500/20">
                          <Lightbulb className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
                          <span className="text-blue-700 dark:text-blue-300 text-xs">{match.recommendation}</span>
                        </div>
                      )}
                    </AccordionContent>
                  </AccordionItem>
                );
              })}
            </Accordion>
          </div>
        )}

        {explainability?.details && explainability.details.length > 0 && (
          <div>
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
              <Info className="h-4 w-4" />
              Analysis Details
            </h4>
            <ul className="space-y-1 text-sm text-muted-foreground">
              {explainability.details.map((detail, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-muted-foreground">•</span>
                  <span>{detail}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {explainability?.recommendations && explainability.recommendations.length > 0 && (
          <div className="p-3 rounded-lg bg-primary/5 border border-primary/20">
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2 text-primary">
              <Lightbulb className="h-4 w-4" />
              Recommendations
            </h4>
            <ul className="space-y-1 text-sm">
              {explainability.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-primary">→</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
});

export const ThreatScoreGauge = memo(function ThreatScoreGauge({ 
  score, 
  size = 'md' 
}: { 
  score: number; 
  size?: 'sm' | 'md' | 'lg' 
}) {
  const sizeClasses = {
    sm: 'h-16 w-16',
    md: 'h-24 w-24',
    lg: 'h-32 w-32'
  };
  
  const strokeWidth = size === 'sm' ? 4 : size === 'md' ? 6 : 8;
  const radius = size === 'sm' ? 28 : size === 'md' ? 40 : 56;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  
  const getColor = () => {
    if (score >= 70) return 'stroke-red-500';
    if (score >= 50) return 'stroke-orange-500';
    if (score >= 30) return 'stroke-yellow-500';
    return 'stroke-green-500';
  };
  
  return (
    <div className={cn("relative", sizeClasses[size])}>
      <svg className="rotate-[-90deg] w-full h-full">
        <circle
          cx="50%"
          cy="50%"
          r={radius}
          fill="none"
          className="stroke-muted"
          strokeWidth={strokeWidth}
        />
        <circle
          cx="50%"
          cy="50%"
          r={radius}
          fill="none"
          className={cn("transition-all duration-500", getColor())}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className={cn(
          "font-bold",
          size === 'sm' ? 'text-sm' : size === 'md' ? 'text-xl' : 'text-2xl'
        )}>
          {score}
        </span>
      </div>
    </div>
  );
});
