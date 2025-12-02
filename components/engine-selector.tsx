/**
 * Security Engine Selector Component
 * Allows per-tenant selection of WAF Engine, ModSecurity, or both
 */

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Shield, Zap, Check } from 'lucide-react';

interface EngineSelectorProps {
  currentEngine: 'waf-engine' | 'modsecurity' | 'both' | null | undefined;
  onSelect: (engine: 'waf-engine' | 'modsecurity' | 'both') => void;
  isLoading?: boolean;
}

export function EngineSelector({ currentEngine, onSelect, isLoading }: EngineSelectorProps) {
  // Ensure currentEngine has a valid value
  const activeEngine = (currentEngine || 'both') as 'waf-engine' | 'modsecurity' | 'both';
  
  const engines = [
    {
      id: 'waf-engine',
      name: 'WAF Engine',
      description: 'Pattern matching + ML threat scoring + DDoS detection',
      rules: '450+ OWASP rules',
      icon: Shield,
      color: 'bg-blue-100 dark:bg-blue-900',
      textColor: 'text-blue-700 dark:text-blue-300',
    },
    {
      id: 'modsecurity',
      name: 'ModSecurity',
      description: 'OWASP Core Rule Set v3.3 - Industry standard protection',
      rules: '513+ CRS rules',
      icon: Zap,
      color: 'bg-yellow-100 dark:bg-yellow-900',
      textColor: 'text-yellow-700 dark:text-yellow-300',
    },
    {
      id: 'both',
      name: 'Both (Recommended)',
      description: 'Multi-layer defense - both engines protect in parallel',
      rules: '963+ combined rules',
      icon: Shield,
      color: 'bg-green-100 dark:bg-green-900',
      textColor: 'text-green-700 dark:text-green-300',
    },
  ];

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-lg font-semibold mb-2">Security Engine Selection</h3>
        <p className="text-sm text-muted-foreground mb-4">
          Choose which security engine(s) protect this tenant's traffic
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {engines.map((engine) => {
          const Icon = engine.icon;
          const isSelected = activeEngine === engine.id;

          return (
            <Card
              key={engine.id}
              className={`cursor-pointer transition-all duration-300 ${
                isSelected
                  ? 'ring-3 ring-primary shadow-xl bg-gradient-to-br from-primary/10 to-primary/5 border-primary border-2'
                  : 'hover:shadow-md border border-transparent hover:border-muted-foreground/20'
              }`}
              onClick={() => !isLoading && onSelect(engine.id as any)}
            >
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2 flex-1">
                    <div className={`p-2 rounded ${engine.color} transition-transform ${isSelected ? 'scale-110' : ''}`}>
                      <Icon className={`w-5 h-5 ${engine.textColor}`} />
                    </div>
                    <div className="flex-1">
                      <CardTitle className="text-base flex items-center gap-2">
                        {engine.name}
                        {isSelected && (
                          <Check className="w-5 h-5 text-primary animate-pulse" />
                        )}
                      </CardTitle>
                      {isSelected && (
                        <Badge className="mt-1 bg-primary text-primary-foreground" variant="default">
                          ✓ Active
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">{engine.description}</p>
                <div className="flex items-center justify-between">
                  <Badge variant="secondary">{engine.rules}</Badge>
                  {isSelected ? (
                    <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100">
                      Selected
                    </Badge>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={isLoading}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelect(engine.id as any);
                      }}
                      className="hover:bg-primary hover:text-primary-foreground transition-colors"
                    >
                      Select
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      <Card className="bg-muted/50">
        <CardHeader>
          <CardTitle className="text-sm">Engine Comparison</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="font-medium">WAF Engine:</span>
              <span className="text-muted-foreground">Pattern matching + ML + DDoS</span>
            </div>
            <div className="flex justify-between">
              <span className="font-medium">ModSecurity:</span>
              <span className="text-muted-foreground">OWASP CRS v3.3 (513+ rules)</span>
            </div>
            <div className="flex justify-between">
              <span className="font-medium">Both:</span>
              <span className="text-green-600 font-semibold">Maximum protection (recommended)</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
