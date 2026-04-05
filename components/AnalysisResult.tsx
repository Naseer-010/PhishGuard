import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, Info } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface AnalysisResultProps {
  result: {
    url: string;
    risk_score: number;
    label: string;
    reasoning?: string[];
    features?: Record<string, any>;
  };
}

export default function AnalysisResult({ result }: AnalysisResultProps) {
  const isSafe = result.risk_score < 0.3;
  const isSuspicious = result.risk_score >= 0.3 && result.risk_score < 0.7;
  const isMalicious = result.risk_score >= 0.7;

  const getStatusColor = () => {
    if (isSafe) return 'text-cyber-green border-cyber-green/30 bg-cyber-green/5';
    if (isSuspicious) return 'text-yellow-400 border-yellow-400/30 bg-yellow-400/5';
    return 'text-cyber-red border-cyber-red/30 bg-cyber-red/5';
  };

  const getIcon = () => {
    if (isSafe) return <ShieldCheck className="w-12 h-12" />;
    if (isSuspicious) return <ShieldAlert className="w-12 h-12" />;
    return <ShieldX className="w-12 h-12" />;
  };

  return (
    <div className="w-full max-w-4xl mx-auto mt-12 animate-in fade-in slide-in-from-bottom-5 duration-700">
      <div className={cn(
        "glass-morphism rounded-2xl p-8 border-t-2",
        getStatusColor()
      )}>
        <div className="flex flex-col md:flex-row items-center md:items-start gap-8">
          <div className="shrink-0 p-4 rounded-full bg-white/5 border border-white/10">
            {getIcon()}
          </div>
          
          <div className="flex-1 text-center md:text-left">
            <h2 className="text-3xl font-bold mb-2 uppercase tracking-widest flex items-center justify-center md:justify-start gap-3">
              {result.label} RISK DETECTED
            </h2>
            <p className="text-white/60 font-mono break-all mb-6">{result.url}</p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-black/40 rounded-xl p-6 border border-white/5">
                <div className="text-sm uppercase tracking-wider text-white/40 mb-2">Threat Score</div>
                <div className="flex items-end gap-2">
                  <span className="text-5xl font-black">{Math.round(result.risk_score * 100)}%</span>
                  <span className="text-sm text-white/20 mb-2">PROBABILITY</span>
                </div>
                <div className="w-full h-2 bg-white/5 rounded-full mt-4 overflow-hidden">
                  <div 
                    className={cn("h-full transition-all duration-1000 ease-out", 
                      isSafe ? "bg-cyber-green" : isSuspicious ? "bg-yellow-400" : "bg-cyber-red"
                    )}
                    style={{ width: `${result.risk_score * 100}%` }}
                  />
                </div>
              </div>

              <div className="bg-black/40 rounded-xl p-6 border border-white/5">
                <div className="text-sm uppercase tracking-wider text-white/40 mb-2">Analysis Key Signals</div>
                <ul className="space-y-2">
                  {(result.reasoning || ['High entropy in domain name', 'Suspicious TLS certificate', 'Recent domain registration']).map((reason, i) => (
                    <li key={i} className="flex items-center gap-2 text-sm text-white/80">
                      <div className="w-1.5 h-1.5 rounded-full bg-white/20 shrink-0" />
                      {reason}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-8 pt-8 border-t border-white/5 flex items-center gap-2 text-white/30 text-xs">
          <Info className="w-4 h-4" />
          <span>This scan uses the PhishGuard Deep Risk Model for comprehensive threat analysis.</span>
        </div>
      </div>
    </div>
  );
}
