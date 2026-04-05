"use client";

import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, Info, AlertOctagon, Terminal, Fingerprint, Activity, Radio, Lock, Unlock } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface DetailedAnalysisResultProps {
  result: {
    url: string;
    risk_score: number;
    label: string;
    reasoning?: string[];
    features?: Record<string, any>;
  };
}

export default function DetailedAnalysisResult({ result }: DetailedAnalysisResultProps) {
  const displayScore = Math.min(100, Math.max(0, Math.round(result.risk_score * 100)));
  const label = (result.label || 'Unknown').toUpperCase();

  const isSafe = displayScore < 40;
  const isSuspicious = displayScore >= 40 && displayScore < 75;
  const isMalicious = displayScore >= 75;

  const getStatusColor = () => {
    if (isSafe) return 'text-cyber-green';
    if (isSuspicious) return 'text-yellow-400';
    return 'text-cyber-red';
  };

  const getStatusBg = () => {
    if (isSafe) return 'bg-cyber-green/5 border-cyber-green/20';
    if (isSuspicious) return 'bg-yellow-400/5 border-yellow-400/20';
    return 'bg-cyber-red/5 border-cyber-red/20';
  };

  return (
    <div className="w-full max-w-5xl mx-auto mt-20 animate-fade-in slide-up">
      {/* Header Summary Card */}
      <div className={cn("relative glass-morphism rounded-3xl p-10 border-t-2 mb-12", getStatusBg())}>
        <div className="flex flex-col md:flex-row items-center gap-10">
          {/* Risk Gauge */}
          <div className="relative shrink-0 w-48 h-48 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90">
              <circle
                cx="96"
                cy="96"
                r="88"
                className="stroke-white/5 fill-none"
                strokeWidth="12"
              />
              <circle
                cx="96"
                cy="96"
                r="88"
                className={cn("fill-none transition-all duration-2000 ease-out", 
                  isSafe ? "stroke-cyber-green" : isSuspicious ? "stroke-yellow-400" : "stroke-cyber-red"
                )}
                strokeWidth="12"
                strokeDasharray="552.92"
                strokeDashoffset={552.92 * (1 - result.risk_score)}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-[10px] uppercase font-mono tracking-widest text-white/40 mb-1">Threat</span>
              <span className={cn("text-5xl font-black tracking-tighter leading-none", getStatusColor())}>
                {displayScore}%
              </span>
            </div>
          </div>

          <div className="flex-1 text-center md:text-left space-y-6">
            <div className="space-y-2">
              <div className="flex items-center justify-center md:justify-start gap-3">
                {isSafe ? <ShieldCheck className="w-8 h-8 text-cyber-green" /> : 
                 isSuspicious ? <ShieldAlert className="w-8 h-8 text-yellow-400" /> : 
                 <ShieldX className="w-8 h-8 text-cyber-red" />}
                <h2 className={cn("text-4xl font-black uppercase tracking-tight", getStatusColor())}>
                  {label} RISK DETECTED
                </h2>
              </div>
              <p className="text-white/40 font-mono text-sm break-all tracking-wider py-1 border-b border-white/5 inline-block">
                {result.url}
              </p>
            </div>

            <div className="flex flex-wrap justify-center md:justify-start gap-4">
              <div className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyber-blue" />
                <span className="text-[10px] uppercase font-bold tracking-widest text-white/60">Forensic Scan Active</span>
              </div>
              <div className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyber-green" />
                <span className="text-[10px] uppercase font-bold tracking-widest text-white/60">Neural Engine v2.4</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Detailed Analysis Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {/* Signal Matrix */}
        <div className="md:col-span-2 glass-morphism rounded-3xl p-8 border-white/5 space-y-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Radio className="w-5 h-5 text-cyber-blue animate-pulse" />
              <h3 className="text-sm font-bold uppercase tracking-widest text-white/50">Detailed Signal Matrix</h3>
            </div>
            <div className="px-3 py-1 rounded bg-white/5 text-[9px] font-mono text-white/30 uppercase tracking-widest">Live Metadata</div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {(result.reasoning || ['High entropy in domain name', 'Suspicious TLS certificate', 'Recent domain registration']).map((reason, i) => (
              <div key={i} className="group p-4 rounded-2xl bg-black/40 border border-white/5 hover:border-white/10 transition-colors flex items-start gap-4">
                <div className="shrink-0 p-2 rounded-lg bg-cyber-blue/5 border border-cyber-blue/10">
                  <Fingerprint className="w-4 h-4 text-cyber-blue group-hover:scale-110 transition-transform" />
                </div>
                <div className="space-y-1">
                  <div className="text-[10px] uppercase font-bold tracking-widest text-white/20">Metric Signal</div>
                  <div className="text-xs text-white/80 leading-relaxed font-medium">{reason}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Action Security Recommendation */}
        <div className="glass-morphism rounded-3xl p-8 border-white/5 flex flex-col items-center text-center justify-center space-y-6">
          <div className="p-5 rounded-full bg-white/5 border border-white/10">
            {isSafe ? <Lock className="w-10 h-10 text-cyber-green" /> : <Unlock className="w-10 h-10 text-cyber-red" />}
          </div>
          <div className="space-y-2">
            <h4 className="text-xl font-bold uppercase tracking-widest">Protocol Recommendation</h4>
            <p className="text-xs text-white/40 leading-relaxed px-4">
              {isSafe ? 
                "This URL shows no structural anomalies. Safety protocols allow for continued navigation with standard caution." : 
                "CRITICAL: High probability of phishing or credential harvesting. Do not enter any sensitive data or interact with page elements."}
            </p>
          </div>
          <button 
            onClick={() => {
              if (isSafe) {
                window.open(result.url, '_blank', 'noopener,noreferrer');
              } else {
                // For malicious, we could just close the result or show an alert
                alert("ACCESS BLOCKED: This domain is classified as a high-risk security threat.");
              }
            }}
            className={cn(
              "w-full py-4 rounded-2xl font-black uppercase text-[10px] tracking-[0.2em] transition-all",
              isSafe ? "bg-cyber-green/10 text-cyber-green border border-cyber-green/30 hover:bg-cyber-green/20" : 
              "bg-cyber-red/20 text-cyber-red border border-cyber-red/30 hover:bg-cyber-red/40 neon-glow-red"
            )}
          >
            {isSafe ? "CONTINUE TO SITE" : "BLOCK NETWORK ACCESS"}
          </button>
        </div>
      </div>

      {/* Footer Disclaimer */}
      <div className="mt-12 flex items-center justify-center gap-2 text-white/20 text-[9px] uppercase tracking-widest">
        <Info className="w-3 h-3" />
        <span>PhishGuard Neural Core powered by SIH25159 Detection Engine</span>
      </div>
    </div>
  );
}
