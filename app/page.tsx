"use client";

import React, { useState } from 'react';
import { Shield, Terminal, Globe, Cpu, Lock, ShieldAlert, ChevronRight } from 'lucide-react';
import UrlInput from '@/components/UrlInput';
import DetailedAnalysisResult from '@/components/DetailedAnalysisResult';

export default function Home() {
  const [isLoading, setIsLoading] = useState(false);
  const [analysis, setAnalysis] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (url: string) => {
    setIsLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) throw new Error('Forensic analysis failed.');

      const data = await response.json();
      setAnalysis(data);
    } catch (err) {
      setError('Neural Core link failure. Please re-initiate scan.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="min-h-screen relative overflow-hidden flex flex-col items-center pt-24 pb-32 px-6">
      {/* Background elements */}
      <div className="fixed inset-0 cyber-grid -z-10" />
      <div className="fixed top-1/4 left-1/4 w-[500px] h-[500px] bg-cyber-blue/10 rounded-full blur-[120px] -z-20" />
      <div className="fixed bottom-1/4 right-1/4 w-[500px] h-[500px] bg-cyber-purple/10 rounded-full blur-[120px] -z-20" />

      <div className="w-full max-w-7xl mx-auto z-10">
        {/* Navigation / Top Bar */}
        <div className="flex justify-between items-center mb-24 px-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-cyber-blue shadow-[0_0_20px_rgba(0,240,255,0.3)] flex items-center justify-center rounded-lg">
              <Shield className="w-6 h-6 text-black" />
            </div>
            <div className="flex flex-col">
              <span className="text-xl font-black tracking-tighter text-white leading-none">PHISHGUARD</span>
              <span className="text-[8px] font-mono tracking-[0.3em] text-cyber-blue uppercase">Neural Core v2</span>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-8 text-[10px] font-mono tracking-widest text-white/30 uppercase">
            <a href="#" className="hover:text-cyber-blue transition-colors">Heuristics</a>
            <a href="#" className="hover:text-cyber-blue transition-colors">Forensics</a>
            <a href="#" className="hover:text-cyber-blue transition-colors">API</a>
            <div className="px-4 py-2 border border-white/10 rounded-full bg-white/5 hover:bg-white/10 transition-all cursor-pointer">
              System Status: <span className="text-cyber-green">Optimal</span>
            </div>
          </div>
        </div>

        {/* Hero Section */}
        <div className="text-center mb-16 space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-[9px] font-mono uppercase tracking-[0.2em] text-white/40 mb-2">
            <Terminal className="w-3 h-3 text-cyber-green" />
            Active Threat Mitigation Active
          </div>
          <h1 className="text-6xl md:text-8xl font-black tracking-tighter text-white leading-none">
            Deep Neural <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-blue via-white to-cyber-green">Detection.</span>
          </h1>
          <p className="text-lg md:text-xl text-white/40 max-w-2xl mx-auto font-light leading-relaxed tracking-wide">
            Real-time heuristic mapping and AI-driven forensic analysis for immediate 
            phishing threat detection. Built on the SIH25159 security protocol.
          </p>
        </div>

        {/* Input UI */}
        <div className="mb-20">
          <UrlInput onAnalyze={handleAnalyze} isLoading={isLoading} />
        </div>

        {/* Error State */}
        {error && (
          <div className="max-w-md mx-auto p-4 glass-morphism border-cyber-red/30 rounded-2xl flex items-center gap-4 text-cyber-red animate-shake">
            <ShieldAlert className="w-6 h-6 shrink-0" />
            <p className="text-xs font-mono uppercase tracking-widest">{error}</p>
          </div>
        )}

        {/* Dynamic Content */}
        {analysis ? (
          <DetailedAnalysisResult result={analysis} />
        ) : !isLoading && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-10 max-w-6xl mx-auto">
            <FeatureCard 
              icon={<Globe className="w-6 h-6 text-cyber-blue" />}
              title="Global reputation"
              description="Cross-referencing telemetry with known malicious domain clusters and zero-day threat feeds."
            />
            <FeatureCard 
              icon={<Cpu className="w-6 h-6 text-cyber-green" />}
              title="Structural analysis"
              description="Deep inspection of HTML attribute distribution, CSS anomalies, and JS obfuscation patterns."
            />
            <FeatureCard 
              icon={<Lock className="w-6 h-6 text-cyber-purple" />}
              title="Identity Guard"
              description="Identifying credential harvesting attempts via visual similarity and structural brand spoofing."
            />
          </div>
        )}
      </div>

      {/* Background Branding */}
      <div className="fixed bottom-10 left-10 text-white/5 font-black text-9xl -rotate-90 select-none pointer-events-none uppercase">
        FORENSIC
      </div>
      <div className="fixed top-10 right-10 text-white/5 font-black text-9xl rotate-90 select-none pointer-events-none uppercase">
        NEURAL
      </div>
    </main>
  );
}

function FeatureCard({ icon, title, description }: { icon: React.ReactNode, title: string, description: string }) {
  return (
    <div className="group p-8 rounded-3xl glass-morphism hover:bg-white/[0.04] transition-all cursor-default relative overflow-hidden">
      <div className="absolute top-0 right-0 p-4 opacity-0 group-hover:opacity-100 transition-opacity">
        <ChevronRight className="w-4 h-4 text-white/20" />
      </div>
      <div className="space-y-6 relative">
        <div className="w-14 h-14 bg-white/5 rounded-2xl flex items-center justify-center border border-white/10 group-hover:border-white/20 transition-all">
          {icon}
        </div>
        <div className="space-y-2">
          <h3 className="text-xl font-bold text-white group-hover:text-cyber-blue transition-colors">{title}</h3>
          <p className="text-sm text-white/30 leading-relaxed font-light">{description}</p>
        </div>
      </div>
    </div>
  );
}
