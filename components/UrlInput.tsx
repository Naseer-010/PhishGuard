"use client";

import React, { useState } from 'react';
import { Shield, Search, Loader2, Zap } from 'lucide-react';

interface UrlInputProps {
  onAnalyze: (url: string) => void;
  isLoading: boolean;
}

export default function UrlInput({ onAnalyze, isLoading }: UrlInputProps) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const isValidUrl = (string: string) => {
    // Basic check: must have a dot and no spaces (as requested)
    return string.includes('.') && !string.includes(' ');
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedUrl = url.trim();
    
    if (!trimmedUrl) return;

    if (!isValidUrl(trimmedUrl)) {
      setError('INVALID URL: Please inject a properly structured target (e.g., example.com)');
      return;
    }

    setError('');
    onAnalyze(trimmedUrl);
  };

  return (
    <div className="w-full max-w-3xl mx-auto animate-fade-in">
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-blue/10 border border-cyber-blue/20 text-[10px] font-mono uppercase tracking-[0.2em] text-cyber-blue mb-4">
          <Zap className="w-3 h-3" />
          Quantum Heuristic Engine v2.4
        </div>
      </div>

      <form onSubmit={handleSubmit} className="relative">
        {/* Decorative elements */}
        <div className="absolute -top-10 -left-10 w-40 h-40 bg-cyber-blue/10 rounded-full blur-[80px]" />
        <div className="absolute -bottom-10 -right-10 w-40 h-40 bg-cyber-green/10 rounded-full blur-[80px]" />

        <div className="relative glass-morphism rounded-2xl overflow-hidden p-1 group">
          <div className="absolute inset-0 bg-gradient-to-r from-cyber-blue/20 via-transparent to-cyber-green/20 opacity-0 group-focus-within:opacity-100 transition-opacity duration-500" />
          
          <div className="relative flex items-center bg-black/80 rounded-[14px] px-6 py-4">
            <Shield className={`w-6 h-6 mr-4 transition-colors duration-500 ${isLoading ? 'text-cyber-green animate-pulse' : 'text-white/20'}`} />
            
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (error) setError('');
              }}
              placeholder="Inject URL for deep neural inspection..."
              className={`w-full bg-transparent border-none focus:ring-0 text-white placeholder-white/20 text-lg font-light tracking-wide outline-none ml-2 ${error ? 'text-red-400' : ''}`}
              autoComplete="off"
              required
              disabled={isLoading}
            />

            <button
              type="submit"
              disabled={isLoading || !url.trim()}
              className="relative ml-4 px-8 py-3 group/btn overflow-hidden rounded-xl border border-white/10 hover:border-cyber-blue/50 transition-all duration-300 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <div className="absolute inset-0 bg-cyber-blue/5 group-hover/btn:bg-cyber-blue/10 transition-colors" />
              <div className="relative flex items-center gap-2">
                {isLoading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-cyber-blue" />
                    <span className="text-xs font-bold tracking-widest uppercase text-cyber-blue">Scanning</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4 text-white/50 group-hover/btn:text-cyber-blue transition-colors" />
                    <span className="text-xs font-bold tracking-widest uppercase text-white/50 group-hover/btn:text-white transition-colors">Analyze</span>
                  </>
                )}
              </div>
            </button>
          </div>
        </div>

        {/* Error Message */}
        {error && (
          <div className="mt-4 px-2 flex items-center gap-2 text-red-400 font-mono text-[10px] uppercase tracking-wider animate-shake">
            <span className="w-1 h-1 rounded-full bg-red-400 animate-pulse" />
            {error}
          </div>
        )}

        {/* Scan Status bar (Only visible when loading) */}
        {isLoading && (
          <div className="mt-4 px-2">
            <div className="flex justify-between text-[10px] font-mono uppercase text-white/40 mb-2">
              <span>Deep Packet Inspection...</span>
              <span className="animate-pulse">Loading Heuristics</span>
            </div>
            <div className="h-[2px] w-full bg-white/5 rounded-full overflow-hidden">
              <div className="h-full bg-cyber-blue animate-[loading_2s_ease-in-out_infinite]" style={{ width: '40%' }} />
            </div>
          </div>
        )}
      </form>

      <style jsx>{`
        @keyframes loading {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(250%); }
        }
      `}</style>
    </div>
  );
}
