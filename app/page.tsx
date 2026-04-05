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
        <main id="home" className="min-h-screen relative overflow-hidden pt-32 pb-32">
            {/* Background elements */}
            <div className="fixed inset-0 cyber-grid -z-10" />
            <div className="fixed top-1/4 left-1/4 w-[500px] h-[500px] bg-cyber-blue/10 rounded-full blur-[120px] -z-20" />
            <div className="fixed bottom-1/4 right-1/4 w-[500px] h-[500px] bg-cyber-purple/10 rounded-full blur-[120px] -z-20" />

            <div className="max-w-7xl mx-auto px-6 z-10 relative">
                {/* Hero Section */}
                <section className="text-center mb-32 space-y-8 animate-in fade-in slide-in-from-bottom-8 duration-1000">
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 text-[10px] font-mono uppercase tracking-[0.3em] text-cyber-blue mb-4">
                        <Terminal className="w-4 h-4 text-cyber-green animate-pulse" />
                        Neural Core v2.4 Status: Active
                    </div>
                    <h1 className="text-6xl md:text-9xl font-black tracking-tighter text-white leading-[0.85] mb-8">
                        Deep Neural <br />
                        <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-blue via-white to-cyber-green">Detection.</span>
                    </h1>
                    <p className="text-lg md:text-xl text-white/40 max-w-3xl mx-auto font-light leading-relaxed tracking-wide">
                        Next-generation phishing defense using real-time heuristic mapping and
                        AI-driven forensic analysis. Built to intercept threats before they reach your data.
                    </p>
                </section>

                {/* Input UI */}
                <section className="mb-40 relative group">
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-[300px] bg-cyber-blue/5 blur-[100px] rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-1000" />
                    <UrlInput onAnalyze={handleAnalyze} isLoading={isLoading} />
                </section>

                {/* About Section */}
                <section id="about" className="mb-40 scroll-mt-32">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-20 items-center">
                        <div className="space-y-8">
                            <h2 className="text-4xl md:text-5xl font-black tracking-tighter text-white uppercase">
                                What is <br /><span className="text-cyber-blue">PhishGuard?</span>
                            </h2>
                            <p className="text-white/60 leading-relaxed font-light text-lg">
                                PhishGuard is a high-performance security ecosystem designed to provide instant protection against evolving phishing threats.
                                Using a combination of **Deep Learning heuristics** and **Real-Time Forensic Data**, we scan every interaction to ensure your credentials never fall into the wrong hands.
                            </p>
                            <ul className="space-y-4">
                                {['ML-Driven Heuristics', 'Pre-Navigation Interception', 'Hover Scan Intelligence', 'Neural Thread Analysis'].map((item, i) => (
                                    <li key={i} className="flex items-center gap-3 text-xs font-mono tracking-widest text-white/40">
                                        <span className="w-1.5 h-1.5 rounded-full bg-cyber-blue shadow-[0_0_10px_#00f0ff]" />
                                        {item}
                                    </li>
                                ))}
                            </ul>
                        </div>
                        <div className="relative">
                            <div className="absolute inset-0 bg-cyber-blue/20 blur-[100px] rounded-full" />
                            <div className="relative glass-morphism rounded-3xl p-8 border-white/10 aspect-square flex items-center justify-center overflow-hidden">
                                <Shield className="w-32 h-32 text-cyber-blue animate-pulse" />
                                <div className="absolute bottom-0 left-0 right-0 p-6 bg-gradient-to-t from-black/80 to-transparent">
                                    <div className="text-[10px] font-mono text-cyber-green tracking-widest uppercase">Encryption Active: SIH25159</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Error State */}
                {error && (
                    <div className="max-w-md mx-auto p-4 mb-20 glass-morphism border-cyber-red/30 rounded-2xl flex items-center gap-4 text-cyber-red animate-shake">
                        <ShieldAlert className="w-6 h-6 shrink-0" />
                        <p className="text-xs font-mono uppercase tracking-widest">{error}</p>
                    </div>
                )}

                {/* Dynamic Content */}
                <section className="mb-40">
                    {analysis ? (
                        <DetailedAnalysisResult result={analysis} />
                    ) : !isLoading && (
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
                            <FeatureCard
                                icon={<Globe className="w-6 h-6 text-cyber-blue" />}
                                title="Global Reputation"
                                description="Cross-referencing telemetry with known malicious domain clusters and zero-day threat feeds."
                            />
                            <FeatureCard
                                icon={<Cpu className="w-6 h-6 text-cyber-green" />}
                                title="Structural Analysis"
                                description="Deep inspection of HTML attribute distribution, CSS anomalies, and JS obfuscation patterns."
                            />
                            <FeatureCard
                                icon={<Lock className="w-6 h-6 text-cyber-purple" />}
                                title="Identity Guard"
                                description="Identifying credential harvesting attempts via visual similarity and structural brand spoofing."
                            />
                        </div>
                    )}
                </section>

                {/* Contact Section */}
                <section id="contact" className="mb-20 scroll-mt-32 max-w-4xl mx-auto">
                    <div className="text-center mb-16">
                        <h2 className="text-4xl font-black tracking-tighter text-white uppercase mb-4">Contact the <span className="text-cyber-green">Core</span></h2>
                        <p className="text-white/40 text-sm font-light">Have technical inquiries or need bespoke security deployment?</p>
                    </div>
                    <ContactForm />
                </section>
            </div>

            {/* Background Branding Decor */}
            <div className="fixed bottom-1/4 left-0 text-white/[0.02] font-black text-[20vw] -rotate-90 select-none pointer-events-none uppercase leading-none opacity-20">
                SECURE
            </div>
            <div className="fixed top-1/4 right-0 text-white/[0.02] font-black text-[20vw] rotate-90 select-none pointer-events-none uppercase leading-none opacity-20">
                AI
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

function ContactForm() {
    const [isSending, setIsSending] = useState(false);
    const [status, setStatus] = useState<{ type: 'success' | 'error', msg: string } | null>(null);

    const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        setIsSending(true);
        setStatus(null);

        const formData = new FormData(e.currentTarget);
        const data = {
            name: formData.get('name'),
            email: formData.get('email'),
            message: formData.get('message'),
        };

        try {
            const response = await fetch('/api/contact', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data),
            });

            if (!response.ok) throw new Error('Transmission failed.');

            setStatus({ type: 'success', msg: 'Core Link Established: Message transmitted.' });
            (e.target as HTMLFormElement).reset();
        } catch (err) {
            setStatus({ type: 'error', msg: 'Signal Failure: Unable to reach relay server.' });
        } finally {
            setIsSending(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6 glass-morphism p-10 rounded-3xl border-white/5 relative overflow-hidden">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                    <label className="text-[10px] font-mono uppercase tracking-widest text-white/30 ml-2">Initials / Name</label>
                    <input
                        name="name"
                        placeholder="OPERATOR NAME"
                        required
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-4 text-white placeholder-white/20 outline-none focus:border-cyber-blue/50 transition-all"
                    />
                </div>
                <div className="space-y-2">
                    <label className="text-[10px] font-mono uppercase tracking-widest text-white/30 ml-2">Return Address / Email</label>
                    <input
                        type="email"
                        name="email"
                        placeholder="SECURE EMAIL"
                        required
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-4 text-white placeholder-white/20 outline-none focus:border-cyber-blue/50 transition-all"
                    />
                </div>
            </div>
            <div className="space-y-2">
                <label className="text-[10px] font-mono uppercase tracking-widest text-white/30 ml-2">Encrypted Message</label>
                <textarea
                    name="message"
                    placeholder="TRANSMIT DATA..."
                    required
                    rows={5}
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-5 py-4 text-white placeholder-white/20 outline-none focus:border-cyber-blue/50 transition-all resize-none"
                />
            </div>

            {status && (
                <div className={`p-4 rounded-xl text-xs font-mono uppercase tracking-widest flex items-center gap-3 ${status.type === 'success' ? 'bg-cyber-green/10 text-cyber-green border border-cyber-green/20' : 'bg-cyber-red/10 text-cyber-red border border-cyber-red/20'
                    }`}>
                    <div className={`w-2 h-2 rounded-full animate-pulse ${status.type === 'success' ? 'bg-cyber-green' : 'bg-cyber-red'}`} />
                    {status.msg}
                </div>
            )}

            <button
                type="submit"
                disabled={isSending}
                className="w-full py-5 bg-white text-black font-black uppercase text-xs tracking-[0.3em] rounded-xl hover:bg-cyber-blue hover:text-white transition-all disabled:opacity-50"
            >
                {isSending ? 'TRANSMITTING...' : 'INITIATE TRANSMISSION'}
            </button>
        </form>
    );
}
