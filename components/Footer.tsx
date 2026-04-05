"use client";

import React from 'react';
import { Shield, Github, Twitter, Linkedin, Terminal } from 'lucide-react';
import Link from 'next/link';

const Footer = () => {
    return (
        <footer className="w-full bg-black border-t border-white/5 pt-20 pb-10 px-6 overflow-hidden relative">
            {/* Background Decor */}
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-1/2 h-[1px] bg-gradient-to-r from-transparent via-cyber-blue/20 to-transparent" />

            <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-12 mb-20">
                {/* Brand Column */}
                <div className="md:col-span-2 space-y-6">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 bg-cyber-blue/20 border border-cyber-blue/30 flex items-center justify-center rounded-lg">
                            <Shield className="w-5 h-5 text-cyber-blue" />
                        </div>
                        <span className="text-xl font-black tracking-tighter text-white">PHISHGUARD</span>
                    </div>
                    <p className="text-white/40 text-sm font-light max-w-sm leading-relaxed">
                        Advanced neural-heuristic phishing detection platform. Securing the modern web with real-time ML forensic analysis.
                    </p>
                    <div className="flex items-center gap-4">
                        <a href="#" className="w-10 h-10 rounded-full bg-white/5 border border-white/10 flex items-center justify-center hover:bg-cyber-blue/10 hover:border-cyber-blue/30 transition-all text-white/40 hover:text-cyber-blue">
                            <Github className="w-4 h-4" />
                        </a>
                        <a href="#" className="w-10 h-10 rounded-full bg-white/5 border border-white/10 flex items-center justify-center hover:bg-cyber-blue/10 hover:border-cyber-blue/30 transition-all text-white/40 hover:text-cyber-blue">
                            <Twitter className="w-4 h-4" />
                        </a>
                        <a href="#" className="w-10 h-10 rounded-full bg-white/5 border border-white/10 flex items-center justify-center hover:bg-cyber-blue/10 hover:border-cyber-blue/30 transition-all text-white/40 hover:text-cyber-blue">
                            <Linkedin className="w-4 h-4" />
                        </a>
                    </div>
                </div>

                {/* Links Column 1 */}
                <div className="space-y-6">
                    <h4 className="text-[10px] font-mono tracking-[0.3em] text-white/30 uppercase">Technology</h4>
                    <ul className="space-y-4 text-xs font-mono tracking-widest text-white/60">
                        <li><Link href="#" className="hover:text-cyber-blue transition-colors">Neural Engine</Link></li>
                        <li><Link href="#" className="hover:text-cyber-blue transition-colors">Heuristic Core</Link></li>
                        <li><Link href="#" className="hover:text-cyber-blue transition-colors">API Docs</Link></li>
                        <li><Link href="#" className="hover:text-cyber-blue transition-colors">Forensics</Link></li>
                    </ul>
                </div>

                {/* Links Column 2 */}
                <div className="space-y-6">
                    <h4 className="text-[10px] font-mono tracking-[0.3em] text-white/30 uppercase">Legal</h4>
                    <ul className="space-y-4 text-xs font-mono tracking-widest text-white/60">
                        <li><Link href="#" className="hover:text-cyber-blue transition-colors">Privacy Policy</Link></li>
                        <li><Link href="#" className="hover:text-cyber-blue transition-colors">Sec Protocol</Link></li>
                        <li><Link href="#" className="hover:text-cyber-blue transition-colors">Contact</Link></li>
                    </ul>
                </div>
            </div>

            <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center pt-10 border-t border-white/5 gap-6">
                <div className="text-[10px] font-mono tracking-widest text-white/20 uppercase flex items-center gap-2">
                    <Terminal className="w-3 h-3" />
                    © 2026 PHISHGUARD | SIH25159 SECURE PROTOCOL
                </div>
                <div className="px-4 py-1 rounded-full bg-white/5 border border-white/10 text-[9px] font-mono tracking-widest text-white/40 uppercase">
                    Latency: <span className="text-cyber-green">12ms</span>
                </div>
            </div>
        </footer>
    );
};

export default Footer;
