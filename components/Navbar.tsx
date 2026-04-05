"use client";

import React, { useState, useEffect } from 'react';
import { Shield, Menu, X, Terminal } from 'lucide-react';
import Link from 'next/link';

const Navbar = () => {
    const [isScrolled, setIsScrolled] = useState(false);
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

    useEffect(() => {
        const handleScroll = () => {
            setIsScrolled(window.scrollY > 20);
        };
        window.addEventListener('scroll', handleScroll);
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    return (
        <nav className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${isScrolled ? 'py-3 bg-black/60 backdrop-blur-xl border-b border-white/5' : 'py-6 bg-transparent'
            }`}>
            <div className="max-w-7xl mx-auto px-6 flex justify-between items-center">
                {/* Logo */}
                <Link href="#home" className="flex items-center gap-3 group" onClick={(e) => {
                    e.preventDefault();
                    document.getElementById('home')?.scrollIntoView({ behavior: 'smooth' });
                }}>
                    <div className="w-10 h-10 bg-cyber-blue shadow-[0_0_20px_rgba(0,240,255,0.3)] flex items-center justify-center rounded-lg group-hover:scale-110 transition-transform">
                        <Shield className="w-6 h-6 text-black" />
                    </div>
                    <div className="flex flex-col">
                        <span className="text-xl font-black tracking-tighter text-white leading-none">PHISHGUARD</span>
                        <span className="text-[8px] font-mono tracking-[0.3em] text-cyber-blue uppercase">Neural Core v2</span>
                    </div>
                </Link>

                {/* Desktop Menu */}
                <div className="hidden md:flex items-center gap-10">
                    <div className="flex items-center gap-8 text-[10px] font-mono tracking-widest text-white/40 uppercase">
                        <Link href="#home" className="hover:text-cyber-blue transition-colors" onClick={(e) => {
                            e.preventDefault();
                            document.getElementById('home')?.scrollIntoView({ behavior: 'smooth' });
                        }}>Home</Link>
                        <Link href="#about" className="hover:text-cyber-blue transition-colors" onClick={(e) => {
                            e.preventDefault();
                            document.getElementById('about')?.scrollIntoView({ behavior: 'smooth' });
                        }}>About</Link>
                        <Link href="#contact" className="hover:text-cyber-blue transition-colors" onClick={(e) => {
                            e.preventDefault();
                            document.getElementById('contact')?.scrollIntoView({ behavior: 'smooth' });
                        }}>Contact</Link>
                    </div>

                    <div className="flex items-center gap-4">
                        <div className="px-4 py-2 border border-white/10 rounded-full bg-white/5 flex items-center gap-2 text-[10px] font-mono tracking-widest text-white/60">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse"></span>
                            STATUS: <span className="text-cyber-green">OPTIMAL</span>
                        </div>
                    </div>
                </div>

                {/* Mobile Toggle */}
                <button
                    className="md:hidden text-white p-2"
                    onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                >
                    {isMobileMenuOpen ? <X /> : <Menu />}
                </button>
            </div>

            {/* Mobile Menu */}
            {isMobileMenuOpen && (
                <div className="md:hidden absolute top-full left-0 right-0 bg-black/95 backdrop-blur-2xl border-b border-white/10 p-8 flex flex-col gap-6 animate-in slide-in-from-top duration-300">
                    <Link href="#home" className="text-lg font-mono tracking-widest text-white/60 uppercase" onClick={(e) => {
                        e.preventDefault();
                        setIsMobileMenuOpen(false);
                        document.getElementById('home')?.scrollIntoView({ behavior: 'smooth' });
                    }}>Home</Link>
                    <Link href="#about" className="text-lg font-mono tracking-widest text-white/60 uppercase" onClick={(e) => {
                        e.preventDefault();
                        setIsMobileMenuOpen(false);
                        document.getElementById('about')?.scrollIntoView({ behavior: 'smooth' });
                    }}>About</Link>
                    <Link href="#contact" className="text-lg font-mono tracking-widest text-white/60 uppercase" onClick={(e) => {
                        e.preventDefault();
                        setIsMobileMenuOpen(false);
                        document.getElementById('contact')?.scrollIntoView({ behavior: 'smooth' });
                    }}>Contact</Link>
                    <hr className="border-white/5" />
                    <div className="flex flex-col gap-4">
                        <div className="px-4 py-3 border border-white/10 rounded-xl bg-white/5 flex items-center gap-2 text-xs font-mono tracking-widest text-white/60">
                            <span className="w-2 h-2 rounded-full bg-cyber-green animate-pulse"></span>
                            SYSTEM STATUS: OPTIMAL
                        </div>
                    </div>
                </div>
            )}
        </nav>
    );
};

export default Navbar;
