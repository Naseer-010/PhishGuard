import type { Metadata } from "next";
import { Inter, Space_Grotesk } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const spaceGrotesk = Space_Grotesk({ subsets: ["latin"], variable: "--font-space-grotesk" });

export const metadata: Metadata = {
  title: "PhishGuard | AI Phishing Detection",
  description: "Real-time AI/ML-driven phishing detection and prevention platform.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${spaceGrotesk.variable}`} suppressHydrationWarning>
      <body className="antialiased font-sans" suppressHydrationWarning>
        <div className="fixed inset-0 -z-10 cyber-grid" />
        <div className="absolute inset-0 -z-20 bg-black" />
        {children}
      </body>
    </html>
  );
}
