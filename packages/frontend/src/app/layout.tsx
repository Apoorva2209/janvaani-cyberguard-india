import type { Metadata, Viewport } from 'next';
import { headers } from 'next/headers';
import React from 'react';
import './globals.css';

export const metadata: Metadata = {
  title: 'CyberGuard India — Sovereign Cyber Threat Verification & Fraud Shield',
  description:
    'Free, privacy-first cybersecurity verification platform for Indian citizens. Analyze suspicious SMS, WhatsApp forwards, phishing domains, fake APKs, UPI scams, and digital arrest extortion.',
  robots: {
    index: true,
    follow: true,
  },
  icons: {
    icon: '/favicon.ico',
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const headersList = await headers();
  const nonce = headersList.get('x-nonce') || '';

  return (
    <html lang="en" dir="ltr" className="h-full bg-[#0a0e17] text-slate-100 antialiased">
      <head>
        <meta charSet="utf-8" />
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        <meta httpEquiv="X-Frame-Options" content="DENY" />
        <meta name="csp-nonce" content={nonce} />
      </head>
      <body className="flex min-h-full flex-col font-sans bg-[#0a0e17] text-slate-100">
        {/* Subtle Indian National Tri-Color Accent Line */}
        <div className="h-1 w-full bg-gradient-to-r from-orange-500 via-white to-emerald-500 opacity-90"></div>

        {/* Top Emergency Advisory Bar */}
        <div className="bg-gradient-to-r from-red-950/80 via-rose-900/60 to-red-950/80 border-b border-rose-800/40 px-4 py-2 text-center text-xs text-rose-200">
          <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-center gap-x-4 gap-y-1">
            <span className="flex items-center gap-1.5 font-semibold text-rose-300">
              <span className="w-2 h-2 rounded-full bg-red-500 animate-ping"></span>
              National Cyber Financial Fraud Immediate Action:
            </span>
            <span className="text-slate-300">
              Lost money to scam? Call <a href="tel:1930" className="text-white font-extrabold underline hover:text-rose-300">1930</a> within the Golden Hour or report at{' '}
              <a href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer" className="text-white font-extrabold underline hover:text-rose-300">
                cybercrime.gov.in ↗
              </a>
            </span>
          </div>
        </div>

        {/* Main Content Area */}
        <main className="flex-1 w-full">
          {children}
        </main>

        {/* Global Footer */}
        <footer className="border-t border-slate-800/80 bg-[#070a10] py-8 text-xs text-slate-400">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-bold text-sm">
                  🛡️
                </div>
                <div>
                  <div className="font-bold text-slate-200">CyberGuard India</div>
                  <div className="text-[11px] text-slate-500">Citizen Threat Verification & Fraud Prevention Platform</div>
                </div>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-6 text-[11px] text-slate-400">
                <span>DPDP Act 2023 Compliant</span>
                <span>•</span>
                <span>NIST CSF 2.0 Aligned</span>
                <span>•</span>
                <span>OWASP API Security</span>
                <span>•</span>
                <span>Zero Citizen Profiling</span>
              </div>
              <div className="text-[11px] text-slate-500">
                © 2026 CyberGuard India. Open Public Security Initiative.
              </div>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
