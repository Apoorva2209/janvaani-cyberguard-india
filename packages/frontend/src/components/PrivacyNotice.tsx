'use client';

/**
 * PRIVACY NOTICE COMPONENT
 * ============================================================================
 * DPDP Act 2023 Compliance & User Rights Notice:
 * 1. What data is collected & purpose limitation:
 *    - Only the user-submitted suspicious text/URL and uploaded artifacts.
 *    - Used exclusively for threat triage, scam detection, and community safety.
 * 2. Data Retention Period:
 *    - Raw submissions are automatically purged after 24 hours.
 *    - Anonymized threat telemetry (e.g. malicious domain hashes) is retained for defense.
 * 3. Right to Deletion:
 *    - Users can purge their analysis results at any time via a single click.
 * 4. External Processing Disclosure:
 *    - Uses Sandboxed ML engines and optional multilingual translation.
 * 5. Explicit Data Prohibition:
 *    - No Aadhaar, PAN, UPI PIN, OTPs, or phone book contacts are EVER requested or stored.
 * ============================================================================
 */

import React, { useState } from 'react';

export interface PrivacyConsentState {
  allowMlAnalysis: boolean;
  allowTranslation: boolean;
  allowTelemetrySharing: boolean;
}

interface PrivacyNoticeProps {
  onConsentChange?: (consent: PrivacyConsentState) => void;
}

export function PrivacyNotice({ onConsentChange }: PrivacyNoticeProps) {
  const [consent, setConsent] = useState<PrivacyConsentState>({
    allowMlAnalysis: true,
    allowTranslation: true,
    allowTelemetrySharing: false,
  });

  const [expanded, setExpanded] = useState<boolean>(false);

  const handleToggle = (key: keyof PrivacyConsentState) => {
    const updated = { ...consent, [key]: !consent[key] };
    setConsent(updated);
    if (onConsentChange) {
      onConsentChange(updated);
    }
  };

  return (
    <section
      id="privacy"
      aria-labelledby="privacy-heading"
      className="rounded-xl border border-blue-200 bg-blue-50/60 p-5 text-sm text-slate-800 shadow-sm"
    >
      <div className="flex items-start justify-between">
        <div className="flex items-center space-x-2">
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-blue-600 text-xs font-bold text-white">
            i
          </span>
          <h2 id="privacy-heading" className="text-base font-semibold text-blue-950">
            Privacy Notice & Digital Personal Data Protection (DPDP) Act Compliance
          </h2>
        </div>
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="text-xs font-medium text-blue-700 hover:text-blue-900 underline focus:outline-none focus:ring-2 focus:ring-blue-500 rounded px-1"
          aria-expanded={expanded}
        >
          {expanded ? 'Show Less' : 'Read Full Notice'}
        </button>
      </div>

      <p className="mt-2 text-slate-700 leading-relaxed">
        <strong>Your submission is analyzed securely and automatically purged after 24 hours.</strong>{' '}
        CyberGuard India is engineered to protect citizens from fraud while upholding zero-trust data
        privacy principles.
      </p>

      {expanded && (
        <div className="mt-4 space-y-4 border-t border-blue-200/80 pt-4 text-xs text-slate-700">
          <div>
            <h3 className="font-semibold text-slate-900">1. Data Collected & Specific Purpose</h3>
            <p className="mt-1">
              We only collect the suspicious message text, URL, or screenshot you submit for the sole
              purpose of analyzing scam patterns and phishing signatures. We{' '}
              <span className="font-bold text-red-700">NEVER</span> ask for, collect, or store your
              Aadhaar number, PAN, UPI PIN, bank credentials, or phone contact list.
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-slate-900">2. Data Retention & Automatic Purge</h3>
            <p className="mt-1">
              All raw uploaded text and files are permanently purged from our sandboxed storage
              infrastructure within <strong>24 hours</strong>. You also have the right to immediately
              destroy your analysis session using the &quot;Delete Report&quot; button.
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-slate-900">3. Third-Party & AI Model Processing</h3>
            <p className="mt-1">
              Automated classification is performed in sandboxed environments. For non-English messages
              (e.g., Hindi, Tamil, Telugu), text may be routed through private, non-logging translation
              services to identify fraud indicators.
            </p>
          </div>

          <div>
            <h3 className="font-semibold text-slate-900">4. Processing Consents & Controls</h3>
            <div className="mt-2 space-y-2">
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={consent.allowMlAnalysis}
                  onChange={() => handleToggle('allowMlAnalysis')}
                  className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                />
                <span>Allow automated threat scoring and heuristic classification (Required for scan)</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={consent.allowTranslation}
                  onChange={() => handleToggle('allowTranslation')}
                  className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                />
                <span>Allow automated Indian language translation for regional scam analysis</span>
              </label>

              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={consent.allowTelemetrySharing}
                  onChange={() => handleToggle('allowTelemetrySharing')}
                  className="rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                />
                <span>
                  Allow contributing anonymized scam indicator hashes to national threat intelligence feeds
                </span>
              </label>
            </div>
          </div>

          <div>
            <h3 className="font-semibold text-slate-900">5. Incident Reporting & Grievance Officer</h3>
            <p className="mt-1">
              If your financial credentials were compromised, immediately call{' '}
              <a href="tel:1930" className="font-bold underline text-blue-800">
                1930
              </a>{' '}
              or register a formal complaint with the National Cyber Crime Reporting Portal at{' '}
              <a
                href="https://cybercrime.gov.in"
                target="_blank"
                rel="noopener noreferrer"
                className="font-bold underline text-blue-800"
              >
                cybercrime.gov.in
              </a>
              . For privacy inquiries, contact our Data Protection Officer at dpo@cyberguard.gov.in.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}
