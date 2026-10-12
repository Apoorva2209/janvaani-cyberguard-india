'use client';

/**
 * REPORT RESULT DISPLAY COMPONENT
 * ============================================================================
 * Security & Accuracy Rationale:
 * 1. Confidence Classification: High, Medium, Low confidence scores.
 * 2. Visual Separation:
 *    - Distinct visual cards for 'Risk Indicators' vs 'External Source Matches' vs 'Human-Reviewed Findings'.
 * 3. Privacy & Defamation Safeguard:
 *    - Never outputs raw citizen names, personal mobile numbers, or accusatory language.
 * 4. Transparent Provenance:
 *    - Displays model/engine name, execution timestamp, detected source language, and limitations.
 *    - Machine-translated content is prominently marked as machine-translated.
 * 5. Mandatory Advisory & Disclaimer:
 *    - Prominent legal notice: 'This is an automated analysis, not legal proof. Report to authorities if you suspect fraud.'
 * 6. Right to Erasure:
 *    - Instant 'Purge Analysis Data' button that destroys the local state and triggers server-side deletion.
 * ============================================================================
 */

import React from 'react';
import { sanitizeExternalUrl } from '../lib/security';

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW';

export interface ExternalSourceMatch {
  title: string;
  url: string;
  source: string;
  retrievalTimestamp: string;
  publicationDate?: string;
  summary: string;
}

export interface AnalysisReport {
  id: string;
  confidence: ConfidenceLevel;
  riskScore: number; // 0 - 100
  modelName: string;
  analyzedAt: string;
  detectedLanguage: string;
  isMachineTranslated: boolean;
  limitations: string[];
  riskIndicators: Array<{
    category: string;
    description: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  }>;
  externalMatches: ExternalSourceMatch[];
  humanReviewedFindings?: Array<{
    analystId: string;
    verifiedAt: string;
    notes: string;
  }>;
}

interface ReportResultProps {
  report: AnalysisReport;
  onDeleteReport: (id: string) => void;
}

export function ReportResult({ report, onDeleteReport }: ReportResultProps) {
  const getBadgeColor = (confidence: ConfidenceLevel) => {
    switch (confidence) {
      case 'HIGH':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'LOW':
        return 'bg-green-100 text-green-800 border-green-300';
      default:
        return 'bg-slate-100 text-slate-800 border-slate-300';
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-700 text-white';
      case 'HIGH':
        return 'bg-rose-500 text-white';
      case 'MEDIUM':
        return 'bg-amber-500 text-white';
      default:
        return 'bg-slate-500 text-white';
    }
  };

  return (
    <div className="space-y-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      {/* Top Banner / Risk Overview */}
      <div className="flex flex-col gap-4 border-b border-slate-200 pb-5 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center space-x-3">
            <h3 className="text-xl font-bold text-slate-900">Analysis Summary</h3>
            <span
              className={`rounded-full border px-3 py-1 text-xs font-bold uppercase tracking-wider ${getBadgeColor(
                report.confidence
              )}`}
            >
              {report.confidence} Risk Confidence
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Report ID: <code className="font-mono text-slate-700">{report.id}</code> | Timestamp:{' '}
            {new Date(report.analyzedAt).toLocaleString('en-IN')}
          </p>
        </div>

        <button
          type="button"
          onClick={() => onDeleteReport(report.id)}
          className="inline-flex items-center rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-semibold text-red-700 hover:bg-red-100 hover:text-red-800 focus:outline-none focus:ring-2 focus:ring-red-500"
          aria-label="Permanently delete this report from server"
        >
          🗑 Purge Analysis Data
        </button>
      </div>

      {/* Model & Language Metadata */}
      <div className="rounded-lg bg-slate-50 p-3 text-xs text-slate-600">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <div>
            <span className="font-semibold text-slate-700">Engine: </span>
            <span>{report.modelName}</span>
          </div>
          <div>
            <span className="font-semibold text-slate-700">Language: </span>
            <span className="uppercase">{report.detectedLanguage}</span>
          </div>
          <div>
            <span className="font-semibold text-slate-700">Translation: </span>
            <span>
              {report.isMachineTranslated ? (
                <span className="rounded bg-amber-100 px-1.5 py-0.5 font-bold text-amber-800">
                  Machine-Translated
                </span>
              ) : (
                'Original Text'
              )}
            </span>
          </div>
          <div>
            <span className="font-semibold text-slate-700">Heuristic Score: </span>
            <span className="font-bold text-slate-800">{report.riskScore} / 100</span>
          </div>
        </div>
      </div>

      {/* Mandatory Regulatory & Legal Disclaimer */}
      <div className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-xs text-amber-900">
        <p className="font-bold">⚠️ Important Public Advisory:</p>
        <p className="mt-1">
          This is an automated threat intelligence triage assessment, not legal or definitive forensic
          proof. Scammers constantly evolve tactics. If you have transferred money or suspect fraud,
          immediately dial <strong>1930</strong> (National Cyber Financial Fraud Helpline) and register
          a complaint on{' '}
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noopener noreferrer"
            className="font-bold underline"
          >
            cybercrime.gov.in
          </a>
          .
        </p>
      </div>

      {/* Section 1: Detected Risk Indicators */}
      <div className="space-y-3">
        <h4 className="text-sm font-bold uppercase tracking-wider text-slate-700">
          Detected Risk Indicators
        </h4>
        {report.riskIndicators.length === 0 ? (
          <p className="text-xs text-slate-500 italic">No suspicious indicators identified.</p>
        ) : (
          <ul className="space-y-2">
            {report.riskIndicators.map((ind, idx) => (
              <li
                key={idx}
                className="flex items-start justify-between rounded-lg border border-slate-200 bg-white p-3 text-xs"
              >
                <div>
                  <span className="font-semibold text-slate-800">{ind.category}: </span>
                  <span className="text-slate-600">{ind.description}</span>
                </div>
                <span
                  className={`ml-2 inline-block rounded px-2 py-0.5 text-[10px] font-bold ${getSeverityBadge(
                    ind.severity
                  )}`}
                >
                  {ind.severity}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Section 2: External Threat Matches */}
      <div className="space-y-3">
        <h4 className="text-sm font-bold uppercase tracking-wider text-slate-700">
          External Source Matches & Advisory Intelligence
        </h4>
        {report.externalMatches.length === 0 ? (
          <p className="text-xs text-slate-500 italic">
            No matching public threat feeds or registered scam advisories found for this pattern.
          </p>
        ) : (
          <div className="space-y-3">
            {report.externalMatches.map((match, idx) => {
              const safeLink = sanitizeExternalUrl(match.url);
              return (
                <div key={idx} className="rounded-lg border border-slate-200 bg-slate-50/50 p-3 text-xs">
                  <div className="flex items-center justify-between">
                    <p className="font-semibold text-slate-800">{match.title}</p>
                    <span className="text-[10px] text-slate-400">
                      Retrieved: {new Date(match.retrievalTimestamp).toLocaleDateString('en-IN')}
                    </span>
                  </div>
                  <p className="mt-1 text-slate-600 leading-relaxed">{match.summary}</p>
                  <div className="mt-2 flex items-center justify-between text-[11px]">
                    <span className="text-slate-500">Source: {match.source}</span>
                    {safeLink && (
                      <a
                        href={safeLink}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-indigo-600 font-medium hover:underline"
                      >
                        Read Advisory ↗
                      </a>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Section 3: Human-Reviewed Findings (if applicable) */}
      {report.humanReviewedFindings && report.humanReviewedFindings.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-bold uppercase tracking-wider text-indigo-900">
            Human-Reviewed Finding
          </h4>
          <div className="rounded-lg border border-indigo-200 bg-indigo-50/40 p-4 text-xs text-indigo-950">
            {report.humanReviewedFindings.map((finding, idx) => (
              <div key={idx}>
                <p className="font-semibold">Verified by Security Analyst #{finding.analystId}</p>
                <p className="mt-1 text-slate-700">{finding.notes}</p>
                <p className="mt-2 text-[10px] text-slate-400">
                  Reviewed on {new Date(finding.verifiedAt).toLocaleString('en-IN')}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Limitations note */}
      {report.limitations.length > 0 && (
        <div className="rounded-lg bg-slate-100 p-3 text-[11px] text-slate-600">
          <p className="font-semibold text-slate-700">Analysis Limitations:</p>
          <ul className="mt-1 list-disc pl-4 space-y-0.5">
            {report.limitations.map((lim, idx) => (
              <li key={idx}>{lim}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
