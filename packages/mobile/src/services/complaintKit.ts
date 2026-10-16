import { AnalysisOutcome } from '../types';

/**
 * Builds a ready-to-paste complaint draft for the National Cyber Crime
 * Reporting Portal / 1930 helpline. JanVaani never files on the user's behalf:
 * the portal requires the citizen's own login and OTP, and filing is the
 * citizen's legal act. We prepare the facts; the user submits.
 */

export const OFFICIAL_LINKS = {
  helpline: 'tel:1930',
  cybercrimePortal: 'https://cybercrime.gov.in',
  // DoT Sanchar Saathi "Chakshu" — report suspected fraud calls/SMS/WhatsApp
  chakshu: 'https://sancharsaathi.gov.in/sfc/',
} as const;

export interface ComplaintInput {
  source: string;
  sender?: string;
  receivedAt?: number;
  messageText: string;
  outcome: AnalysisOutcome;
}

function extract(re: RegExp, text: string): string[] {
  return Array.from(new Set(text.match(re) ?? [])).slice(0, 10);
}

export function buildComplaintDraft(input: ComplaintInput): string {
  const { source, sender, receivedAt, messageText, outcome } = input;
  const when = new Date(receivedAt ?? Date.now()).toLocaleString('en-IN');
  const links = extract(/https?:\/\/[^\s]+/gi, messageText);
  const upiIds = extract(/\b[\w.-]{2,}@(?:ok\w+|ybl|ibl|axl|paytm|upi|apl|icici|sbi|hdfcbank|axisbank|kotak|yesbank|fbl)\b/gi, messageText);
  const phones = extract(/(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g, messageText);
  const tactics = outcome.evidenceClues.map((c) => `- ${c.tactic}`).join('\n') || '- (none detected automatically)';

  return [
    'SUSPECTED CYBER FRAUD — INCIDENT DETAILS',
    '(Prepared with JanVaani. Please review and correct before submitting.)',
    '',
    `Channel: ${source}`,
    `Sender / number shown: ${sender?.trim() || 'Not available'}`,
    `Date & time received: ${when}`,
    '',
    'Message received (verbatim):',
    `"""${messageText.trim().slice(0, 1500)}"""`,
    '',
    `Links in message: ${links.length ? links.join(', ') : 'None'}`,
    `UPI IDs in message: ${upiIds.length ? upiIds.join(', ') : 'None'}`,
    `Phone numbers in message: ${phones.length ? phones.join(', ') : 'None'}`,
    '',
    'Warning signs identified (automated, not a finding of fact):',
    tactics,
    '',
    'Did I lose money?  [ ] No   [ ] Yes — Amount: ____  Transaction ID / UTR: ____  Bank: ____',
    '',
    'Note: Sender names and caller IDs can be spoofed; this report does not accuse any specific person.',
  ].join('\n');
}
