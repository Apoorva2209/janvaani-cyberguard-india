import { DeterministicRuleEngine, RuleMatchResult, RuleSeverity } from '../detection/rules.js';

/**
 * Plain-text scam check for feature (button) phones.
 *
 * A user texts a suspicious message to the service number and receives a short
 * verdict back by SMS. Replies stay within one 160-character GSM-7 segment so
 * they display on any handset.
 */

export type FeaturePhoneVerdict = 'DANGER' | 'CAUTION' | 'NO_FLAGS';

export interface FeaturePhoneReply {
  verdict: FeaturePhoneVerdict;
  text: string;
}

const SEVERITY_RANK: Record<RuleSeverity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

const MAX_SMS_LENGTH = 160;
const MAX_INPUT_LENGTH = 2000;
const HELPLINE = 'Cyber fraud? Call 1930 or visit cybercrime.gov.in';

export const HELP_REPLY =
  'JanVaani: text or forward any suspicious SMS/WhatsApp message here and we will tell you if it looks like a scam. ' +
  HELPLINE;

const URL_PATTERN = /\b(?:https?:\/\/|www\.)[^\s<>"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|co|net|org|info|xyz|top|link|cc|app|club|online|site|live)\b[^\s<>"']*/gi;

/** Pulls URL-like tokens out of free text so URL rules can run on them. */
export function extractUrls(text: string): string[] {
  const found = text.match(URL_PATTERN) ?? [];
  return [...new Set(found.map((u) => u.replace(/[.,;:!?)]+$/, '')))].slice(0, 10);
}

function highestSeverity(matches: RuleMatchResult[]): RuleSeverity | null {
  let best: RuleSeverity | null = null;
  for (const m of matches) {
    if (best === null || SEVERITY_RANK[m.severity] > SEVERITY_RANK[best]) {
      best = m.severity;
    }
  }
  return best;
}

/** Keeps replies ASCII (GSM-7 safe) and inside a single SMS segment. */
export function fitToSms(text: string): string {
  const ascii = text.replace(/[^\x20-\x7E]/g, ' ').replace(/\s+/g, ' ').trim();
  return ascii.length <= MAX_SMS_LENGTH ? ascii : `${ascii.slice(0, MAX_SMS_LENGTH - 3).trimEnd()}...`;
}

/** True when the sender is just asking for instructions rather than sending a message to check. */
export function isHelpRequest(body: string): boolean {
  return /^\s*(help|hi|hello|start|info|\?)\s*$/i.test(body) || body.trim().length === 0;
}

export function buildFeaturePhoneReply(
  rawBody: string,
  engine: DeterministicRuleEngine = new DeterministicRuleEngine(),
): FeaturePhoneReply {
  if (isHelpRequest(rawBody)) {
    return { verdict: 'NO_FLAGS', text: fitToSms(HELP_REPLY) };
  }

  const body = rawBody.slice(0, MAX_INPUT_LENGTH);
  const matches = engine.evaluate(body, extractUrls(body));
  const level = highestSeverity(matches);

  if (level === 'CRITICAL' || level === 'HIGH') {
    return {
      verdict: 'DANGER',
      text: fitToSms(
        'DANGER: likely SCAM. Do not click links, pay, or share OTP/PIN/Aadhaar. Call 1930 to report.',
      ),
    };
  }

  if (level === 'MEDIUM' || level === 'LOW') {
    return {
      verdict: 'CAUTION',
      text: fitToSms(
        'CAUTION: this has scam warning signs. Verify with the real company on its official number. Report: 1930',
      ),
    };
  }

  return {
    verdict: 'NO_FLAGS',
    text: fitToSms(
      'No known scam signs found, but this is not proof it is safe. Never share OTP or PIN. Doubt? Call 1930',
    ),
  };
}
