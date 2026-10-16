/**
 * What a sender ID can and cannot tell you.
 *
 * JanVaani cannot name the real person or organisation behind a message: numbers and
 * names are easy to fake. It only reads the *kind* of sender ID, which is a useful clue
 * (for example, a bank that texts from an ordinary mobile number is a red flag).
 */

export type SenderKind =
  | 'business-header'
  | 'indian-mobile'
  | 'international'
  | 'short-code'
  | 'email'
  | 'name-only'
  | 'unknown';

export interface SenderProfile {
  kind: SenderKind;
  label: string;
  note: string;
  /** True when the kind of sender ID is itself a warning sign for this kind of message. */
  suspicious: boolean;
}

const OFFICIAL_TOPICS = /\b(bank|kyc|account|aadhaar|pan|upi|card|loan|police|court|customs|income\s*tax|electricity|parcel|courier|refund)\b/i;

export const SENDER_DISCLAIMER =
  'JanVaani cannot tell who the person really is. Phone numbers and sender names can be faked.';

export function profileSender(rawSender: string | undefined, messageText = ''): SenderProfile {
  const sender = (rawSender ?? '').trim();
  const digits = sender.replace(/[\s()-]/g, '');
  const aboutOfficialTopic = OFFICIAL_TOPICS.test(messageText);

  if (!sender) {
    return {
      kind: 'unknown',
      label: 'Unknown sender',
      note: 'No sender ID was available for this message.',
      suspicious: false,
    };
  }

  if (/^[A-Za-z0-9]{2}-[A-Za-z0-9]{3,8}$/.test(sender) || (/^[A-Za-z][A-Za-z0-9]{3,10}$/.test(sender) && !/^\d+$/.test(sender))) {
    return {
      kind: 'business-header',
      label: 'Business sender ID',
      note: 'Registered businesses send texts under names like AX-HDFCBK. Fraudsters can imitate these names, so check the message, not just the name.',
      suspicious: false,
    };
  }

  if (/^\+?91[6-9]\d{9}$/.test(digits) || /^[6-9]\d{9}$/.test(digits)) {
    return {
      kind: 'indian-mobile',
      label: 'Ordinary Indian mobile number',
      note: aboutOfficialTopic
        ? 'Banks, government offices and courier companies do not message from personal mobile numbers. This is a strong warning sign.'
        : 'This is a personal mobile number, so there is no way to confirm who it belongs to.',
      suspicious: aboutOfficialTopic,
    };
  }

  if (/^\+\d{7,15}$/.test(digits) && !/^\+91/.test(digits)) {
    return {
      kind: 'international',
      label: 'International number',
      note: 'Messages from abroad claiming to be an Indian bank, office or delivery firm are a common scam pattern.',
      suspicious: aboutOfficialTopic,
    };
  }

  if (/^\d{3,6}$/.test(digits)) {
    return {
      kind: 'short-code',
      label: 'Short code',
      note: 'Short codes are used by service providers but can also be misused. Do not reply with personal details.',
      suspicious: false,
    };
  }

  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sender)) {
    return {
      kind: 'email',
      label: 'Email address',
      note: 'Check the part after the @ carefully. Lookalike domains such as sbi-support.xyz are a common trick.',
      suspicious: false,
    };
  }

  return {
    kind: 'name-only',
    label: 'Display name only',
    note: 'A display name can be set to anything and proves nothing about who sent the message.',
    suspicious: false,
  };
}
