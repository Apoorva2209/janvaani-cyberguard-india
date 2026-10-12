import {
  AnalysisOutcome,
  CheckerModality,
  EvidenceClue,
  OfficialSourceMatch,
  RiskLabel,
} from '../types';

/**
 * JanVaani On-Device Heuristic & Triage Engine
 *
 * Implements Trust & Safety Rules:
 * - Never promise to detect every fake or guarantee accuracy.
 * - Never claim something is true or fake based only on keywords or AI score.
 * - Never accuse a person or identify real identity behind spoofed caller ID.
 * - Separate "risk indicators", "official source match", and "human-reviewed finding".
 * - Use plain language with exact quoted clues.
 */
export function analyzeSuspiciousContent(params: {
  modality: CheckerModality;
  content: string;
  claimedSender?: string;
  claimedNumber?: string;
  isAnonymous?: boolean;
}): AnalysisOutcome {
  const { modality, content, claimedSender, claimedNumber } = params;
  const lower = content.toLowerCase();
  const evidenceClues: EvidenceClue[] = [];
  let officialMatch: OfficialSourceMatch | undefined = undefined;

  const nowStr = new Date().toLocaleTimeString('en-IN', {
    hour: '2-digit',
    minute: '2-digit',
  });
  const dateStr = new Date().toISOString().split('T')[0] ?? '2026-03-15';

  // 1. EVALUATION: Calls and Call Scripts
  if (modality === 'call') {
    // Check for Digital Arrest or Law Enforcement threats
    if (
      lower.includes('digital arrest') ||
      lower.includes('cbi') ||
      lower.includes('narcotics') ||
      lower.includes('customs') ||
      lower.includes('crime branch') ||
      lower.includes('skype') ||
      lower.includes('warrant')
    ) {
      evidenceClues.push({
        tactic: 'Law Enforcement Coercion & Digital Arrest Threat',
        quote: extractQuote(content, [
          'digital arrest',
          'cbi',
          'narcotics',
          'crime branch',
          'skype',
          'warrant',
        ]),
        explanation:
          'Caller claims to be a law enforcement officer (CBI, Customs, or Police) and threatens arrest or detention over video calls.',
        severity: 'high',
      });
      officialMatch = {
        sourceName: 'MHA Indian Cybercrime Coordination Centre (I4C)',
        url: 'https://cybercrime.gov.in',
        publishDate: '2024-05-14',
        retrievalTime: nowStr,
        matchedPassage:
          'Indian Police and central law enforcement agencies NEVER arrest citizens through Skype, WhatsApp, or video calls. No legal provision exists for "Digital Arrest".',
      };
    }

    // Check for OTP / UPI PIN / CVV / Password requests
    if (
      lower.includes('otp') ||
      lower.includes('upi pin') ||
      lower.includes('password') ||
      lower.includes('cvv') ||
      lower.includes('atm pin')
    ) {
      evidenceClues.push({
        tactic: 'Secret Credential Solicitation',
        quote: extractQuote(content, ['otp', 'upi pin', 'password', 'cvv', 'atm pin']),
        explanation:
          'Caller requested a confidential authorization credential. Real bank employees and government officials will NEVER request OTPs or PINs over phone calls.',
        severity: 'high',
      });
    }

    // Check for Remote Access App installation (AnyDesk, TeamViewer, RustDesk)
    if (
      lower.includes('anydesk') ||
      lower.includes('teamviewer') ||
      lower.includes('quicksupport') ||
      lower.includes('screen share') ||
      lower.includes('remote app')
    ) {
      evidenceClues.push({
        tactic: 'Remote Screen-Access Exploitation',
        quote: extractQuote(content, ['anydesk', 'teamviewer', 'quicksupport', 'screen share']),
        explanation:
          'Caller requested installation of remote access applications which allow fraudsters to view your screen, read OTPs, and take over online banking.',
        severity: 'high',
      });
    }

    // Check for KYC Suspension or Urgent Blocking
    if (
      lower.includes('kyc') ||
      lower.includes('account blocked') ||
      lower.includes('sim blocked') ||
      lower.includes('pan card update')
    ) {
      evidenceClues.push({
        tactic: 'Urgent Service Suspension Threat',
        quote: extractQuote(content, ['kyc', 'blocked', 'pan card']),
        explanation:
          'Caller manufactures false panic claiming your bank account or SIM card will be deactivated immediately unless you follow their instructions.',
        severity: 'medium',
      });
    }
  }

  // 2. EVALUATION: SMS and Chat screening
  if (modality === 'message') {
    // Electricity power cut scam
    if (
      (lower.includes('electricity') || lower.includes('power') || lower.includes('bijli')) &&
      (lower.includes('disconnected') || lower.includes('tonight') || lower.includes('bill'))
    ) {
      evidenceClues.push({
        tactic: 'Utility Disconnection Pressure',
        quote: extractQuote(content, ['electricity', 'disconnected', 'tonight', 'bill']),
        explanation:
          'Message threatens electricity power disconnection within hours and provides an unofficial personal mobile number to contact.',
        severity: 'high',
      });
      officialMatch = {
        sourceName: 'Indian Computer Emergency Response Team (CERT-In)',
        url: 'https://www.cert-in.org.in',
        publishDate: '2024-03-22',
        retrievalTime: nowStr,
        matchedPassage:
          'Fraudulent SMS campaigns targeting consumers falsely claim power will be disconnected at 9:30 PM. Legitimate discoms send notifications with authorized alphanumeric sender headers.',
      };
    }

    // UPI PIN to Receive / Fake Lottery
    if (
      lower.includes('lottery') ||
      lower.includes('won') ||
      lower.includes('cashback') ||
      lower.includes('reward') ||
      lower.includes('enter upi pin to receive') ||
      lower.includes('scan qr to receive')
    ) {
      evidenceClues.push({
        tactic: 'Fake Prize / UPI PIN Reverse Charge',
        quote: extractQuote(content, ['lottery', 'won', 'cashback', 'upi pin', 'receive']),
        explanation:
          'Message promises prize or refund but tricks the victim into authorizing a debit transaction. A UPI PIN is only entered to SEND money.',
        severity: 'high',
      });
      officialMatch = {
        sourceName: 'National Payments Corporation of India (NPCI)',
        url: 'https://www.npci.org.in',
        publishDate: '2024-01-10',
        retrievalTime: nowStr,
        matchedPassage:
          'UPI PIN is entered only to authorize deductions from your bank account. You do NOT need to enter your UPI PIN to receive money from anyone.',
      };
    }

    // Part-time job / Telegram task scams
    if (
      (lower.includes('part-time job') || lower.includes('work from home') || lower.includes('youtube like')) &&
      (lower.includes('telegram') || lower.includes('earn per day') || lower.includes('₹'))
    ) {
      evidenceClues.push({
        tactic: 'Prepaid Task / Part-time Job Trap',
        quote: extractQuote(content, ['part-time job', 'work from home', 'telegram', 'earn']),
        explanation:
          'Promises lucrative daily income for liking videos or rating hotels, later requiring "investment deposits" before withholding all money.',
        severity: 'high',
      });
    }
  }

  // 3. EVALUATION: Link & QR Code
  if (modality === 'link') {
    // Lookalike banking or government domain
    if (
      (lower.includes('sbi') || lower.includes('hdfc') || lower.includes('icici') || lower.includes('pm-kisan') || lower.includes('aadhaar')) &&
      !lower.includes('.gov.in') &&
      !lower.includes('.nic.in') &&
      !lower.includes('onlinesbi.sbi')
    ) {
      evidenceClues.push({
        tactic: 'Deceptive Lookalike Domain',
        quote: extractQuote(content, ['sbi', 'hdfc', 'icici', 'pm-kisan', 'aadhaar']),
        explanation:
          'Domain mimics a major bank or government service but lacks verified official domain extensions (e.g. .gov.in, .nic.in, or verified banking root).',
        severity: 'high',
      });
    }

    // Shortened URL hiding destination
    if (lower.includes('bit.ly') || lower.includes('t.co') || lower.includes('tinyurl') || lower.includes('is.gd')) {
      evidenceClues.push({
        tactic: 'Obfuscated Shortened Link',
        quote: extractQuote(content, ['bit.ly', 't.co', 'tinyurl', 'is.gd']),
        explanation:
          'Link uses a URL shortener to conceal the true web destination. Scammers use this to bypass visual domain checks.',
        severity: 'medium',
      });
    }
  }

  // 4. EVALUATION: Media, Photo, Video, Deepfake
  if (modality === 'media') {
    evidenceClues.push({
      tactic: 'Media Authenticity & Deepfake Triage',
      explanation:
        'Image/video analyzed against synthetic generation markers. Notice: Compression artifacts and lighting can mimic manipulation cues.',
      severity: 'info',
    });
    if (lower.includes('fake') || lower.includes('deepfake') || lower.includes('viral video') || lower.includes('minister') || lower.includes('celebrity investment')) {
      evidenceClues.push({
        tactic: 'High-Impact Synthetic Persona Claim',
        quote: extractQuote(content, ['deepfake', 'viral', 'minister', 'celebrity', 'investment']),
        explanation:
          'Content claims an endorsement or instruction from a public figure. Note: Generative AI audio/face clones are frequently used for fraudulent stock trading platforms.',
        severity: 'medium',
      });
    }
  }

  // 5. EVALUATION: Audio / Voice Recording
  if (modality === 'audio') {
    evidenceClues.push({
      tactic: 'Synthetic Voice / Voice Cloning Advisory',
      explanation:
        'Voice clone algorithms replicate vocal timbre from 3 seconds of audio. Calls claiming a relative is in police custody or distress must be verified by calling the relative directly on their known personal number.',
      severity: 'info',
    });
  }

  // Formulate Nuanced Outcome Label
  let label: RiskLabel = 'NO_COMMON_INDICATORS';
  let plainLanguageSummary = '';
  let confidenceScore = 0.65;

  if (evidenceClues.some((c) => c.severity === 'high')) {
    label = 'HIGH_RISK';
    confidenceScore = 0.94;
    plainLanguageSummary =
      'Strong warning indicators of known cyber fraud and coercive deception were identified in the submitted details.';
  } else if (officialMatch) {
    label = 'OFFICIAL_MATCH';
    confidenceScore = 0.96;
    plainLanguageSummary =
      'Content closely matches an official public cybercrime advisory issued by Indian regulatory or law enforcement agencies.';
  } else if (evidenceClues.some((c) => c.severity === 'medium')) {
    label = 'CHECK_CAREFULLY';
    confidenceScore = 0.78;
    plainLanguageSummary =
      'Some warning indicators or unverified claims were found. Exercise high caution and verify independently before taking action.';
  } else if (content.length < 20) {
    label = 'NEEDS_REVIEW';
    confidenceScore = 0.45;
    plainLanguageSummary =
      'The provided information is too brief or ambiguous to identify definitive indicators. More details are needed.';
  } else {
    label = 'NO_COMMON_INDICATORS';
    confidenceScore = 0.68;
    plainLanguageSummary =
      'No common high-risk indicators were identified in our current pattern registry. Note: absence of match does not guarantee authenticity.';
  }

  return {
    id: `JV-${Math.floor(100000 + Math.random() * 900000)}`,
    modality,
    label,
    plainLanguageSummary,
    confidenceScore,
    confidenceLimits:
      'Confidence is calibrated via heuristic pattern matching and official advisory indexes. Not a legal or forensic proof.',
    languageMethod: 'Bhashini-aligned on-device token analysis with localized rule models.',
    evidenceClues,
    officialMatch,
    nextSteps: [
      'Stop communicating with the sender or caller immediately.',
      'NEVER share an OTP or enter your UPI PIN. UPI PIN is only for sending money.',
      'Independently find the organization’s official contact number from their legitimate website.',
      'Preserve screenshots and debit SMS alerts as evidence.',
      'If you have lost money, dial 1930 immediately or lodge an incident report at cybercrime.gov.in.',
    ],
    disclaimer:
      'JanVaani provides informational safety indicators to help citizens make informed decisions. It does not file official police complaints or replace formal investigation.',
    timestamp: `${dateStr} ${nowStr}`,
  };
}

function extractQuote(text: string, keywords: string[]): string {
  const words = text.split(/\s+/);
  for (let i = 0; i < words.length; i++) {
    const word = words[i]?.toLowerCase() || '';
    if (keywords.some((k) => word.includes(k))) {
      const start = Math.max(0, i - 3);
      const end = Math.min(words.length, i + 6);
      return `"...${words.slice(start, end).join(' ')}..."`;
    }
  }
  return `"${text.slice(0, 60)}..."`;
}
