/**
 * @file packages/backend/src/detection/rules.ts
 * @description Production deterministic scam detection rule engine tailored for India-specific threats.
 * Detects UPI fraud, KYC deactivation scams, Digital Arrest impersonation, fake government schemes,
 * KBC lotteries, job scams, sextortion, and homograph/typosquatting URL attacks.
 * 
 * SECURITY RATIONALE:
 * - Rules are strictly typed, versioned, and loaded from structured configuration.
 * - Anti-evasion matching supports Devanagari Hindi, Romanized Hinglish, and English variations.
 * - Evidence captures match indices and token categories WITHOUT leaking raw user PII into system audit logs.
 * - Homograph and punycode detection prevents Cyrillic/Greek lookalike domain spoofing.
 */

import { z } from 'zod';

export type RuleType =
  | 'URL_PATTERN'
  | 'PHONE_PATTERN'
  | 'TEXT_PATTERN'
  | 'KEYWORD_MATCH'
  | 'FINANCIAL_PATTERN';

export type ScamCategory =
  | 'UPI_FRAUD'
  | 'KYC_UPDATE_SCAM'
  | 'DIGITAL_ARREST_IMPERSONATION'
  | 'GOVT_SCHEME_FRAUD'
  | 'LOTTERY_PRIZE_SCAM'
  | 'JOB_TASK_SCAM'
  | 'SEXTORTION_BLACKMAIL'
  | 'PHISHING_TYPOSQUATTING';

export type RuleSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/**
 * Zod schema for rule definition.
 */
export const DetectionRuleSchema = z.object({
  id: z.string(),
  version: z.string(),
  type: z.enum(['URL_PATTERN', 'PHONE_PATTERN', 'TEXT_PATTERN', 'KEYWORD_MATCH', 'FINANCIAL_PATTERN']),
  category: z.enum([
    'UPI_FRAUD',
    'KYC_UPDATE_SCAM',
    'DIGITAL_ARREST_IMPERSONATION',
    'GOVT_SCHEME_FRAUD',
    'LOTTERY_PRIZE_SCAM',
    'JOB_TASK_SCAM',
    'SEXTORTION_BLACKMAIL',
    'PHISHING_TYPOSQUATTING',
  ]),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  confidence: z.number().min(0).max(1),
  description: z.string(),
  pattern: z.union([z.instanceof(RegExp), z.string()]),
  keywords: z.array(z.string()).optional(),
  lastUpdated: z.string(),
});

export type DetectionRule = z.infer<typeof DetectionRuleSchema>;

/**
 * Matched rule result.
 * Records location and sanitized tokens, avoiding raw PII logging.
 */
export interface RuleMatchResult {
  readonly ruleId: string;
  readonly ruleVersion: string;
  readonly category: ScamCategory;
  readonly severity: RuleSeverity;
  readonly confidence: number;
  readonly description: string;
  readonly evidence: {
    readonly matchType: RuleType;
    readonly matchedKeywordOrPattern: string;
    readonly startIndex: number;
    readonly endIndex: number;
  };
}

/**
 * Configurable rule set repository.
 */
export interface RuleEngineConfig {
  version: string;
  rules: DetectionRule[];
  lastUpdated: string;
}

/**
 * Default India-specific scam detection rules (Versioned V2026.1).
 */
export const DEFAULT_INDIA_SCAM_RULES: DetectionRule[] = [
  // 1. UPI Fraud & Collect Request Scams
  {
    id: 'IND-UPI-001',
    version: '1.2.0',
    type: 'FINANCIAL_PATTERN',
    category: 'UPI_FRAUD',
    severity: 'CRITICAL',
    confidence: 0.95,
    description: 'UPI PIN entry deception (claiming PIN is required to receive funds)',
    pattern: /(enter\s+(?:your\s+)?(?:upi\s+)?pin\s+to\s+(?:receive|claim|accept|credit)\s+(?:money|cash|amount|cashback)|पिन\s+(?:डालें|दर्ज\s+करें)\s+पैसे\s+(?:प्राप्त|पाने)\s+के\s+लिए|pin\s+daalein\s+paise\s+paane\s+ke\s+liye)/i,
    lastUpdated: '2026-03-01T00:00:00Z',
  },
  {
    id: 'IND-UPI-002',
    version: '1.1.0',
    type: 'FINANCIAL_PATTERN',
    category: 'UPI_FRAUD',
    severity: 'HIGH',
    confidence: 0.90,
    description: 'Fake refund / QR code scan to receive payment deception',
    pattern: /(scan\s+(?:this\s+)?qr\s+code\s+to\s+(?:receive|get|credit)\s+(?:refund|money|amount)|qr\s+code\s+scan\s+karke\s+paisa\s+lo)/i,
    lastUpdated: '2026-02-15T00:00:00Z',
  },
  {
    id: 'IND-UPI-003',
    version: '1.0.0',
    type: 'TEXT_PATTERN',
    category: 'UPI_FRAUD',
    severity: 'HIGH',
    confidence: 0.88,
    description: 'Fraudulent UPI collect request pretext',
    pattern: /(approve\s+collect\s+request\s+on\s+(?:gpay|phonepe|paytm|bhim)|paytm\s+cashback\s+scratch\s+card\s+worth\s+rs)/i,
    lastUpdated: '2026-01-10T00:00:00Z',
  },

  // 2. KYC Update & SIM Deactivation Scams
  {
    id: 'IND-KYC-001',
    version: '1.3.0',
    type: 'TEXT_PATTERN',
    category: 'KYC_UPDATE_SCAM',
    severity: 'CRITICAL',
    confidence: 0.96,
    description: 'Urgent KYC expiration threat and SIM/bank blocking ultimatum',
    pattern: /(dear\s+customer.*?(?:kyc|pan\s+card|aadhaar).*?(?:suspended|blocked|deactivated|expire).*?(?:within\s+\d+\s+hours|today)|प्रिय\s+ग्राहक.*?(?:केवाईसी|पैन|आधार).*?(?:ब्लॉक|बंद|निलंबित).*?(?:घंटे\s+के\s+भीतर))/i,
    lastUpdated: '2026-04-01T00:00:00Z',
  },
  {
    id: 'IND-KYC-002',
    version: '1.1.0',
    type: 'URL_PATTERN',
    category: 'KYC_UPDATE_SCAM',
    severity: 'CRITICAL',
    confidence: 0.94,
    description: 'Phishing domain impersonating SBI / HDFC / Paytm / Airtel KYC portal',
    pattern: /(?:sbi|hdfc|icici|paytm|airtel|jio|vi)[-_]?(?:kyc|pan|support|update|verify|apk)\.(?:apk|top|xyz|club|live|info|buzz|click|cc)/i,
    lastUpdated: '2026-03-20T00:00:00Z',
  },

  // 3. Digital Arrest & Law Enforcement Impersonation
  {
    id: 'IND-IMPERSONATION-001',
    version: '1.4.0',
    type: 'TEXT_PATTERN',
    category: 'DIGITAL_ARREST_IMPERSONATION',
    severity: 'CRITICAL',
    confidence: 0.98,
    description: 'Digital Arrest scam impersonating CBI, Cyber Crime, TRAI, or Police video call',
    pattern: /(?:digital\s+arrest|cbi\s+cyber\s+crime\s+branch|mumbai\s+police\s+narcotics|customs\s+seizure\s+parcel.*?(?:drugs|passport|sim\s+card)|trai\s+(?:mobile\s+number\s+disconnected|illegal\s+advertisement)|stay\s+on\s+skype\s+video\s+call)/i,
    lastUpdated: '2026-05-10T00:00:00Z',
  },
  {
    id: 'IND-IMPERSONATION-002',
    version: '1.0.0',
    type: 'KEYWORD_MATCH',
    category: 'DIGITAL_ARREST_IMPERSONATION',
    severity: 'HIGH',
    confidence: 0.92,
    description: 'RBI or Supreme Court fake verification account payment demand',
    pattern: /(?:rbi\s+verification\s+account|supreme\s+court\s+clearance\s+fee|money\s+laundering\s+clearance\s+deposit)/i,
    lastUpdated: '2026-04-15T00:00:00Z',
  },

  // 4. Fake Government Schemes & Subsidies
  {
    id: 'IND-GOVT-001',
    version: '1.2.0',
    type: 'TEXT_PATTERN',
    category: 'GOVT_SCHEME_FRAUD',
    severity: 'HIGH',
    confidence: 0.93,
    description: 'Fake PM Yojana, free mobile recharge, or Ladli Behna cash distribution links',
    pattern: /(?:pm\s+(?:yojana|kisan|mudra\s+loan|awas)|pradhan\s+mantri.*?(?:free\s+recharge|laptop|scooter|subsidy)|लाडली\s+बहना\s+योजना\s+रजिस्ट्रेशन|मुफ्त\s+रिचार्ज\s+के\s+लिए\s+क्लिक\s+करें)/i,
    lastUpdated: '2026-03-12T00:00:00Z',
  },

  // 5. Lottery & KBC Prize Scams
  {
    id: 'IND-LOTTERY-001',
    version: '1.1.0',
    type: 'TEXT_PATTERN',
    category: 'LOTTERY_PRIZE_SCAM',
    severity: 'HIGH',
    confidence: 0.95,
    description: 'KBC WhatsApp lottery winner or lucky draw prize fee scam',
    pattern: /(?:kbc\s+(?:all\s+india\s+sim\s+card\s+lucky\s+draw|lottery\s+winner\s+rs\s+\d+|rana\s+pratap\s+singh)|congratulations.*?(?:won|selected\s+for)\s+(?:lottery|tata\s+harrier|car).*?(?:deposit|processing\s+fee|tax\s+charges))/i,
    lastUpdated: '2026-01-25T00:00:00Z',
  },

  // 6. Job & Part-time Task Scams
  {
    id: 'IND-JOB-001',
    version: '1.3.0',
    type: 'TEXT_PATTERN',
    category: 'JOB_TASK_SCAM',
    severity: 'HIGH',
    confidence: 0.91,
    description: 'YouTube video like, Google map review part-time daily salary Telegram trap',
    pattern: /(?:earn\s+rs\.?\s*(?:2000|3000|5000|8000)\s*(?:daily|per\s+day)|part-time\s+job.*?(?:youtube\s+like|google\s+review|hotel\s+rating|telegram)|prepaid\s+task\s+investment.*?(?:crypto|merchant))/i,
    lastUpdated: '2026-04-20T00:00:00Z',
  },

  // 7. Sextortion & Video Call Blackmail
  {
    id: 'IND-SEXTORTION-001',
    version: '1.2.0',
    type: 'TEXT_PATTERN',
    category: 'SEXTORTION_BLACKMAIL',
    severity: 'CRITICAL',
    confidence: 0.97,
    description: 'Nude video call recording extortion & threat of uploading to YouTube/family',
    pattern: /(?:recorded\s+your\s+(?:nude|obscene|private)\s+video\s+call|viral\s+on\s+youtube|send\s+to\s+all\s+your\s+contacts|pay\s+within\s+\d+\s+minutes\s+or\s+face\s+social\s+defamation|cyber\s+crime\s+officer\s+calling\s+to\s+delete\s+video)/i,
    lastUpdated: '2026-05-02T00:00:00Z',
  },

  // 8. Typosquatting / Suspicious Homograph Domains
  {
    id: 'IND-TYPO-001',
    version: '1.1.0',
    type: 'URL_PATTERN',
    category: 'PHISHING_TYPOSQUATTING',
    severity: 'HIGH',
    confidence: 0.89,
    description: 'Suspicious top-level domain hosting banking/government keywords',
    pattern: /(https?:\/\/[a-zA-Z0-9.-]*(?:sbi|hdfc|icici|pnb|bob|uidai|incometax|epfindia)[a-zA-Z0-9.-]*\.(?:xyz|top|site|club|buzz|click|cc|work|rest|link|press))/i,
    lastUpdated: '2026-02-18T00:00:00Z',
  },
];

/**
 * Deterministic scam detection engine.
 */
export class DeterministicRuleEngine {
  private rules: DetectionRule[];
  private readonly configVersion: string;
  private readonly lastUpdated: string;

  constructor(customConfig?: RuleEngineConfig) {
    if (customConfig) {
      this.configVersion = customConfig.version;
      this.lastUpdated = customConfig.lastUpdated;
      this.rules = customConfig.rules.map((r) => DetectionRuleSchema.parse(r));
    } else {
      this.configVersion = '2026.1.0';
      this.lastUpdated = '2026-05-15T00:00:00Z';
      this.rules = [...DEFAULT_INDIA_SCAM_RULES];
    }
  }

  public getVersion(): string {
    return this.configVersion;
  }

  public getLastUpdated(): string {
    return this.lastUpdated;
  }

  public getRuleCount(): number {
    return this.rules.length;
  }

  /**
   * Executes all active rules against the supplied text content and extracted URLs.
   */
  public evaluate(text: string, extractedUrls: string[] = []): RuleMatchResult[] {
    const matches: RuleMatchResult[] = [];
    const normalizedText = this.normalizeInput(text);

    // 1. Text and Keyword Rules
    for (const rule of this.rules) {
      if (rule.type === 'TEXT_PATTERN' || rule.type === 'FINANCIAL_PATTERN' || rule.type === 'KEYWORD_MATCH') {
        const regex = typeof rule.pattern === 'string' ? new RegExp(rule.pattern, 'i') : rule.pattern;
        const match = regex.exec(normalizedText);

        if (match && match.index !== undefined) {
          matches.push({
            ruleId: rule.id,
            ruleVersion: rule.version,
            category: rule.category,
            severity: rule.severity,
            confidence: rule.confidence,
            description: rule.description,
            evidence: {
              matchType: rule.type,
              matchedKeywordOrPattern: rule.id,
              startIndex: match.index,
              endIndex: match.index + match[0].length,
            },
          });
        }
      }
    }

    // 2. URL and Typosquatting Rules
    for (const url of extractedUrls) {
      // Homograph / Punycode check
      const homographDetected = this.detectHomographAttack(url);
      if (homographDetected) {
        matches.push({
          ruleId: 'IND-HOMOGRAPH-001',
          ruleVersion: '1.0.0',
          category: 'PHISHING_TYPOSQUATTING',
          severity: 'CRITICAL',
          confidence: 0.98,
          description: 'IDN Homograph attack detected (lookalike characters or xn-- punycode spoofing)',
          evidence: {
            matchType: 'URL_PATTERN',
            matchedKeywordOrPattern: 'PUNYCODE_HOMOGRAPH',
            startIndex: 0,
            endIndex: url.length,
          },
        });
      }

      // Pattern-based URL rules
      for (const rule of this.rules) {
        if (rule.type === 'URL_PATTERN') {
          const regex = typeof rule.pattern === 'string' ? new RegExp(rule.pattern, 'i') : rule.pattern;
          const match = regex.exec(url);
          if (match && match.index !== undefined) {
            matches.push({
              ruleId: rule.id,
              ruleVersion: rule.version,
              category: rule.category,
              severity: rule.severity,
              confidence: rule.confidence,
              description: rule.description,
              evidence: {
                matchType: rule.type,
                matchedKeywordOrPattern: rule.id,
                startIndex: match.index,
                endIndex: match.index + match[0].length,
              },
            });
          }
        }
      }
    }

    return matches;
  }

  /**
   * Normalizes text by removing zero-width characters, normalizing NFKC unicode,
   * and collapsing repeated whitespace to counteract obfuscation.
   */
  private normalizeInput(text: string): string {
    return text
      .normalize('NFKC')
      .replace(/[\u200B-\u200D\uFEFF]/g, '') // Strip zero-width chars
      .replace(/\s+/g, ' ')
      .trim();
  }

  /**
   * Detects internationalized domain name (IDN) homograph attacks using Punycode prefix
   * or mixed non-ASCII lookalike characters in the domain authority.
   */
  private detectHomographAttack(rawUrl: string): boolean {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      const hostname = parsed.hostname.toLowerCase();

      // Punycode marker indicates non-ASCII characters in domain
      if (hostname.includes('xn--')) {
        return true;
      }

      // Check for Cyrillic / Greek characters mixed into Latin domains (e.g. Cyrillic 'а', 'е', 'о', 'р')
      const hasCyrillicOrGreek = /[\u0400-\u04FF\u0370-\u03FF]/.test(hostname);
      return hasCyrillicOrGreek;
    } catch {
      return false;
    }
  }
}
