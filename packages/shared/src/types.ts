/**
 * @fileoverview Shared TypeScript types and interfaces for the CyberGuard India platform.
 * 
 * SECURITY RATIONALE:
 * - Shared strictly typed contracts eliminate data boundary ambiguities between frontend and backend.
 * - Prevents injection of invalid enum states or malformed structures.
 * - Enforces zero-PII leak policy across API responses by design.
 */

// ============================================================================
// Core Domain Enums
// ============================================================================

/**
 * Role-Based Access Control (RBAC) tiers.
 * Principle of Least Privilege: USER has zero administrative or review privileges.
 */
export enum Role {
  ADMIN = 'ADMIN',
  REVIEWER = 'REVIEWER',
  STAFF = 'STAFF',
  USER = 'USER',
}

/**
 * Supported cyber threat analysis content types.
 */
export enum ContentType {
  TEXT = 'TEXT',
  URL = 'URL',
  IMAGE = 'IMAGE',
  AUDIO = 'AUDIO',
  VIDEO = 'VIDEO',
  DOCUMENT = 'DOCUMENT',
}

/**
 * Lifecycle status of an analysis report.
 */
export enum ReportStatus {
  PENDING = 'PENDING',
  ANALYZING = 'ANALYZING',
  COMPLETED = 'COMPLETED',
  FLAGGED_FOR_REVIEW = 'FLAGGED_FOR_REVIEW',
  REVIEWED = 'REVIEWED',
  DELETED = 'DELETED',
}

/**
 * Assessed threat risk categorization.
 * ABSTAIN indicates ambiguous input or lack of authoritative signals where making
 * an unconfident classification could cause false positives or false sense of security.
 */
export enum RiskLevel {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  NONE = 'NONE',
  ABSTAIN = 'ABSTAIN',
}

/**
 * Antivirus / anti-malware verification status for submitted artifacts.
 */
export enum ScanStatus {
  PENDING = 'PENDING',
  CLEAN = 'CLEAN',
  INFECTED = 'INFECTED',
  ERROR = 'ERROR',
}

/**
 * Human analyst review disposition for high-risk or flagged analyses.
 */
export enum HumanReviewDecision {
  CONFIRMED_THREAT = 'CONFIRMED_THREAT',
  FALSE_POSITIVE = 'FALSE_POSITIVE',
  INCONCLUSIVE = 'INCONCLUSIVE',
  ESCALATED = 'ESCALATED',
}

/**
 * Audit log outcome status.
 */
export enum AuditOutcome {
  SUCCESS = 'SUCCESS',
  FAILURE = 'FAILURE',
  DENIED = 'DENIED',
}

/**
 * State machine status for Digital Personal Data Protection Act (DPDPA) deletion requests.
 */
export enum DataDeletionStatus {
  REQUESTED = 'REQUESTED',
  VERIFIED = 'VERIFIED',
  PROCESSING = 'PROCESSING',
  COMPLETED = 'COMPLETED',
  CANCELLED = 'CANCELLED',
}

/**
 * Supported Bhashini language codes across Indian regional languages.
 */
export type SupportedLanguage =
  | 'hi' // Hindi
  | 'en' // English
  | 'bn' // Bengali
  | 'ta' // Tamil
  | 'te' // Telugu
  | 'mr' // Marathi
  | 'gu' // Gujarati
  | 'kn' // Kannada
  | 'ml' // Malayalam
  | 'or' // Odia
  | 'pa' // Punjabi
  | 'as' // Assamese
  | 'ur'; // Urdu

// ============================================================================
// Pipeline & Signal Analysis Interfaces
// ============================================================================

/**
 * Individual threat or anomaly signal detected by pipeline stages.
 */
export interface Signal {
  /** Identifier of the detection rule or model heuristic */
  id: string;
  /** Categorization tag (e.g., 'UPI_FRAUD', 'DIGITAL_ARREST', 'PHISHING', 'MALICIOUS_APK') */
  category: string;
  /** Normalized confidence score [0.0 - 1.0] */
  confidence: number;
  /** Threat severity assigned to this specific signal */
  severity: RiskLevel;
  /** Sanitized explanation safe to display to the user without disclosing confidential IOC signatures */
  description: string;
  /** Optional sanitized context or indicator matches (redacted for PII) */
  matchedPattern?: string;
  /** Mitre ATT&CK or Indian Cybercrime Coordination Centre (I4C) taxonomy code if applicable */
  taxonomyCode?: string;
}

/**
 * Result of an individual pipeline analysis stage.
 */
export interface PipelineStageResult {
  /** Unique name of the pipeline stage */
  stageName: string;
  /** Version of the model or heuristic logic */
  stageVersion: string;
  /** Execution status of the stage */
  status: 'SUCCESS' | 'FAILED' | 'SKIPPED';
  /** Confidence score produced by this stage [0.0 - 1.0] */
  confidence: number;
  /** Signals isolated by this stage */
  signals: Signal[];
  /** Execution time in milliseconds */
  durationMs: number;
  /** Optional error message sanitized of internal stack trace */
  errorMessage?: string;
}

/**
 * Complete analysis result payload stored and returned to clients.
 */
export interface AnalysisResultData {
  id: string;
  reportId: string;
  pipelineVersion: string;
  stages: PipelineStageResult[];
  overallConfidence: number;
  riskLevel: RiskLevel;
  signals: Signal[];
  /** Transparent limitations of the model/heuristic for user awareness */
  limitations: string[];
  /** Specific model versions utilized */
  modelVersions: Record<string, string>;
  processingTimeMs: number;
  createdAt: string;
  /** Indicates whether machine translation was applied during analysis */
  machineTranslated?: boolean;
  detectedLanguage?: SupportedLanguage | string;
}

// ============================================================================
// API Request & Response Contracts
// ============================================================================

/**
 * Standard structured API Error response conforming to RFC 7807 (Problem Details).
 * Prevents information leakage and server fingerprinting.
 */
export interface ApiErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown> | Array<unknown>;
    requestId?: string;
    timestamp: string;
  };
}

/**
 * Standard successful API envelope.
 */
export interface ApiSuccessResponse<T> {
  success: true;
  data: T;
  meta?: {
    requestId?: string;
    timestamp: string;
  };
}

// --- Public Check API ---

export interface CheckTextRequest {
  /** Text content or URL to analyze (Max 5,000 characters to prevent ReDoS / payload exhaustion) */
  content: string;
  /** Must explicitly match TEXT or URL */
  contentType: ContentType.TEXT | ContentType.URL;
  /** Optional Indian District for localized fraud pattern aggregation */
  district?: string;
  /** Optional Indian State / UT */
  state?: string;
  /** User consent for processing via external sovereign AI pipelines (e.g. Bhashini) */
  bhashiniConsent?: boolean;
}

export interface CheckResponseData {
  reportId: string;
  status: ReportStatus;
  riskLevel: RiskLevel;
  overallConfidence: number;
  signals: Signal[];
  limitations: string[];
  machineTranslated: boolean;
  languageDetected?: string;
  processingTimeMs: number;
  advisories?: GovernmentAdvisorySummary[];
  createdAt: string;
  expiresAt: string;
}

export interface GovernmentAdvisorySummary {
  id: string;
  title: string;
  category: string;
  sourceUrl: string;
  matchedPassage?: string;
}

export interface CheckUploadResponseData {
  reportId: string;
  uploadId: string;
  status: ReportStatus;
  scanStatus: ScanStatus;
  originalNameSanitized: string;
  sizeBytes: number;
  sha256Hash: string;
  result?: CheckResponseData;
  expiresAt: string;
}

export interface ReportDeletionResponseData {
  reportId: string;
  deleted: boolean;
  message: string;
}

// --- Auth API ---

export interface RegisterRequest {
  email: string;
  password: string;
}

export interface RegisterResponseData {
  userId: string;
  email: string;
  role: Role;
  message: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  deviceFingerprint?: string;
}

export interface LoginResponseData {
  userId: string;
  email: string;
  role: Role;
  mfaRequired: boolean;
  accessToken?: string;
}

export interface RefreshResponseData {
  accessToken: string;
}

export interface LogoutResponseData {
  message: string;
}

export interface MfaSetupResponseData {
  secret: string;
  qrCodeUri: string;
  recoveryCodes: string[];
}

export interface MfaVerifyRequest {
  totpCode: string;
  recoveryCode?: string;
}

export interface MfaVerifyResponseData {
  mfaVerified: boolean;
  accessToken: string;
}

// --- Admin API ---

export interface AuditLogItem {
  id: string;
  eventId: string;
  previousHash: string;
  currentHash: string;
  actorId: string | null;
  actorRole: string;
  action: string;
  resourceType: string;
  resourceId: string;
  ipHash: string;
  userAgentSanitized: string;
  outcome: AuditOutcome;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface AuditLogsQueryParams {
  page?: number;
  limit?: number;
  action?: string;
  actorId?: string;
  resourceType?: string;
  outcome?: AuditOutcome;
  fromDate?: string;
  toDate?: string;
}

export interface AuditLogsResponseData {
  logs: AuditLogItem[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface FlaggedReportItem {
  id: string;
  contentType: ContentType;
  status: ReportStatus;
  district: string | null;
  state: string | null;
  languageDetected: string | null;
  createdAt: string;
  riskLevel: RiskLevel;
  overallConfidence: number;
  signalsCount: number;
}

export interface ReviewDecisionRequest {
  decision: HumanReviewDecision;
  notes: string;
}

export interface ReviewDecisionResponseData {
  reviewId: string;
  reportId: string;
  decision: HumanReviewDecision;
  reviewedAt: string;
}

export interface SystemStatsResponseData {
  totalReports: number;
  reportsByContentType: Record<ContentType, number>;
  reportsByRiskLevel: Record<RiskLevel, number>;
  pendingReviewsCount: number;
  averageProcessingTimeMs: number;
  activeAdvisoriesCount: number;
  systemHealth: 'OPERATIONAL' | 'DEGRADED' | 'MAINTENANCE';
}
