/**
 * JanVaani Mobile - Core Data Contracts and Interfaces
 */

export type CheckerModality = 'message' | 'call' | 'link' | 'media' | 'audio';

export type RiskLabel =
  | 'HIGH_RISK'
  | 'CHECK_CAREFULLY'
  | 'NO_COMMON_INDICATORS'
  | 'OFFICIAL_MATCH'
  | 'NEEDS_REVIEW';

export interface EvidenceClue {
  tactic: string;
  quote?: string;
  explanation: string;
  severity: 'high' | 'medium' | 'info';
}

export interface OfficialSourceMatch {
  sourceName: string;
  url: string;
  publishDate: string;
  retrievalTime: string;
  matchedPassage: string;
}

export interface AnalysisOutcome {
  id: string;
  modality: CheckerModality;
  label: RiskLabel;
  plainLanguageSummary: string;
  confidenceScore: number;
  confidenceLimits: string;
  languageMethod: string;
  evidenceClues: EvidenceClue[];
  officialMatch?: OfficialSourceMatch;
  nextSteps: string[];
  disclaimer: string;
  timestamp: string;
}

export interface LanguageInfo {
  code: string;
  name: string;
  nativeName: string;
  script: string;
  isRtl?: boolean;
  isHumanReviewed: boolean; // True for English & Hindi; False for English Fallback state
}

export interface QuizOption {
  text: string;
  isCorrect: boolean;
  explanation: string;
}

export interface QuizQuestion {
  id: string;
  question: string;
  options: QuizOption[];
}

export interface SafeHabitsLesson {
  id: string;
  title: string;
  nativeTitle: string;
  category: 'calls' | 'payments' | 'messages' | 'media';
  durationMin: number;
  summary: string;
  takeaways: string[];
  quiz: QuizQuestion;
}

export type ActiveTab = 'shield' | 'check' | 'learn' | 'helpline' | 'privacy';
