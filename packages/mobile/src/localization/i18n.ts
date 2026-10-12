import { en } from './en';
import { hi } from './hi';
import { INDIAN_LANGUAGES_REGISTRY } from './languages';
import { LanguageInfo } from '../types';

export type TranslationDictionary = typeof en;

const TRANSLATIONS: Record<string, TranslationDictionary> = {
  en,
  hi,
};

let currentLanguageCode = 'en';

export function setAppLanguage(code: string): void {
  currentLanguageCode = code;
}

export function getCurrentLanguageCode(): string {
  return currentLanguageCode;
}

export function getCurrentLanguageInfo(): LanguageInfo {
  const found = INDIAN_LANGUAGES_REGISTRY.find((l) => l.code === currentLanguageCode);
  return (
    found || {
      code: 'en',
      name: 'English',
      nativeName: 'English',
      script: 'Latin',
      isHumanReviewed: true,
    }
  );
}

/**
 * Returns string translations for active language, falling back to English
 * if translation dictionary is not human-reviewed yet for that dialect/language.
 */
export function useTranslations(): {
  t: TranslationDictionary;
  langInfo: LanguageInfo;
  isFallback: boolean;
} {
  const langInfo = getCurrentLanguageInfo();
  const dict = TRANSLATIONS[currentLanguageCode] || en;
  const isFallback = !langInfo.isHumanReviewed;

  return {
    t: dict,
    langInfo,
    isFallback,
  };
}
