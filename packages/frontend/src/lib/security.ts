'use client';

/**
 * FRONTEND SECURITY UTILITIES
 * ============================================================================
 * Security principles:
 * 1. Safe text rendering & HTML sanitization:
 *    - All external/user input must be treated as untrusted.
 *    - Escape dangerous HTML entities (&, <, >, ", ') when displaying dynamic content.
 * 2. URL validation:
 *    - Strict protocol enforcement: ONLY 'https:' protocols are permitted.
 *    - Blocks 'javascript:', 'data:', 'vbscript:', 'file:', and non-standard schemes.
 * 3. Client-side File Pre-validation:
 *    - Client checks provide immediate UX feedback (size, MIME type, file extension).
 *    - CRITICAL: Server-side validation with ClamAV and magic byte inspection is always
 *      the authoritative enforcement layer. Client validation is UX only.
 * 4. LocalStorage Security Warning:
 *    - NEVER store JWTs, passwords, PII, session IDs, or private keys in localStorage!
 *    - LocalStorage is completely accessible to ANY JavaScript running on the domain.
 *      Any XSS vulnerability would immediately compromise tokens stored there.
 *    - Authentication tokens MUST only reside in HttpOnly, Secure, SameSite cookies.
 *    - SecureLocalStorage wrapper below strictly limits stored items to benign UI preferences.
 * ============================================================================
 */

import React, { createContext, useContext } from 'react';

// Context for CSP nonce injection in React tree
export const NonceContext = createContext<string>('');

export function useNonce(): string {
  return useContext(NonceContext);
}

/**
 * Escapes common HTML control characters to prevent XSS in raw text contexts.
 */
export function escapeHtml(unsafeText: string): string {
  if (typeof unsafeText !== 'string') return '';
  return unsafeText
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Validates whether a given URL is strictly an HTTPS link.
 * Prevents javascript: URI execution, data URI phishing, and unencrypted HTTP traffic.
 */
export function isSecureHttpsUrl(rawUrl: string): boolean {
  if (!rawUrl || typeof rawUrl !== 'string') return false;
  try {
    const parsed = new URL(rawUrl.trim());
    return parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Formats a clean, safe external URL.
 * Returns null if the URL is not valid HTTPS.
 */
export function sanitizeExternalUrl(rawUrl: string): string | null {
  if (!isSecureHttpsUrl(rawUrl)) return null;
  try {
    const parsed = new URL(rawUrl.trim());
    // Strip userinfo (user:pass@host)
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return null;
  }
}

/**
 * Client-Side File Pre-validation Config
 */
export const FILE_VALIDATION_CONFIG = {
  maxSizeBytes: 5 * 1024 * 1024, // 5MB maximum file size
  allowedMimeTypes: [
    'image/jpeg',
    'image/png',
    'image/webp',
    'application/pdf',
    'text/plain',
  ] as const,
  allowedExtensions: ['.jpg', '.jpeg', '.png', '.webp', '.pdf', '.txt'] as const,
};

export interface FileValidationResult {
  isValid: boolean;
  error?: string;
}

/**
 * Client-side file pre-check.
 * Note: Server-side ClamAV malware scan and magic byte inspection remain authoritative.
 */
export function validateFileBeforeUpload(file: File): FileValidationResult {
  if (!file) {
    return { isValid: false, error: 'No file selected.' };
  }

  // 1. File size check
  if (file.size > FILE_VALIDATION_CONFIG.maxSizeBytes) {
    const maxMb = FILE_VALIDATION_CONFIG.maxSizeBytes / (1024 * 1024);
    return {
      isValid: false,
      error: `File size exceeds the allowed limit of ${maxMb}MB.`,
    };
  }

  // 2. MIME type check
  const isMimeAllowed = (FILE_VALIDATION_CONFIG.allowedMimeTypes as readonly string[]).includes(
    file.type
  );
  if (!isMimeAllowed) {
    return {
      isValid: false,
      error: `File type "${file.type || 'unknown'}" is not supported. Allowed formats: JPG, PNG, WEBP, PDF, TXT.`,
    };
  }

  // 3. Extension check (prevent extension spoofing like image.png.exe)
  const lowerName = file.name.toLowerCase();
  const hasValidExtension = FILE_VALIDATION_CONFIG.allowedExtensions.some((ext) =>
    lowerName.endsWith(ext)
  );

  if (!hasValidExtension) {
    return {
      isValid: false,
      error: 'File extension is not recognized. Please provide a supported file type.',
    };
  }

  // 4. Double extension detection (common malware obfuscation pattern)
  const segments = lowerName.split('.');
  if (segments.length > 2) {
    const dangerousExtensions = ['exe', 'bat', 'sh', 'vbs', 'ps1', 'scr', 'dll', 'cmd'];
    if (segments.some((part) => dangerousExtensions.includes(part))) {
      return {
        isValid: false,
        error: 'Dangerous file pattern detected. Multi-extension executables are rejected.',
      };
    }
  }

  return { isValid: true };
}

/**
 * SECURE LOCAL STORAGE WRAPPER
 * ----------------------------------------------------------------------------
 * EXPLICIT SECURITY WARNING:
 * NEVER store authentication credentials, JWT access tokens, refresh tokens,
 * passwords, Aadhaar numbers, phone numbers, or any PII in localStorage.
 * LocalStorage has NO protection against XSS vulnerabilities.
 *
 * This wrapper ONLY permits non-sensitive client preferences (e.g., UI theme,
 * language code, accessibility settings).
 * ----------------------------------------------------------------------------
 */
const ALLOWED_PREFERENCE_KEYS = new Set([
  'cg_theme_mode',
  'cg_preferred_lang',
  'cg_high_contrast',
  'cg_privacy_banner_dismissed',
]);

export const secureLocalStorage = {
  setItem(key: string, value: string): void {
    if (typeof window === 'undefined') return;

    if (!ALLOWED_PREFERENCE_KEYS.has(key)) {
      console.warn(
        `[SECURITY WARNING] Blocked attempt to store unauthorized key "${key}" in localStorage. Sensitive tokens must use HttpOnly cookies.`
      );
      return;
    }

    try {
      window.localStorage.setItem(key, value);
    } catch (e) {
      console.error('LocalStorage write error:', e);
    }
  },

  getItem(key: string): string | null {
    if (typeof window === 'undefined') return null;

    if (!ALLOWED_PREFERENCE_KEYS.has(key)) {
      return null;
    }

    try {
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  },

  removeItem(key: string): void {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.removeItem(key);
    } catch {
      // Ignored
    }
  },
};
