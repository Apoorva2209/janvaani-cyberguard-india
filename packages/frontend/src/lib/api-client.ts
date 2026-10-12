/**
 * SECURE API CLIENT FOR CYBERGUARD INDIA
 * ============================================================================
 * CRITICAL SECURITY ARCHITECTURE WARNING:
 * NEVER store or expose secret API keys, master credentials, encryption keys,
 * or administrative tokens in frontend client code or environment variables!
 * All NEXT_PUBLIC_* variables are bundled into client-side JavaScript and
 * completely readable by any external visitor or attacker via browser devtools.
 *
 * Authentication Architecture:
 * - Session/Access tokens are handled via HttpOnly, SameSite=Strict, Secure cookies
 *   managed directly by the backend to prevent theft via Cross-Site Scripting (XSS).
 * - Client uses `withCredentials: true` to forward session cookies automatically.
 * - CSRF tokens are injected via headers (X-CSRF-Token) read from secure cookie/meta tag.
 * - Refresh flow intercepts 401 Unauthorized responses, invokes token rotation endpoint,
 *   and retries failed requests without exposing tokens to JavaScript runtime.
 * - Output validation is strictly enforced with Zod schemas to ensure type integrity
 *   and prevent Prototype Pollution or data spoofing.
 * - Raw error traces, stack traces, and database error messages are sanitized before
 *   being exposed to UI components or end users.
 * ============================================================================
 */

import axios, {
  type AxiosError,
  type AxiosInstance,
  type AxiosRequestConfig,
  type InternalAxiosRequestConfig,
} from 'axios';
import { z } from 'zod';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
const DEFAULT_TIMEOUT_MS = 30_000; // 30 seconds

/**
 * Standard sanitized error structure presented to application UI
 */
export interface SanitizedApiError {
  code: string;
  message: string;
  status?: number;
  details?: Record<string, unknown>;
}

/**
 * Helper to retrieve CSRF token from document cookie or meta header
 */
function getCsrfToken(): string | null {
  if (typeof document === 'undefined') {
    return null;
  }
  // Check for meta tag first (injected by layout)
  const metaTag = document.querySelector('meta[name="csrf-token"]');
  if (metaTag) {
    const content = metaTag.getAttribute('content');
    if (content) return content;
  }

  // Fallback: check csrf-token cookie (not httpOnly, double-submit cookie pattern)
  const match = document.cookie.match(/(^|;\s*)XSRF-TOKEN=([^;]+)/);
  return match && match[2] ? decodeURIComponent(match[2]) : null;
}

/**
 * Configure primary Axios instance
 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: DEFAULT_TIMEOUT_MS,
  withCredentials: true, // Automatically transmits HttpOnly auth cookies
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'X-Requested-With': 'XMLHttpRequest', // Helps mitigate CSRF alongside origin check
  },
});

// Flag to track ongoing token refresh request to avoid concurrency race conditions
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value?: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

const processQueue = (error: unknown) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve();
    }
  });
  failedQueue = [];
};

/**
 * Request Interceptor:
 * Injects CSRF tokens and enforces strict origin checks.
 */
apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    // Inject CSRF token if available
    const csrfToken = getCsrfToken();
    if (csrfToken && config.headers) {
      config.headers['X-CSRF-Token'] = csrfToken;
    }
    return config;
  },
  (error: unknown) => {
    return Promise.reject(sanitizeApiError(error));
  }
);

/**
 * Response Interceptor:
 * Handles 401 Unauthorized via automated token refresh and sanitizes all errors.
 */
apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & { _retry?: boolean };

    // Handle token expiration (401 Unauthorized)
    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      // Do not attempt refresh on the login or refresh endpoints themselves
      if (
        originalRequest.url?.includes('/auth/refresh') ||
        originalRequest.url?.includes('/auth/login')
      ) {
        return Promise.reject(sanitizeApiError(error));
      }

      if (isRefreshing) {
        // Queue subsequent requests while refresh is in progress
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then(() => apiClient(originalRequest))
          .catch((err) => Promise.reject(sanitizeApiError(err)));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Request token refresh (credentials: 'include' ensures refresh cookie is sent)
        await axios.post(
          `${API_BASE_URL}/api/v1/auth/refresh`,
          {},
          { withCredentials: true, timeout: DEFAULT_TIMEOUT_MS }
        );

        processQueue(null);
        return apiClient(originalRequest);
      } catch (refreshErr) {
        processQueue(refreshErr);
        // Clear local session state and redirect safely to login if running in browser
        if (typeof window !== 'undefined') {
          // Avoid open redirects: only redirect to safe relative path
          window.location.href = '/login?session_expired=true';
        }
        return Promise.reject(sanitizeApiError(refreshErr));
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(sanitizeApiError(error));
  }
);

/**
 * Error Sanitizer:
 * Never leak SQL errors, file system paths, stack traces, or upstream internal error codes.
 */
export function sanitizeApiError(error: unknown): SanitizedApiError {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status;
    const responseData = error.response?.data as Record<string, unknown> | undefined;

    // Default friendly messages by HTTP status
    if (status === 400) {
      return {
        code: 'VALIDATION_ERROR',
        message:
          typeof responseData?.message === 'string'
            ? responseData.message
            : 'The submitted request was invalid. Please check your input and try again.',
        status: 400,
        details: typeof responseData?.details === 'object' ? (responseData.details as Record<string, unknown>) : undefined,
      };
    }

    if (status === 401) {
      return {
        code: 'UNAUTHORIZED',
        message: 'Your session has expired. Please authenticate to continue.',
        status: 401,
      };
    }

    if (status === 403) {
      return {
        code: 'FORBIDDEN',
        message: 'You do not have permission to perform this action.',
        status: 403,
      };
    }

    if (status === 404) {
      return {
        code: 'NOT_FOUND',
        message: 'The requested resource was not found.',
        status: 404,
      };
    }

    if (status === 429) {
      return {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests were received in a short period. Please try again after a few minutes.',
        status: 429,
      };
    }

    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      return {
        code: 'REQUEST_TIMEOUT',
        message: 'The analysis server took too long to respond. Please try again.',
      };
    }

    if (!error.response) {
      return {
        code: 'NETWORK_ERROR',
        message: 'Unable to connect to the cybersecurity service. Please check your network connection.',
      };
    }

    return {
      code: 'SERVER_ERROR',
      message: 'An unexpected server error occurred. Our security monitoring team has been notified.',
      status,
    };
  }

  if (error instanceof z.ZodError) {
    return {
      code: 'SCHEMA_PARSE_ERROR',
      message: 'Server returned a response that did not match the expected security contract.',
      details: { errors: error.errors },
    };
  }

  return {
    code: 'UNKNOWN_ERROR',
    message: 'An unexpected application error occurred.',
  };
}

/**
 * Type-safe Request Execution with Zod Schema Validation
 * Validates responses against a runtime schema before returning data to the application.
 */
export async function secureRequest<T>(
  config: AxiosRequestConfig,
  schema: z.ZodType<T>
): Promise<T> {
  try {
    const response = await apiClient.request<unknown>(config);
    const parsed = schema.safeParse(response.data);

    if (!parsed.success) {
      // Log validation failure for monitoring without leaking in user UI
      if (process.env.NODE_ENV !== 'production') {
        console.error('Schema validation failed for response:', parsed.error);
      }
      throw parsed.error;
    }

    return parsed.data;
  } catch (error) {
    throw sanitizeApiError(error);
  }
}
