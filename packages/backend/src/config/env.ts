import { z } from 'zod';

/**
 * Environment configuration schema for CyberGuard India.
 * 
 * Security Rationale:
 * - Fail-fast pattern: Any misconfiguration or missing secret prevents startup, avoiding undefined behavior.
 * - String minimum length bounds: Cryptographic secrets (JWT, Session, CSRF) must possess sufficient entropy (min 32 chars).
 * - Origins parsing: Restricts CORS attack surface to explicit whitelist domains.
 * - Secret exclusion: Config object provides non-enumerable or sanitized logging representation to prevent accidental leaks.
 */
const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('production'),
  PORT: z.coerce.number().int().min(1024).max(65535).default(3000),
  
  // Database & Cache Infrastructure
  DATABASE_URL: z.string().url('DATABASE_URL must be a valid connection URL'),
  REDIS_URL: z.string().url('REDIS_URL must be a valid redis connection string'),
  
  // Cryptographic Secrets (Mandating strong entropy)
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must have at least 32 characters for security entropy'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must have at least 32 characters'),
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must have at least 32 characters'),
  CSRF_SECRET: z.string().min(32, 'CSRF_SECRET must have at least 32 characters'),
  
  // Storage (S3 / MinIO / Object Storage for evidence & incident files)
  S3_BUCKET: z.string().min(3, 'S3_BUCKET is required'),
  S3_ENDPOINT: z.string().url('S3_ENDPOINT must be a valid URL'),
  S3_ACCESS_KEY: z.string().min(8, 'S3_ACCESS_KEY is required'),
  S3_SECRET_KEY: z.string().min(16, 'S3_SECRET_KEY is required'),
  
  // India Sovereign AI Services (Bhashini National Translation & NLP Pipeline)
  BHASHINI_API_KEY: z.string().min(1, 'BHASHINI_API_KEY is required'),
  BHASHINI_PIPELINE_URL: z.string().url('BHASHINI_PIPELINE_URL must be a valid URL'),
  
  // Access Control & CORS Whitelist (comma-delimited or JSON array of allowed origins)
  ALLOWED_ORIGINS: z.string().min(1).transform((val) => {
    return val.split(',').map((origin) => origin.trim()).filter(Boolean);
  }),
  
  // Operational Parameters & Safety Defaults
  MAX_UPLOAD_SIZE_MB: z.coerce.number().positive().max(50).default(10),
  FILE_RETENTION_DAYS: z.coerce.number().int().positive().default(30),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
});

export type EnvConfig = z.infer<typeof envSchema>;

/**
 * Validates process.env variables and freezes the resulting configuration.
 * Exits process immediately with exit code 1 if validation fails to prevent
 * running in an insecure or broken state.
 */
function loadAndValidateConfig(): EnvConfig {
  if (typeof (process as any).loadEnvFile === 'function') {
    for (const envPath of ['.env', 'packages/backend/.env', '../.env', '../../.env']) {
      try {
        (process as any).loadEnvFile(envPath);
      } catch {
        // Ignored if not present
      }
    }
  }

  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    // SECURITY: Format errors cleanly, showing which keys failed validation
    // without printing variable contents in standard error logs.
    const errorDetails = result.error.errors.map((err) => ({
      variable: err.path.join('.'),
      issue: err.message,
    }));

    // Use raw console.error here because loggers depend on configuration
    console.error('FATAL: Environment configuration validation failed:');
    console.error(JSON.stringify(errorDetails, null, 2));
    process.exit(1);
  }

  // Freeze the object to prevent runtime tampering
  return Object.freeze(result.data);
}

export const env: EnvConfig = loadAndValidateConfig();

/**
 * Sanitized configuration representation safe for debugging and health inspection.
 * Explicitly masks all secret credentials.
 */
export function getSanitizedConfig(): Record<string, unknown> {
  return {
    NODE_ENV: env.NODE_ENV,
    PORT: env.PORT,
    ALLOWED_ORIGINS: env.ALLOWED_ORIGINS,
    MAX_UPLOAD_SIZE_MB: env.MAX_UPLOAD_SIZE_MB,
    FILE_RETENTION_DAYS: env.FILE_RETENTION_DAYS,
    RATE_LIMIT_MAX: env.RATE_LIMIT_MAX,
    RATE_LIMIT_WINDOW_MS: env.RATE_LIMIT_WINDOW_MS,
    LOG_LEVEL: env.LOG_LEVEL,
    S3_BUCKET: env.S3_BUCKET,
    S3_ENDPOINT: env.S3_ENDPOINT,
    BHASHINI_PIPELINE_URL: env.BHASHINI_PIPELINE_URL,
    DATABASE_CONFIGURED: Boolean(env.DATABASE_URL),
    REDIS_CONFIGURED: Boolean(env.REDIS_URL),
    SECRETS_MASKED: true,
  };
}
