/**
 * @file packages/backend/src/upload/file-validator.ts
 * @description Secure file upload validation pipeline for CyberGuard India.
 * Implements strict magic byte inspection, double extension detection,
 * filename sanitization, size/duration thresholds, archive rejection, and integrity hashing.
 * 
 * SECURITY RATIONALE:
 * - Never trust client-supplied Content-Type or file extensions: attackers spoof these trivially.
 * - Enforce strict magic byte checking against verified byte offsets.
 * - Enforce size limits per MIME category to prevent resource exhaustion (DoS).
 * - Reject archives (ZIP, 7z, RAR, etc.) to eliminate decompression bombs and hidden executable payloads.
 * - Sanitize filenames against directory traversal, control characters, null bytes, and double extensions.
 */

import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';

/**
 * Supported MIME categories.
 */
export type FileCategory = 'image' | 'audio' | 'video' | 'document';

/**
 * Magic byte pattern definition.
 */
export interface MagicByteDefinition {
  readonly mimeType: string;
  readonly category: FileCategory;
  readonly maxSizeBytes: number;
  readonly extensions: readonly string[];
  /**
   * Signature matching logic against the file buffer.
   */
  readonly matches: (buffer: Buffer) => boolean;
}

/**
 * Strict size limits per category in bytes:
 * - Images: 10MB
 * - Audio: 25MB
 * - Video: 50MB
 * - Documents: 5MB
 */
export const CATEGORY_SIZE_LIMITS: Record<FileCategory, number> = {
  image: 10 * 1024 * 1024,      // 10 MB
  audio: 25 * 1024 * 1024,      // 25 MB
  video: 50 * 1024 * 1024,      // 50 MB
  document: 5 * 1024 * 1024,    // 5 MB
} as const;

/**
 * Media duration limits:
 * - Audio: 5 minutes (300 seconds)
 * - Video: 2 minutes (120 seconds)
 */
export const MEDIA_DURATION_LIMITS = {
  audioSeconds: 300,
  videoSeconds: 120,
} as const;

/**
 * Maximum allowed decompressed payload size (100MB) for bomb protection.
 */
export const MAX_DECOMPRESSED_SIZE_BYTES = 100 * 1024 * 1024;

/**
 * Dangerous extensions that must never appear in any extension position
 * (preventing double extension attacks like 'report.php.jpg' or 'invoice.exe.pdf').
 */
const DANGEROUS_EXTENSIONS = new Set([
  'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
  'exe', 'dll', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'wsf', 'wsh',
  'sh', 'bash', 'csh', 'ksh', 'zsh',
  'js', 'mjs', 'cjs', 'ts', 'jsx', 'tsx',
  'jar', 'war', 'ear', 'class',
  'py', 'pyc', 'pyo', 'pyd',
  'rb', 'pl', 'pm', 'cgi',
  'asp', 'aspx', 'jsp', 'jspx',
  'msi', 'com', 'scr', 'hta', 'cpl',
  'elf', 'bin', 'so', 'dylib'
]);

/**
 * Archive magic byte signatures that must be explicitly rejected
 * to prevent archive smuggling and zip bombs.
 */
const ARCHIVE_SIGNATURES: Array<{ name: string; match: (buf: Buffer) => boolean }> = [
  // PK zip header (PK\x03\x04 or PK\x05\x06 or PK\x07\x08)
  {
    name: 'ZIP / Office Open XML',
    match: (b: Buffer) => b.length >= 4 && b[0] === 0x50 && b[1] === 0x4B &&
      (b[2] === 0x03 || b[2] === 0x05 || b[2] === 0x07) &&
      (b[3] === 0x04 || b[3] === 0x06 || b[3] === 0x08),
  },
  // 7-Zip header (7z\xBC\xAF\x27\x1C)
  {
    name: '7-Zip',
    match: (b: Buffer) => b.length >= 6 &&
      b[0] === 0x37 && b[1] === 0x7A && b[2] === 0xBC && b[3] === 0xAF && b[4] === 0x27 && b[5] === 0x1C,
  },
  // RAR (Rar!\x1A\x07)
  {
    name: 'RAR',
    match: (b: Buffer) => b.length >= 7 &&
      b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21 && b[4] === 0x1A && b[5] === 0x07,
  },
  // GZIP (1F 8B)
  {
    name: 'GZIP',
    match: (b: Buffer) => b.length >= 2 && b[0] === 0x1F && b[1] === 0x8B,
  },
  // BZIP2 (42 5A 68)
  {
    name: 'BZIP2',
    match: (b: Buffer) => b.length >= 3 && b[0] === 0x42 && b[1] === 0x5A && b[2] === 0x68,
  },
  // TAR (ustar at offset 257)
  {
    name: 'TAR',
    match: (b: Buffer) => b.length >= 262 &&
      b[257] === 0x75 && b[258] === 0x73 && b[259] === 0x74 && b[260] === 0x61 && b[261] === 0x72,
  },
  // XZ (FD 37 7A 58 5A 00)
  {
    name: 'XZ',
    match: (b: Buffer) => b.length >= 6 &&
      b[0] === 0xFD && b[1] === 0x37 && b[2] === 0x7A && b[3] === 0x58 && b[4] === 0x5A && b[5] === 0x00,
  },
];

/**
 * ALLOWED_TYPES map with verified magic byte signatures.
 */
export const ALLOWED_TYPES: readonly MagicByteDefinition[] = [
  // --- IMAGES ---
  // JPEG: FF D8 FF
  {
    mimeType: 'image/jpeg',
    category: 'image',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.image,
    extensions: ['jpg', 'jpeg'],
    matches: (b) => b.length >= 3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF,
  },
  // PNG: 89 50 4E 47 (0x89 'PNG')
  {
    mimeType: 'image/png',
    category: 'image',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.image,
    extensions: ['png'],
    matches: (b) => b.length >= 8 &&
      b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47 &&
      b[4] === 0x0D && b[5] === 0x0A && b[6] === 0x1A && b[7] === 0x0A,
  },
  // WebP: RIFF (52 49 46 46) ... WEBP (57 45 42 50) at offset 8
  {
    mimeType: 'image/webp',
    category: 'image',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.image,
    extensions: ['webp'],
    matches: (b) => b.length >= 12 &&
      b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50,
  },

  // --- AUDIO ---
  // MP3: ID3 tag header (49 44 33) OR MPEG Audio sync frame (FF FB / FF F3 / FF F2)
  {
    mimeType: 'audio/mpeg',
    category: 'audio',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.audio,
    extensions: ['mp3'],
    matches: (b) => {
      if (b.length >= 3 && b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) {
        return true; // ID3v2 container
      }
      if (b.length >= 2 && b[0] === 0xFF) {
        // Sync frame MPEG-1 Layer 3 (FF FB / FF FA) or MPEG-2 / 2.5 (FF F3 / FF F2)
        const second = b[1] ?? 0;
        return (second & 0xE0) === 0xE0 && (second & 0x06) !== 0x00;
      }
      return false;
    },
  },
  // WAV: RIFF (52 49 46 46) ... WAVE (57 41 56 45) at offset 8
  {
    mimeType: 'audio/wav',
    category: 'audio',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.audio,
    extensions: ['wav'],
    matches: (b) => b.length >= 12 &&
      b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x41 && b[10] === 0x56 && b[11] === 0x45,
  },
  // OGG: OggS (4F 67 67 53)
  {
    mimeType: 'audio/ogg',
    category: 'audio',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.audio,
    extensions: ['ogg', 'oga'],
    matches: (b) => b.length >= 4 &&
      b[0] === 0x4F && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53,
  },
  // M4A / AAC: ftyp with 'M4A ' / 'mp42' brand OR ADTS header (FF F1 / FF F9)
  {
    mimeType: 'audio/mp4',
    category: 'audio',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.audio,
    extensions: ['m4a', 'aac'],
    matches: (b) => {
      // ADTS header
      if (b.length >= 2 && b[0] === 0xFF && ((b[1] ?? 0) & 0xF6) === 0xF0) {
        return true;
      }
      // MP4 ftyp container with M4A brand
      if (b.length >= 12) {
        const isFtyp = b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70;
        if (isFtyp) {
          const brand = b.subarray(8, 12).toString('ascii');
          return brand === 'M4A ' || brand === 'mp42' || brand === 'isom';
        }
      }
      return false;
    },
  },

  // --- VIDEO ---
  // MP4: ISO base media file format with ftyp (66 74 79 70) at offset 4
  {
    mimeType: 'video/mp4',
    category: 'video',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.video,
    extensions: ['mp4'],
    matches: (b) => {
      if (b.length >= 12) {
        const isFtyp = b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70;
        if (isFtyp) {
          const brand = b.subarray(8, 12).toString('ascii');
          // Standard video brands
          return brand === 'isom' || brand === 'iso2' || brand === 'mp41' ||
                 brand === 'mp42' || brand === 'avc1' || brand === 'dash';
        }
      }
      return false;
    },
  },
  // WebM: EBML header (1A 45 DF A3)
  {
    mimeType: 'video/webm',
    category: 'video',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.video,
    extensions: ['webm'],
    matches: (b) => b.length >= 4 &&
      b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3,
  },

  // --- DOCUMENTS ---
  // PDF: %PDF (25 50 44 46)
  {
    mimeType: 'application/pdf',
    category: 'document',
    maxSizeBytes: CATEGORY_SIZE_LIMITS.document,
    extensions: ['pdf'],
    matches: (b) => b.length >= 4 &&
      b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46,
  },
] as const;

/**
 * Validated file result structure.
 */
export interface ValidatedFileMetadata {
  id: string;
  originalName: string;
  storageKey: string;
  mimeType: string;
  category: FileCategory;
  sizeBytes: number;
  sha256Hash: string;
  estimatedDurationSeconds?: number;
}

/**
 * Zod schema for runtime validation of the metadata output.
 */
export const ValidatedFileMetadataSchema = z.object({
  id: z.string().uuid(),
  originalName: z.string().min(1).max(255),
  storageKey: z.string().uuid(),
  mimeType: z.string().min(3),
  category: z.enum(['image', 'audio', 'video', 'document']),
  sizeBytes: z.number().int().positive(),
  sha256Hash: z.string().regex(/^[a-f0-9]{64}$/),
  estimatedDurationSeconds: z.number().nonnegative().optional(),
});

/**
 * Custom error hierarchy for file validation failures.
 */
export class FileValidationError extends Error {
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'FileValidationError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Strips path traversal, null bytes, control chars, normalizes unicode,
 * enforces length limits, and prevents extension tampering.
 */
export function sanitizeFilename(filename: string): string {
  if (!filename || typeof filename !== 'string') {
    return 'unnamed_file';
  }

  // 1. Remove null bytes immediately
  let cleaned = filename.replace(/\0/g, '');

  // 2. Normalize Unicode using Canonical Composition (NFC)
  cleaned = cleaned.normalize('NFC');

  // 3. Strip directory traversal tokens and backslashes
  cleaned = cleaned.replace(/[\/\\]+/g, '_');
  cleaned = cleaned.replace(/\.\.+/g, '.');

  // 4. Strip control characters (ASCII 0x00-0x1F and 0x7F)
  cleaned = cleaned.replace(/[\x00-\x1F\x7F]/g, '');

  // 5. Trim leading/trailing whitespace and trailing dots
  cleaned = cleaned.trim().replace(/^\.+/, '').replace(/\.+$/, '');

  // 6. Enforce safe alphanumeric and standard symbol set
  cleaned = cleaned.replace(/[^a-zA-Z0-9._\-]/g, '_');

  // 7. Enforce max length of 255
  if (cleaned.length === 0) {
    return 'sanitized_upload';
  }
  if (cleaned.length > 255) {
    const extIndex = cleaned.lastIndexOf('.');
    if (extIndex !== -1 && cleaned.length - extIndex < 10) {
      const ext = cleaned.substring(extIndex);
      cleaned = cleaned.substring(0, 255 - ext.length) + ext;
    } else {
      cleaned = cleaned.substring(0, 255);
    }
  }

  return cleaned;
}

/**
 * Detects double extension anomalies like 'invoice.php.jpg' or 'malware.exe.pdf'.
 * Throws FileValidationError if a dangerous intermediate extension is detected.
 */
export function validateNoDoubleExtension(filename: string): void {
  const parts = filename.toLowerCase().split('.').filter(Boolean);
  if (parts.length > 2) {
    // Check intermediate tokens
    for (let i = 1; i < parts.length - 1; i++) {
      const part = parts[i];
      if (part && DANGEROUS_EXTENSIONS.has(part)) {
        throw new FileValidationError(
          `Double extension attack detected with suspicious intermediate extension: .${part}`,
          'ERR_DOUBLE_EXTENSION'
        );
      }
    }
  }
}

/**
 * Validates Content-Disposition header format and ensures filename is safe.
 */
export function validateContentDisposition(headerValue?: string): string | null {
  if (!headerValue) return null;

  // Strict regex for standard Content-Disposition format
  const dispositionRegex = /^(inline|attachment)(;\s*filename="?([^";\r\n]+)"?)?$/i;
  const match = headerValue.trim().match(dispositionRegex);
  if (!match) {
    throw new FileValidationError(
      'Malformed or invalid Content-Disposition header',
      'ERR_INVALID_CONTENT_DISPOSITION'
    );
  }

  const rawFilename = match[3];
  return rawFilename ? sanitizeFilename(rawFilename) : null;
}

/**
 * Inspects header bytes for archive signatures and rejects them.
 */
function rejectArchiveSignatures(buffer: Buffer): void {
  for (const archive of ARCHIVE_SIGNATURES) {
    if (archive.match(buffer)) {
      throw new FileValidationError(
        `Archive formats are strictly rejected to prevent zip bomb attacks: detected ${archive.name}`,
        'ERR_ARCHIVE_REJECTED'
      );
    }
  }
}

/**
 * Validates magic byte signatures against allowed list.
 */
function detectMimeByMagicBytes(buffer: Buffer): MagicByteDefinition {
  for (const def of ALLOWED_TYPES) {
    if (def.matches(buffer)) {
      return def;
    }
  }
  throw new FileValidationError(
    'File format not allowed or invalid magic byte signature. File extension/headers are ignored.',
    'ERR_DISALLOWED_TYPE'
  );
}

/**
 * Estimates/validates media duration from file container headers.
 * Throws if duration exceeds defined limits.
 */
function validateMediaDuration(
  buffer: Buffer,
  category: FileCategory,
  mimeType: string
): number | undefined {
  if (category === 'audio') {
    // Basic MP3 header parsing or duration heuristic based on typical minimum bitrate (32kbps)
    // 25MB at 128kbps = ~26 minutes max, so we strictly estimate or check duration
    // For WAV: Parse fmt and data chunk
    if (mimeType === 'audio/wav' && buffer.length > 44) {
      try {
        const byteRate = buffer.readUInt32LE(28);
        const dataLength = buffer.readUInt32LE(40);
        if (byteRate > 0 && dataLength > 0) {
          const durationSeconds = Math.round(dataLength / byteRate);
          if (durationSeconds > MEDIA_DURATION_LIMITS.audioSeconds) {
            throw new FileValidationError(
              `Audio duration (${durationSeconds}s) exceeds maximum allowed limit (${MEDIA_DURATION_LIMITS.audioSeconds}s)`,
              'ERR_DURATION_EXCEEDED'
            );
          }
          return durationSeconds;
        }
      } catch (err) {
        if (err instanceof FileValidationError) throw err;
        // Non-fatal if header is non-standard
      }
    }
  }

  if (category === 'video') {
    // For MP4: Locate 'mvhd' atom to read timescale and duration
    if (mimeType === 'video/mp4') {
      try {
        const mvhdIndex = buffer.indexOf('mvhd');
        if (mvhdIndex !== -1 && mvhdIndex + 24 <= buffer.length) {
          const version = buffer[mvhdIndex + 4] ?? 0;
          let timescale = 0;
          let duration = 0;
          if (version === 0) {
            timescale = buffer.readUInt32BE(mvhdIndex + 16);
            duration = buffer.readUInt32BE(mvhdIndex + 20);
          } else if (version === 1 && mvhdIndex + 36 <= buffer.length) {
            timescale = buffer.readUInt32BE(mvhdIndex + 24);
            const durationHigh = buffer.readUInt32BE(mvhdIndex + 28);
            const durationLow = buffer.readUInt32BE(mvhdIndex + 32);
            duration = durationHigh * 4294967296 + durationLow;
          }

          if (timescale > 0 && duration > 0) {
            const durationSeconds = Math.round(duration / timescale);
            if (durationSeconds > MEDIA_DURATION_LIMITS.videoSeconds) {
              throw new FileValidationError(
                `Video duration (${durationSeconds}s) exceeds maximum allowed limit (${MEDIA_DURATION_LIMITS.videoSeconds}s)`,
                'ERR_DURATION_EXCEEDED'
              );
            }
            return durationSeconds;
          }
        }
      } catch (err) {
        if (err instanceof FileValidationError) throw err;
      }
    }
  }

  return undefined;
}

/**
 * Main file validation entry point.
 * Performs end-to-end security checks:
 * 1. Checks buffer size against global maximum (100MB bomb protection).
 * 2. Rejects any archive magic byte signature.
 * 3. Inspects magic bytes against allowed formats.
 * 4. Checks category-specific size limits.
 * 5. Sanitizes filename and checks for double extensions.
 * 6. Calculates SHA-256 hash for tamper prevention and deduplication.
 * 7. Checks media duration limits where parseable.
 */
export async function validateUploadedFile(params: {
  buffer: Buffer;
  originalFilename: string;
  contentDisposition?: string;
}): Promise<ValidatedFileMetadata> {
  const { buffer, originalFilename, contentDisposition } = params;

  // 1. Decompression bomb check (absolute max size limit)
  if (buffer.length > MAX_DECOMPRESSED_SIZE_BYTES) {
    throw new FileValidationError(
      `File size (${buffer.length} bytes) exceeds absolute safety threshold (${MAX_DECOMPRESSED_SIZE_BYTES} bytes)`,
      'ERR_BOMB_LIMIT_EXCEEDED'
    );
  }

  // 2. Reject all archive formats explicitly
  rejectArchiveSignatures(buffer);

  // 3. Inspect magic bytes
  const typeDef = detectMimeByMagicBytes(buffer);

  // 4. Strict category size limits
  if (buffer.length > typeDef.maxSizeBytes) {
    throw new FileValidationError(
      `File size (${buffer.length} bytes) exceeds limit for ${typeDef.category} (${typeDef.maxSizeBytes} bytes)`,
      'ERR_CATEGORY_SIZE_EXCEEDED'
    );
  }

  // 5. Filename sanitization & double extension rejection
  const headerFilename = validateContentDisposition(contentDisposition);
  const baseFilename = headerFilename || originalFilename;
  const sanitizedName = sanitizeFilename(baseFilename);
  validateNoDoubleExtension(sanitizedName);

  // 6. Media duration checks
  const estimatedDuration = validateMediaDuration(buffer, typeDef.category, typeDef.mimeType);

  // 7. Compute cryptographically secure SHA-256 hash
  const sha256Hash = createHash('sha256').update(buffer).digest('hex');

  const metadata: ValidatedFileMetadata = {
    id: randomUUID(),
    originalName: sanitizedName,
    storageKey: randomUUID(),
    mimeType: typeDef.mimeType,
    category: typeDef.category,
    sizeBytes: buffer.length,
    sha256Hash,
    ...(estimatedDuration !== undefined ? { estimatedDurationSeconds: estimatedDuration } : {}),
  };

  return ValidatedFileMetadataSchema.parse(metadata);
}
