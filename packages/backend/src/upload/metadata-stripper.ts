/**
 * @file packages/backend/src/upload/metadata-stripper.ts
 * @description Privacy-preserving metadata sanitization engine for CyberGuard India.
 * Removes EXIF, GPS location tags, camera fingerprints, software tags, and author info
 * from images (JPEG, PNG), documents (PDF), and audio (MP3).
 * 
 * SECURITY & PRIVACY RATIONALE:
 * - Digital Evidence / Citizen Reports often inadvertently contain sensitive GPS coordinates,
 *   device IMEI/serials, or real names in EXIF/PDF metadata.
 * - Under India's Digital Personal Data Protection Act (DPDP Act 2023), processing must minimize
 *   unnecessary PII exposure. Stripping metadata protects whistleblowers and victims.
 * - Orientation preservation: image orientation is read from EXIF prior to stripping and
 *   retained or preserved so user viewing remains upright.
 * - Strip ID3 tags from audio to eliminate personal recorder/device tags.
 * - Log strictly that sanitization took place along with byte changes; NEVER log the sensitive metadata content.
 */

import { createHash } from 'node:crypto';
import { z } from 'zod';

/**
 * Metadata stripping summary log schema.
 */
export const StrippingAuditLogSchema = z.object({
  fileSha256Original: z.string().length(64),
  fileSha256Stripped: z.string().length(64),
  mimeType: z.string(),
  removedCategories: z.array(z.string()),
  originalSizeBytes: z.number().int().nonnegative(),
  strippedSizeBytes: z.number().int().nonnegative(),
  timestamp: z.string().datetime(),
});

export type StrippingAuditLog = z.infer<typeof StrippingAuditLogSchema>;

/**
 * Result of metadata sanitization.
 */
export interface StrippingResult {
  readonly buffer: Buffer;
  readonly modified: boolean;
  readonly removedCategories: readonly string[];
  readonly originalSizeBytes: number;
  readonly strippedSizeBytes: number;
  readonly sha256Stripped: string;
}

/**
 * Metadata Stripper Service.
 */
export class MetadataStripper {
  private readonly auditRecords: StrippingAuditLog[] = [];

  /**
   * Primary entry point: Inspects MIME type and applies appropriate metadata removal pipeline.
   */
  public async stripMetadata(
    buffer: Buffer,
    mimeType: string,
    originalSha256: string
  ): Promise<StrippingResult> {
    const originalSize = buffer.length;
    let resultBuffer = buffer;
    const removed: string[] = [];

    switch (mimeType) {
      case 'image/jpeg': {
        const { buffer: cleanBuf, categories } = this.stripJpegMetadata(buffer);
        resultBuffer = cleanBuf;
        removed.push(...categories);
        break;
      }
      case 'image/png': {
        const { buffer: cleanBuf, categories } = this.stripPngMetadata(buffer);
        resultBuffer = cleanBuf;
        removed.push(...categories);
        break;
      }
      case 'application/pdf': {
        const { buffer: cleanBuf, categories } = this.stripPdfMetadata(buffer);
        resultBuffer = cleanBuf;
        removed.push(...categories);
        break;
      }
      case 'audio/mpeg': {
        const { buffer: cleanBuf, categories } = this.stripMp3Metadata(buffer);
        resultBuffer = cleanBuf;
        removed.push(...categories);
        break;
      }
      default:
        // Other formats (e.g. WebP, WAV) pass through or can be extended
        break;
    }

    const modified = resultBuffer.length !== originalSize || !resultBuffer.equals(buffer);
    const sha256Stripped = createHash('sha256').update(resultBuffer).digest('hex');

    // Audit log records ONLY the fact that stripping took place - NEVER stripped PII
    const logEntry: StrippingAuditLog = {
      fileSha256Original: originalSha256,
      fileSha256Stripped: sha256Stripped,
      mimeType,
      removedCategories: removed.length > 0 ? removed : ['NONE'],
      originalSizeBytes: originalSize,
      strippedSizeBytes: resultBuffer.length,
      timestamp: new Date().toISOString(),
    };

    this.auditRecords.push(StrippingAuditLogSchema.parse(logEntry));

    return {
      buffer: resultBuffer,
      modified,
      removedCategories: removed,
      originalSizeBytes: originalSize,
      strippedSizeBytes: resultBuffer.length,
      sha256Stripped,
    };
  }

  /**
   * Strips EXIF (APP1), XMP (APP1), Photoshop IRB (APP13), and Comments (COM) from JPEG files.
   * Preserves image orientation by extracting orientation value and embedding a clean minimal EXIF block.
   */
  private stripJpegMetadata(buffer: Buffer): { buffer: Buffer; categories: string[] } {
    if (buffer.length < 4 || buffer[0] !== 0xFF || buffer[1] !== 0xD8) {
      return { buffer, categories: [] };
    }

    const removedCategories: string[] = [];
    const chunks: Buffer[] = [Buffer.from([0xFF, 0xD8])]; // Start with SOI
    let offset = 2;
    let orientation = 1; // Default upright

    while (offset < buffer.length) {
      if (buffer[offset] !== 0xFF) {
        // Unexpected marker boundary; append remaining
        chunks.push(buffer.subarray(offset));
        break;
      }

      const marker = buffer[offset + 1] ?? 0;
      offset += 2;

      // Standalone markers without length: RST0-7 (D0-D7), SOI (D8), EOI (D9), TEM (01)
      if (marker === 0xD9) {
        chunks.push(Buffer.from([0xFF, 0xD9])); // EOI
        break;
      }
      if ((marker >= 0xD0 && marker <= 0xD7) || marker === 0x01) {
        chunks.push(Buffer.from([0xFF, marker]));
        continue;
      }

      if (offset + 2 > buffer.length) break;
      const length = buffer.readUInt16BE(offset);
      const segmentEnd = offset + length;
      if (segmentEnd > buffer.length) break;

      const segmentData = buffer.subarray(offset + 2, segmentEnd);

      // APP1: EXIF or XMP
      if (marker === 0xE1) {
        // Check for EXIF
        if (segmentData.length >= 6 && segmentData.subarray(0, 6).toString('ascii') === 'Exif\0\0') {
          orientation = this.extractJpegExifOrientation(segmentData.subarray(6)) || 1;
          removedCategories.push('EXIF_GPS_CAMERA_INFO');
        } else {
          removedCategories.push('XMP_METADATA');
        }
        offset = segmentEnd;
        continue; // Drop marker
      }

      // APP2: FlashPix or ICC profile (strip if not essential)
      if (marker === 0xE2) {
        // Keep ICC profile for color correctness, drop other APP2
        const isIcc = segmentData.length >= 12 && segmentData.subarray(0, 11).toString('ascii') === 'ICC_PROFILE';
        if (!isIcc) {
          removedCategories.push('APP2_METADATA');
          offset = segmentEnd;
          continue;
        }
      }

      // APP13: IPTC / Photoshop IRB
      if (marker === 0xED) {
        removedCategories.push('IPTC_PHOTOSHOP_DATA');
        offset = segmentEnd;
        continue; // Drop
      }

      // COM marker (Comments)
      if (marker === 0xFE) {
        removedCategories.push('JPEG_COMMENTS');
        offset = segmentEnd;
        continue; // Drop
      }

      // Start of Scan (SOS): image data begins after this segment
      if (marker === 0xDA) {
        const markerBuf = Buffer.alloc(2);
        markerBuf.writeUInt16BE(0xFF00 | marker, 0);
        const lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16BE(length, 0);
        chunks.push(markerBuf, lenBuf, segmentData, buffer.subarray(segmentEnd));
        break;
      }

      // Safe marker (SOF0, DHT, DQT, APP0 JFIF, etc.): retain
      const markerBuf = Buffer.alloc(2);
      markerBuf.writeUInt16BE(0xFF00 | marker, 0);
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(length, 0);
      chunks.push(markerBuf, lenBuf, segmentData);

      offset = segmentEnd;
    }

    // If orientation was non-default (e.g. rotated), inject minimal clean EXIF containing only orientation
    if (orientation > 1 && orientation <= 8) {
      const minimalExif = this.createMinimalExifOrientationBlock(orientation);
      // Insert right after SOI (index 1)
      chunks.splice(1, 0, minimalExif);
      removedCategories.push('ORIENTATION_NORMALIZED');
    }

    return {
      buffer: Buffer.concat(chunks),
      categories: [...new Set(removedCategories)],
    };
  }

  /**
   * Parses TIFF header inside EXIF segment to find Orientation tag (0x0112).
   */
  private extractJpegExifOrientation(tiffBuf: Buffer): number | null {
    if (tiffBuf.length < 8) return null;
    const isLittleEndian = tiffBuf[0] === 0x49 && tiffBuf[1] === 0x49; // 'II' vs 'MM'
    const readU16 = (off: number) => isLittleEndian ? tiffBuf.readUInt16LE(off) : tiffBuf.readUInt16BE(off);
    const readU32 = (off: number) => isLittleEndian ? tiffBuf.readUInt32LE(off) : tiffBuf.readUInt32BE(off);

    const ifdOffset = readU32(4);
    if (ifdOffset + 2 > tiffBuf.length) return null;

    const numEntries = readU16(ifdOffset);
    let entryOffset = ifdOffset + 2;

    for (let i = 0; i < numEntries; i++) {
      if (entryOffset + 12 > tiffBuf.length) break;
      const tag = readU16(entryOffset);
      if (tag === 0x0112) { // Orientation tag
        const value = readU16(entryOffset + 8);
        return value;
      }
      entryOffset += 12;
    }
    return null;
  }

  /**
   * Generates a completely clean, synthetic APP1 segment containing only the orientation tag.
   */
  private createMinimalExifOrientationBlock(orientation: number): Buffer {
    const tiffHeader = Buffer.from([
      0x49, 0x49, 0x2A, 0x00, // II (Little Endian), 42
      0x08, 0x00, 0x00, 0x00, // Offset to 1st IFD: 8
      0x01, 0x00,             // Number of directory entries: 1
      0x12, 0x01,             // Tag: 0x0112 (Orientation)
      0x03, 0x00,             // Type: SHORT
      0x01, 0x00, 0x00, 0x00, // Count: 1
      orientation, 0x00, 0x00, 0x00, // Value
      0x00, 0x00, 0x00, 0x00  // Next IFD: 0
    ]);

    const prefix = Buffer.from('Exif\0\0', 'ascii');
    const app1Data = Buffer.concat([prefix, tiffHeader]);
    const length = app1Data.length + 2;

    const header = Buffer.alloc(4);
    header[0] = 0xFF;
    header[1] = 0xE1;
    header.writeUInt16BE(length, 2);

    return Buffer.concat([header, app1Data]);
  }

  /**
   * Strips non-essential metadata chunks from PNG files (tEXt, zTXt, iTXt, tIME, eXIf).
   */
  private stripPngMetadata(buffer: Buffer): { buffer: Buffer; categories: string[] } {
    const PNG_SIG = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    if (buffer.length < 8 || !buffer.subarray(0, 8).equals(PNG_SIG)) {
      return { buffer, categories: [] };
    }

    const removedCategories: string[] = [];
    const chunks: Buffer[] = [PNG_SIG];
    let offset = 8;

    const STRIP_CHUNKS = new Set(['tEXt', 'zTXt', 'iTXt', 'tIME', 'eXIf']);

    while (offset + 8 <= buffer.length) {
      const length = buffer.readUInt32BE(offset);
      const chunkType = buffer.subarray(offset + 4, offset + 8).toString('ascii');
      const totalChunkLength = 12 + length; // 4 len + 4 type + data + 4 crc

      if (offset + totalChunkLength > buffer.length) {
        break;
      }

      if (STRIP_CHUNKS.has(chunkType)) {
        removedCategories.push(`PNG_${chunkType}_CHUNK`);
      } else {
        chunks.push(buffer.subarray(offset, offset + totalChunkLength));
      }

      offset += totalChunkLength;
      if (chunkType === 'IEND') break;
    }

    return {
      buffer: Buffer.concat(chunks),
      categories: [...new Set(removedCategories)],
    };
  }

  /**
   * Strips PDF metadata dictionaries (/Info entries like /Author, /Creator, /Title, /Producer)
   * and neutralizes /Metadata streams.
   */
  private stripPdfMetadata(buffer: Buffer): { buffer: Buffer; categories: string[] } {
    let pdfStr = buffer.toString('binary');
    const removedCategories: string[] = [];

    // 1. Sanitize standard /Info dictionary fields
    const sensitiveFields = [
      'Author', 'Creator', 'Producer', 'CreationDate', 'ModDate',
      'Title', 'Subject', 'Keywords', 'Company'
    ];

    for (const field of sensitiveFields) {
      const regex = new RegExp(`(/${field}\\s*\\([^)]*\\)|/${field}\\s*<[^>]*>)`, 'g');
      if (regex.test(pdfStr)) {
        pdfStr = pdfStr.replace(regex, `/${field} ()`);
        removedCategories.push(`PDF_${field.toUpperCase()}`);
      }
    }

    // 2. Neutralize XML /Metadata streams
    const metadataStreamRegex = /(<<[^\r\n]*?\/Type\s*\/Metadata[\s\S]*?stream[\r\n]+)([\s\S]*?)([\r\n]+endstream)/g;
    if (metadataStreamRegex.test(pdfStr)) {
      pdfStr = pdfStr.replace(metadataStreamRegex, '$1<!-- METADATA STRIPPED FOR PRIVACY -->$3');
      removedCategories.push('PDF_XMP_METADATA_STREAM');
    }

    return {
      buffer: Buffer.from(pdfStr, 'binary'),
      categories: [...new Set(removedCategories)],
    };
  }

  /**
   * Strips ID3v2 header and ID3v1 trailer from MP3 audio files.
   */
  private stripMp3Metadata(buffer: Buffer): { buffer: Buffer; categories: string[] } {
    let startOffset = 0;
    let endOffset = buffer.length;
    const removedCategories: string[] = [];

    // 1. Detect and strip ID3v2 at the beginning
    if (buffer.length >= 10 && buffer[0] === 0x49 && buffer[1] === 0x44 && buffer[2] === 0x33) {
      // Synchsafe integer size in bytes 6..9
      const b0 = buffer[6] ?? 0;
      const b1 = buffer[7] ?? 0;
      const b2 = buffer[8] ?? 0;
      const b3 = buffer[9] ?? 0;
      const tagSize = ((b0 & 0x7F) << 21) | ((b1 & 0x7F) << 14) | ((b2 & 0x7F) << 7) | (b3 & 0x7F);

      const flags = buffer[5] ?? 0;
      const hasFooter = (flags & 0x10) !== 0;
      const totalHeaderSize = 10 + tagSize + (hasFooter ? 10 : 0);

      if (totalHeaderSize < buffer.length) {
        startOffset = totalHeaderSize;
        removedCategories.push('AUDIO_ID3V2_TAGS');
      }
    }

    // 2. Detect and strip ID3v1 at the end (128 bytes starting with 'TAG')
    if (endOffset - startOffset >= 128) {
      const tagIndex = endOffset - 128;
      if (
        buffer[tagIndex] === 0x54 &&     // 'T'
        buffer[tagIndex + 1] === 0x41 && // 'A'
        buffer[tagIndex + 2] === 0x47    // 'G'
      ) {
        endOffset = tagIndex;
        removedCategories.push('AUDIO_ID3V1_TAGS');
      }
    }

    const cleanBuffer = buffer.subarray(startOffset, endOffset);
    return {
      buffer: cleanBuffer,
      categories: removedCategories,
    };
  }

  /**
   * Retrieves audit records for compliance reporting.
   */
  public getAuditHistory(): readonly StrippingAuditLog[] {
    return [...this.auditRecords];
  }
}
