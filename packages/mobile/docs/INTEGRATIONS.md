# JanVaani — Service Integrations Matrix (Real, Mocked, & Planned)

| Subsystem / Service | Implementation Status | Integration Architecture & Technical Details |
| :--- | :--- | :--- |
| **Indian Fraud Heuristics** | **REAL (Active)** | Offline-first, on-device rule evaluation for Digital Arrest, UPI reverse charge, utility disconnection phishing, and remote access apps. |
| **English & Hindi Localization** | **REAL (Active)** | 100% human-reviewed safety-critical string tables in `packages/mobile/src/localization/en.ts` and `hi.ts`. |
| **22 Scheduled Languages Catalog** | **REAL (Active)** | Comprehensive registry (`languages.ts`) with native script rendering and explicit *"English Fallback / Review Pending"* disclosures. |
| **Bhashini Sovereign AI Adapter** | **MOCKED / DEV READY** | Server-side adapter in `packages/backend/src/integrations/bhashini.ts` with ULCA API schema for ASR, Translation, and TTS. Configured with placeholder API keys in development template. |
| **Official Public Cyber Advisories** | **REAL (Active)** | Curated database of verified notices from MHA I4C, CERT-In, NPCI, RBI, and DoT Sanchar Saathi with official source URLs. |
| **ClamAV Malware Daemon** | **REAL (Active)** | Socket-based INSTREAM daemon scanning in `packages/backend/src/upload/scanner.ts`, mapped to `clamav/clamav:1.3` in `docker-compose.yml`. |
| **Encrypted Object Storage** | **REAL (Active)** | S3 / MinIO private object storage in `packages/backend/src/upload/storage.ts` using random UUID keys, AES-256 SSE, and 30-day lifecycle shredding. |
| **PostgreSQL & Prisma ORM** | **REAL (Active)** | Relational schema in `packages/backend/prisma/schema.prisma` with 11 tables, enum types, and cryptographic audit chains. |
| **Deepfake Video & Audio Scoring** | **STUBBED WITH DISCLAIMER** | Documented stub with strict Trust & Safety banner: *"Authenticity analysis is probabilistic; compression artifacts cause false scores. Never accuse individuals based solely on an AI score."* |
| **URL Threat Intelligence** | **REAL (Passive)** | Passive domain inspection without crawling; anti-SSRF protections block RFC 1918 and loopback lookups. |
