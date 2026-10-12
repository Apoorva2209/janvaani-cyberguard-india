# JanVaani — Service Integrations Matrix (Real, Mocked, & Planned)

| Subsystem / Service | Implementation Status | Integration Architecture & Technical Details |
| :--- | :--- | :--- |
| **Indian Fraud Heuristics** | **IMPLEMENTED RULES; VALIDATION LIMITED** | Deterministic rule code exists for selected patterns. Coverage is incomplete; no claim of detecting all fraud. Run tests and review `packages/backend/src/detection/rules.ts`. |
| **English & Hindi Localization** | **DICTIONARIES PRESENT; REVIEW SCOPE UNKNOWN** | English and Hindi string tables exist. Do not describe them as fully human-reviewed without documented reviewer sign-off. |
| **22 Scheduled Languages Catalog** | **CATALOG PRESENT; TRANSLATION INCOMPLETE** | Registry (`packages/mobile/src/localization/languages.ts`) includes listed languages and fallback disclosures. Only English and Hindi dictionaries currently exist. |
| **Bhashini Language Services Adapter** | **ADAPTER PRESENT; LIVE SERVICE UNVERIFIED** | `packages/backend/src/integrations/bhashini.ts` contains an integration path. Real credentials, consent behavior, provider access, and end-to-end results must be verified. |
| **Official Public Cyber Advisories** | **SOURCE CODE REQUIRES REVIEW** | Verify each source, citation, freshness, and update process in code before claiming a maintained official advisory feed. |
| **ClamAV Malware Daemon** | **INTEGRATION CODE PRESENT; DEPLOYMENT UNVERIFIED** | Scanner code and a Compose service exist. Test service availability, failure handling, quarantine, and real scan results in the target environment. Malware scanning is not deepfake analysis. |
| **Object Storage** | **INTEGRATION CODE PRESENT; CONTROLS UNVERIFIED** | S3/MinIO code exists. Independently confirm encryption configuration, access policy, deletion, retention, and deployment behavior before storing real evidence. |
| **PostgreSQL & Prisma ORM** | **SCHEMA PRESENT; MIGRATION/OPERATIONS UNVERIFIED** | Prisma schema exists. Validate migrations, backup/restore, access controls, and operational behavior in the deployment environment. |
| **Deepfake Video & Audio Scoring** | **NOT A VALIDATED CAPABILITY** | No claim of reliable live deepfake detection. Never accuse or identify a person based on media analysis. |
| **URL Threat Intelligence** | **RULES/ADAPTERS PRESENT; LIVE REPUTATION UNVERIFIED** | Static indicators are not equivalent to a current threat feed. Do not crawl arbitrary URLs; verify protections and provider configuration before use. |

Status labels describe repository inspection, not an external security audit or
production certification. Re-test each integration in the exact environment
before changing its status to live/verified.
