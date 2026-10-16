# JanVaani — Cyber Safety for India

JanVaani is a cross-platform app and service prototype for helping people assess suspicious calls, SMS/WhatsApp messages, links, and media. It is designed around a simple idea: show people the warning signs, explain why they matter, and give them a safer next step.

The project takes inspiration from the citizen participation and learning journeys of MY Bharat and Skill India. It is an independent project: it is not operated, approved, or endorsed by those platforms or by the Government of India.

> **Prototype notice:** JanVaani does not guarantee that it will detect every scam, prove that content is true or false, or identify the real person behind a caller ID or phone number. Do not rely on a result as the sole basis for a financial, emergency, or legal decision.

## The problem

Fraud attempts often impersonate banks, UPI services, police, government departments, delivery companies, or family members. They may pressure someone to act quickly, reveal an OTP or UPI PIN, install a remote-access app, or send money. Language barriers and confusing technical warnings can make it harder to assess a message safely.

JanVaani aims to make the first check understandable: users choose the kind of content they received, provide the text or a description, and receive possible risk indicators with practical safety guidance. Where evidence is missing, the app should say so rather than label a message as definitively genuine or fake.

## What is in this repository

| Package | Purpose | Current state |
| --- | --- | --- |
| `packages/mobile` | Android/iOS app built with Expo and React Native | Home, checker, shield, learning, helpline, privacy, and language-picker screens; English and Hindi translation dictionaries; other catalogued languages use an English fallback. Android native code (`android/.../guard`) adds an on-device guard that screens incoming SMS and notifications with local rules; this is a prototype and has not been independently validated |
| `packages/frontend` | Next.js web interface | Separate web client for the project; not a native mobile build |
| `packages/backend` | Fastify API in TypeScript | API routes and modules for checks, authentication, administration, privacy, uploads, and detection orchestration |
| `packages/shared` | Shared TypeScript types | Types used across workspaces |
| `docker-compose.yml` | Local service definitions | PostgreSQL, Redis, MinIO, ClamAV, API, and web services for development experiments |
| `packages/mobile/docs` | Supporting project documents | Build notes, demo script, integration status, privacy notice, and threat model |

## How a check works

1. The user selects a content type and enters a message, a call description, a link, or a media description.
2. The mobile demo runs local heuristic rules against the supplied text and optional claimed-sender details.
3. The result displays possible warning indicators and a safety explanation. A lack of detected indicators does **not** prove that content is safe.
4. For suspected financial cyber fraud in India, the app points users to the official [National Cyber Crime Reporting Portal](https://cybercrime.gov.in/) and the 1930 helpline.

The repository also contains a backend detection pipeline and integration adapters. Their presence in source code does not mean every external service is connected, available, or independently validated.

## Detection and integration status

| Capability | Status in this codebase |
| --- | --- |
| Text-based scam indicators | Local heuristic/rule-based screening is present; it can miss new scams and flag innocent content |
| Caller identity lookup | Not provided; caller ID and supplied numbers may be spoofed |
| Language picker | Registry includes the 22 Scheduled Languages and English; full interface translation is currently present for English and Hindi only |
| BHASHINI | Backend adapter exists, but real use requires valid service access/configuration and end-to-end verification |
| URL reputation | Backend module exists; confirm provider configuration and live-service behavior before relying on it |
| Deepfake / media authenticity | Not a guaranteed live detection feature; do not treat a file upload or score as proof |
| Official-source matching | Backend/source modules exist; confirm the current source data, refresh schedule, and evidence display before deployment |
| Upload scanning/storage | Integration code and local service definitions exist; security, retention, and end-to-end behavior still require validation |

Treat `packages/mobile/docs/INTEGRATIONS.md` as an implementation inventory to verify, not as independent evidence that every listed service is live in a deployed environment.

## Technology

- **Mobile:** React Native 0.74, Expo SDK 51, TypeScript
- **Web:** Next.js 14, React, TypeScript
- **API:** Node.js 20+, Fastify 4, TypeScript
- **Data and local services:** PostgreSQL with Prisma, Redis, MinIO-compatible object storage, ClamAV
- **Language integration path:** BHASHINI adapter on the backend; provider credentials must stay server-side
- **Automation:** GitHub Actions workflow for checks and security-oriented scanning

These are the technologies configured in this repository; they do not imply production readiness or certification.

## Run locally

### Requirements

- Node.js 20 or later and npm
- Docker Desktop only if you want to try the services in `docker-compose.yml`
- Android Studio / Android SDK for local Android emulator builds
- macOS and Xcode for local iOS builds; alternatively use a correctly configured Expo/EAS build environment

### Install dependencies

From the repository root:

```bash
npm ci
```

### Start the app

Start the mobile development server:

```bash
npm run mobile:start
```

For a connected Android emulator/device with its native toolchain installed:

```bash
npm run mobile:android
```

Start the web frontend and API together:

```bash
npm run dev
```

The web workspace uses port 3001 and the API uses port 3000 by default. Set up the relevant local environment files from the provided `.env.example` templates before starting services that require configuration. Never commit `.env` files, access tokens, signing keys, or production credentials.

For more detail, see [mobile build instructions](packages/mobile/docs/BUILD_INSTRUCTIONS.md), [integration notes](packages/mobile/docs/INTEGRATIONS.md), [demo script](packages/mobile/docs/DEMO_SCRIPT.md), [privacy notice](packages/mobile/docs/PRIVACY_NOTICE.md), and [threat model](packages/mobile/docs/THREAT_MODEL.md).

## Submission and reviewer materials

- [Technical design and architecture diagram](docs/ARCHITECTURE.md)
- [Fictional sample cases](docs/sample-cases.json) (contains no real phone numbers, accounts, or citizen messages)
- [MIT License](LICENSE)
- Automated backend rule-engine tests: `packages/backend/src/detection/rules.test.ts`

Run the backend unit tests with `npm test -w packages/backend`. The root `test`
script runs workspace tests where configured; packages without a test script
are not covered by that command. The GitHub Actions workflow also runs
dependency/security checks, but a configured workflow is not evidence that its
latest run passed. Check the repository's Actions tab for the actual run state.

This repository does not include the competition's official presentation
template, a recorded 3–5 minute video, or a verified enrollment certificate.
Those must be prepared and uploaded separately by the team. Do not represent
them as included here.

### Local containers: caution

The Compose file contains development defaults for local experimentation. Replace every default password with a unique development-only value before running it, keep the services bound to trusted local interfaces, and never reuse those values in a shared or production environment. Review the Compose file and the environment templates before starting containers.

## Feature phones (button phones)

Not everyone has a smartphone, so JanVaani also works over plain SMS and voice calls. The backend exposes Twilio-compatible webhooks under `/api/v1/feature-phone`:

| Endpoint | What a person does | What they get |
| --- | --- | --- |
| `POST /sms` | Texts or forwards a suspicious message to the service number | A one-SMS verdict (DANGER / CAUTION / no known signs) with the 1930 helpline |
| `POST /voice` and `POST /voice/menu` | Calls the service number and uses the keypad | A spoken menu: how to report fraud, safety tips, repeat |

The SMS check reuses the same rule engine as the app, replies in a single 160-character message, and never logs or stores message text. The routes stay off until a provider is connected:

```bash
FEATURE_PHONE_AUTH_TOKEN=<provider auth token>     # verifies webhook signatures
FEATURE_PHONE_PUBLIC_URL=https://api.example.in    # public base URL of this API
```

Point your provider's incoming-SMS and incoming-voice webhooks at the endpoints above. A number and a provider account (for example Twilio, Exotel or Kaleyra) are needed and cost money; none is included in this repository. Voice replies are currently in English only.

## Languages

The mobile language registry lists the 22 Scheduled Languages and English, including native names and script metadata. The shipped translation dictionaries currently cover English and Hindi. Other languages use an English fallback and are marked as not yet human-reviewed. The registry is a foundation for broader language support, not a claim that all Indian languages and dialects are already translated or accurately analyzed.

Safety-critical translations should be reviewed by fluent speakers before public use. Machine translation and speech recognition can make mistakes, especially with code-mixed speech, dialects, noisy recordings, and uncommon terms.

## Security and privacy

- Do not enter OTPs, UPI PINs, passwords, CVVs, Aadhaar details, or bank login information.
- Do not upload private documents or media unless you understand where they will be processed and stored.
- Never put secrets in frontend code or commit local environment files.
- Treat user-submitted text, links, and files as untrusted input.
- Review the [threat model](packages/mobile/docs/THREAT_MODEL.md) and [privacy notice](packages/mobile/docs/PRIVACY_NOTICE.md) before using this project with real users.
- The repository has not received an independent security audit, penetration test, or government approval. Configuration and safeguards must be reviewed before deployment.

## Roadmap

1. Validate the mobile and API flows end to end with fictional test cases.
2. Review English and Hindi safety content and establish a human translation workflow for more Indian languages.
3. Connect and verify BHASHINI and reputable URL-reputation services through backend adapters.
4. Add specialist audio/video analysis only with clear user consent, documented limits, and human review for consequential cases.
5. Complete security, privacy, accessibility, and deployment reviews before any real-world launch.

## Contributing

For a hackathon contribution, describe the user problem, the package changed, how you checked it, and any external service or credential required. Use fictional data in examples. Do not submit real citizens' messages, phone numbers, credentials, or private media.

## Reporting suspected cyber fraud in India

Use the official [National Cyber Crime Reporting Portal](https://cybercrime.gov.in/). For financial cyber fraud, call **1930** as soon as possible. JanVaani is an information aid; it does not file a complaint on the user's behalf.
