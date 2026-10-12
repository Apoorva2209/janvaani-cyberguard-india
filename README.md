# JanVaani CyberGuard India

JanVaani is an India-first mobile and web prototype for checking suspicious calls, messages, links, and media. It provides explainable risk indicators and safety guidance; it does not guarantee detection, identify a caller, or represent a Government of India service.

## Project layout

- `packages/mobile` — Expo / React Native app for Android and iOS
- `packages/frontend` — Next.js web interface
- `packages/backend` — API, detection pipeline, auth, privacy, and upload handling
- `packages/shared` — shared types
- `packages/mobile/docs` — build notes, demo script, integrations, privacy notice, and threat model

## Requirements

- Node.js 20 or later and npm
- Docker Desktop for the optional local database/cache services
- Expo tooling for mobile development; platform build requirements apply for native builds

## Getting started

1. Copy the relevant `.env.example` files to local `.env` files and set development-only values. Never commit `.env` files or production credentials.
2. Install dependencies from the repository root with `npm ci`.
3. Start the web and API workspaces with `npm run dev`.
4. Start the mobile app with `npm run mobile:start`; use `npm run mobile:android` for an Android development device/emulator.

Review `packages/mobile/docs/BUILD_INSTRUCTIONS.md` and `packages/mobile/docs/INTEGRATIONS.md` for platform and service notes. BHASHINI, reputation, and media-analysis services require separately configured credentials and must remain server-side.

## Safety and status

Detection results are preliminary indicators, not proof that content is genuine or fraudulent. Files are not guaranteed to be analyzed unless a real detector is configured. Verify important claims through independently located official sources. In India, financial cyber fraud can be reported at [cybercrime.gov.in](https://cybercrime.gov.in/) or by calling 1930.

This repository is a prototype and has not been independently security-certified. Review the threat model, retention settings, access controls, and integrations before any real-world deployment.
