# JanVaani

**Cyber safety for India: spot scam messages, links and calls, and know what to do next.**

[![Security CI](https://github.com/Apoorva2209/janvaani-cyberguard-india/actions/workflows/security.yml/badge.svg)](https://github.com/Apoorva2209/janvaani-cyberguard-india/actions/workflows/security.yml)
[![Build Native Apps](https://github.com/Apoorva2209/janvaani-cyberguard-india/actions/workflows/build-apps.yml/badge.svg)](https://github.com/Apoorva2209/janvaani-cyberguard-india/actions/workflows/build-apps.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

JanVaani (जनवाणी) shows people the warning signs in a suspicious message, explains why they matter, and points to a safe next step, including the **1930** cyber-fraud helpline. It runs as a native app on Android, iOS, Windows and macOS, as an app on Linux, and through plain SMS and voice calls for people with button phones.

> **Prototype.** JanVaani cannot catch every scam, prove that a message is true or false, or identify the real person behind a number or sender name. Do not rely on a result alone for a financial, emergency or legal decision. It is an independent project and is not operated or endorsed by any government body.

## Download

Version **1.0** is on the [Releases page](https://github.com/Apoorva2209/janvaani-cyberguard-india/releases/latest).

| Platform | File | Install |
| --- | --- | --- |
| Windows 10 / 11 | `JanVaani-Setup.exe` | Run it and accept the administrator prompt. SmartScreen shows "Windows protected your PC" because the installer is self-signed: choose **More info → Run anyway**. Remove it in *Settings → Apps*. |
| Android | `JanVaani-android.apk` | Open it and allow "install unknown apps". It is signed with a debug key, so it is for testing and sideloading. |
| macOS | `JanVaani-macos.zip` | Unzip, move to Applications, then right-click → **Open** the first time (unsigned). |
| Linux | `JanVaani-linux-x86_64.AppImage`, `JanVaani-linux-amd64.deb` | `chmod +x` the AppImage and run it, or `sudo apt install ./JanVaani-linux-amd64.deb`. |
| iOS | `JanVaani-ios-simulator.zip` | Simulator build for Xcode users. A build for real iPhones needs an Apple Developer account. |
| Button phones | no download | Text a suspicious message to the service number. See [Button phones](#button-phones). |

## What it does

- **Checks a message, link or call description** and lists the warning signs it found, with a plain-language explanation. No result means "no known signs", never "safe".
- **Detects scams automatically on Android.** It checks incoming SMS and notifications from WhatsApp, Telegram, Gmail, Outlook and other chat and email apps as they arrive, and raises an alert. Everything is checked on the phone and nothing is uploaded.
- **Describes the sender.** It tells you whether a message came from a business sender ID, an ordinary mobile number, an international number or a short code, and warns when a "bank" writes from a personal number. It never claims to know who the person really is.
- **Guides reporting.** Official portal and helpline details, plus a complaint kit that collects what you need.
- **Works in English and Hindi**, with a registry ready for the other 22 scheduled languages.

### Automatic protection on Android

Open the app once. It switches the guard on and asks for SMS and notification permission. One step is yours: switch JanVaani on under Android's *Notification access*, because only you can grant that. If the switch is greyed out for an APK install, open *App info → ⋮ → Allow restricted settings* first.

### What the other platforms can do

| Platform | Automatic detection | Why |
| --- | --- | --- |
| Android | Yes (SMS, WhatsApp, Gmail, Outlook and more) | Android allows notification access with your permission |
| iPhone | Partly: SMS junk filter and caller labels | Apple blocks apps from reading other apps' messages. See [iOS extensions](#ios-extensions). |
| Windows, macOS, Linux | No. Paste or share a message to check it | These systems do not let an app read your mailbox or other apps' messages |
| Button phones | Yes, by texting the service number | See [Button phones](#button-phones) |

### iOS extensions

Two Apple-sanctioned extensions are part of the iOS build (source in `packages/mobile/ios-extensions`):

- **Message Filter** moves SMS from unknown senders that look like scams into the *Junk* tab, using the same rules as Android. Turn it on in *Settings → Messages → Unknown & Spam → SMS Filter*. The text never leaves the phone.
- **Caller Labels** shows "Suspected scam" on calls from numbers in `scam-numbers.txt`. The list ships empty because JanVaani does not invent scam numbers. Add numbers you have verified and rebuild. Turn it on in *Settings → Phone → Call Blocking & Identification*.

### Button phones

People without a smartphone can use JanVaani by SMS and voice. The backend exposes Twilio-compatible webhooks under `/api/v1/feature-phone`:

| Endpoint | What a person does | What they get |
| --- | --- | --- |
| `POST /sms` | Texts or forwards a suspicious message to the service number | One SMS (under 160 characters): DANGER, CAUTION or no known signs, plus the 1930 helpline |
| `POST /voice`, `POST /voice/menu` | Calls the number and uses the keypad | A spoken menu: how to report fraud, safety tips, repeat |

The routes stay off until a provider is connected, and message text is never logged or stored:

```bash
FEATURE_PHONE_AUTH_TOKEN=<provider auth token>     # verifies webhook signatures
FEATURE_PHONE_PUBLIC_URL=https://api.example.in    # public base URL of this API
```

A phone number and a provider account (for example Twilio, Exotel or Kaleyra) are needed and cost money; none is included here. Voice replies are English only for now.

## How a check works

1. You pick the kind of content and enter or share the text.
2. Local rules look for known scam patterns: OTP and UPI PIN requests, digital-arrest threats, fake KYC and account blocks, prize lures, task scams, fake parcels, lookalike links and more.
3. The result shows the warning signs found. Finding none does **not** prove the content is safe.
4. For suspected financial fraud the app points to the [National Cyber Crime Reporting Portal](https://cybercrime.gov.in/) and the **1930** helpline.

## Project layout

One repository, npm workspaces:

| Package | What it is | Stack |
| --- | --- | --- |
| `packages/mobile` | The Android and iOS apps and the shared screens | React Native 0.74, Expo 51, TypeScript, Kotlin (Android guard), Swift (iOS extensions) |
| `packages/desktop` | Native Windows and macOS apps, plus the Windows installer script | React Native for Windows and macOS, Inno Setup |
| `packages/linux` | Linux app (AppImage, deb) | Electron window showing the shared screens, because React Native has no Linux target |
| `packages/backend` | API: checks, accounts, uploads, detection, SMS and voice webhooks | Fastify 5, TypeScript, Prisma, PostgreSQL, Redis, MinIO, ClamAV |
| `packages/frontend` | Web client | Next.js 15, React 18, Tailwind CSS |
| `packages/shared` | Shared TypeScript types | TypeScript |

Android, iOS, Windows and macOS are native apps built from the same screens. All of them are built in GitHub Actions by the *Build Native Apps* workflow, and a version tag such as `v1.0.0` publishes the files to a release.

## Run it locally

You need Node.js 20+ and npm. Docker is only needed for the backend services.

```bash
npm ci                    # install everything
cp .env.example .env      # then replace every placeholder secret

npm run mobile:start      # mobile app (Expo dev server)
npm run mobile:android    # Android emulator or device (needs the Android SDK)
npm run dev               # API (port 3000) and web client (port 3001)
npm run desktop:windows   # Windows app (needs Visual Studio 2022 with UWP and C++)
npm run desktop:macos     # macOS app (needs Xcode and CocoaPods)
```

Tests and checks: `npm test`, `npm run lint`, `npm run type-check`.

You can also skip local toolchains: run the *Build Native Apps* workflow from the Actions tab, or push a tag (`git tag v1.0.1 && git push --tags`).

The Docker Compose file contains development defaults. Replace every default password with a unique value before starting it, keep services on trusted local interfaces, and never reuse those values anywhere shared or in production.

More detail: [mobile build notes](packages/mobile/docs/BUILD_INSTRUCTIONS.md), [integrations](packages/mobile/docs/INTEGRATIONS.md), [demo script](packages/mobile/docs/DEMO_SCRIPT.md), [architecture](docs/ARCHITECTURE.md), [sample cases](docs/sample-cases.json) (fictional data only).

## Status of each capability

| Capability | Status |
| --- | --- |
| Text scam indicators | Local rule-based checks. Can miss new scams and flag innocent text. |
| Sender identity | Not provided. Only the kind of sender ID is described, and numbers can be spoofed. |
| Languages | English and Hindi are translated. The other scheduled languages fall back to English until reviewed by fluent speakers. |
| BHASHINI translation | Backend adapter exists. Needs service access and end-to-end verification. |
| URL reputation | Backend module exists. Confirm provider configuration before relying on it. |
| Deepfake / media authenticity | Not a live feature. A file upload or score is not proof. |
| Upload scanning and storage | Code and local services exist. Security and retention still need validation. |

The repository has not had an independent security audit, penetration test or government approval.

## Security and privacy

- Never enter OTPs, UPI PINs, passwords, CVVs, Aadhaar details or bank logins into any app, including this one.
- Message checks on Android and iOS happen on the device. The SMS and voice service does not log or store message text.
- Treat all submitted text, links and files as untrusted input. Never commit `.env` files or secrets.
- Read the [threat model](packages/mobile/docs/THREAT_MODEL.md) and [privacy notice](packages/mobile/docs/PRIVACY_NOTICE.md) before using this with real users.
- Found a vulnerability? Open a private security advisory on GitHub instead of a public issue.

## Roadmap

1. Test every flow end to end on real devices with fictional cases.
2. Have fluent speakers review the English and Hindi safety text, then add more languages.
3. Connect and verify BHASHINI and a reputable URL-reputation service.
4. Publish signed builds: Google Play, Apple App Store and a trusted Windows certificate.
5. Complete security, privacy, accessibility and deployment reviews before any real-world launch.

## Contributing

Describe the user problem, the package you changed, how you checked it, and any service or credential it needs. Use fictional data in examples. Never submit real people's messages, phone numbers, credentials or private media.

## If you have been scammed

Call **1930** as soon as possible, then report at the official [National Cyber Crime Reporting Portal](https://cybercrime.gov.in/). The sooner you call after losing money, the better the chance of stopping the transfer. JanVaani is an information aid; it does not file a complaint for you.

## License and author

Released under the [MIT License](LICENSE). Built by **Apoorva SV** ([@Apoorva2209](https://github.com/Apoorva2209)).
