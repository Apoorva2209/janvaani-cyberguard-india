# JanVaani Auto-Protection (Android)

JanVaani warns you automatically when an incoming **SMS, WhatsApp, Gmail, Outlook, Telegram** (and other messaging app) message looks like a scam, and gives you a one-tap reporting kit.

## How it works

```
Incoming SMS ──► SmsReceiver ───────┐
                                    ├─► ScamRules (on-device) ─► AlertStore (encrypted) ─► High-priority notification
App notification ─► NotificationWatcher ┘                                                     │
 (WhatsApp, Gmail, Outlook…)                                                                   ▼
                                                    Tap ─► Alerts tab ─► full TS engine ─► Report kit
```

| Piece | File |
|---|---|
| Rules (first pass, deterministic) | `android/.../guard/ScamRules.kt` |
| SMS listener (read-only) | `android/.../guard/SmsReceiver.kt` |
| WhatsApp/email listener | `android/.../guard/NotificationWatcher.kt` |
| Encrypted alert inbox, 30-day expiry | `android/.../guard/AlertStore.kt` |
| Notification with "Call 1930" action | `android/.../guard/AlertNotifier.kt` |
| JS bridge | `android/.../guard/GuardModule.kt`, `src/services/guardBridge.ts` |
| Alerts screen | `src/screens/ShieldScreen.tsx` |
| Complaint draft + official links | `src/services/complaintKit.ts`, `src/components/ReportPanel.tsx` |

## Reporting: what the app does and doesn't do

JanVaani **does not file complaints automatically**. The National Cyber Crime Reporting Portal has no public filing API, and it needs the citizen's own login and OTP. Filing is also the citizen's own legal act. So JanVaani:

- prepares a complaint draft containing the channel, sender, time, verbatim message, links, UPI IDs and phone numbers found, and the warning signs;
- lets you copy or share it with one tap;
- opens **cybercrime.gov.in**, dials **1930**, or opens **Sanchar Saathi – Chakshu** (DoT) to report fraud SMS, calls and WhatsApp messages.

## Platform limits

- **Android only.** iOS doesn't let apps read incoming SMS or other apps' notifications.
- **Not in Expo Go.** This needs the native APK (see build steps below).
- **Google Play.** Play restricts SMS permissions to default-SMS apps, and requires a declaration for notification-listener use. A Play Store release needs either a policy declaration or a switch to notification access only. Sideloaded APKs work as they are.
- Email is covered through the mail app's notifications. Only the preview text Android shows is checked, not the full email body.

## Privacy & security

- All analysis happens on the phone. Nothing is uploaded.
- Only an allow-list of messaging and email apps is inspected. Banking and OTP apps are ignored.
- Alerts are stored with AES-256 (Android Keystore through EncryptedSharedPreferences). At most 100 are kept, each excerpt is capped at 600 characters, and alerts auto-delete after 30 days. You can delete one alert or all of them.
- `allowBackup=false`, so alerts are never copied into cloud backups.
- Logs contain only source, level and score, never message text or numbers.
- The SMS receiver is protected by `BROADCAST_SMS`, so only the OS can trigger it. The app never sends, deletes or forwards SMS. It does not request `READ_SMS`, contacts or storage.
- Message text is treated strictly as data. Links are never opened or fetched.
- Alerts are warning signs, not proof. The app never names or accuses a person.

## Build & test

The `android/` folder now contains hand-written native code. **Do not run `npx expo prebuild --clean`**, because it would delete that code.

```bash
cd packages/mobile
npx eas-cli build --platform android --profile preview
```

Install the APK, open **Alerts**, then:

1. Tap **Allow** and grant the SMS and notification permissions.
2. Tap **Open settings** and turn on notification access for JanVaani.
3. Tap **Send a test scam alert**. A notification should appear within a second.
4. Tap the notification to see the analysis and the report kit.

## Known gaps / next steps

- Rules are English/Hinglish only; add Devanagari and other scripts, then evaluate false-positive and false-negative rates per language.
- Add an optional server-side reputation check (Google Safe Browsing / CERT-In feeds) through the backend, with user consent.
- Add Kotlin unit tests for `ScamRules` (JVM tests; no device needed).
