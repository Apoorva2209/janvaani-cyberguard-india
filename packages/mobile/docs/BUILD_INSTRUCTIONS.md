# JanVaani Mobile — Android APK Build and Installation Guide

JanVaani is configured with **React Native**, **Expo SDK 51**, and native Android project scaffolding for building an installable `.apk` file for Android phones.

---

## 1. Fast Track: Cloud Build Standalone APK (Recommended)

Building the APK via **Expo Application Services (EAS)** is the official, zero-dependency method. You don't need Android Studio or Java installed on your machine; Expo compiles the APK on dedicated cloud nodes and gives you a direct download link and QR code to install on your phone.

### Step 1: Open Terminal and Navigate to Mobile Package
```powershell
$env:Path = "C:\Users\mithr\.nodejs;" + $env:Path
cd C:\Users\mithr\.gemini\antigravity\scratch\cyberguard-india\packages\mobile
```

### Step 2: Log in to Expo (Free Account)
If you don't have an Expo account, register for free at [expo.dev/signup](https://expo.dev/signup) (takes 30 seconds).
Then log in:
```powershell
npx eas-cli login
```

### Step 3: Trigger Android APK Cloud Build
We have pre-configured `eas.json` with the `preview` profile set to `buildType: "apk"`:
```powershell
npx eas-cli build --platform android --profile preview
```

### What happens next:
1. EAS will ask: *"Generate a new Android Keystore?"* $\rightarrow$ Type `Y` (Enter).
2. EAS uploads the project and compiles the Android APK on cloud build servers.
3. Once completed (takes ~3 to 5 minutes), EAS will display:
   - **Direct APK download link** (e.g., `https://expo.dev/artifacts/eas/...apk`)
   - **QR Code**: Scan the QR code with your Android phone's camera to download and install the APK directly on your phone!

---

## 2. Option B: Local Android Build via Android Studio

The complete native Android project has already been generated in [`packages/mobile/android`](file:///C:/Users/mithr/.gemini/antigravity/scratch/cyberguard-india/packages/mobile/android) via `npx expo prebuild`.

If you have **Android Studio** installed on your PC:
1. Open Android Studio.
2. Select **Open Existing Project** and choose:
   `C:\Users\mithr\.gemini\antigravity\scratch\cyberguard-india\packages\mobile\android`
3. Wait for Gradle sync to complete.
4. Click **Build** $\rightarrow$ **Build Bundle(s) / APK(s)** $\rightarrow$ **Build APK(s)**.
5. Android Studio will generate the APK at:
   `packages/mobile/android/app/build/outputs/apk/debug/app-debug.apk`
6. Transfer this `.apk` to your phone via USB or WhatsApp and tap to install!

---

## 3. Option C: Instant Native Phone Testing via Expo Go (Zero Build Delay)

If you want to run the live native app on your phone immediately without waiting for the build queue:
1. Install **Expo Go** from the Google Play Store on your Android phone.
2. Start the bundler on your PC:
   ```powershell
   $env:Path = "C:\Users\mithr\.nodejs;" + $env:Path
   cd C:\Users\mithr\.gemini\antigravity\scratch\cyberguard-india\packages\mobile
   npx expo start
   ```
3. Open Expo Go on your phone, tap **Scan QR code**, and scan the QR displayed in your terminal.
4. The full native app opens immediately on your phone!
