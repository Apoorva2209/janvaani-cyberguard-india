# JanVaani Privacy Notice & Data Retention Policy (DPDP Act 2023)

**Effective Date:** March 2026  
**Jurisdiction:** Republic of India (Digital Personal Data Protection Act, 2023)

---

## 1. Core Commitment: Privacy by Default

JanVaani is engineered around strict **Data Minimization** (Section 6, DPDP Act 2023). Ordinary checks and assessments require **Zero Account Registration**.

### What We NEVER Solicit or Collect:
- ❌ Aadhaar numbers or government national identity cards
- ❌ One-Time Passwords (OTPs) or Two-Factor SMS codes
- ❌ Unified Payments Interface (UPI) PINs or ATM PINs
- ❌ Internet banking passwords or credit/debit card CVV numbers
- ❌ Contact list access, call logs, or background location telemetry

---

## 2. Information Handled During a Check

| Information Category | Purpose | Legal Basis / Consent | Retention Window |
| :--- | :--- | :--- | :--- |
| **Submitted Content** (Text, link, audio snippet, screenshot) | Heuristic analysis to identify coercion patterns, deceptive domains, or known scam tactics. | Explicit user consent prior to submitting check. | Transient processing; deleted immediately or within maximum 30 days. |
| **Claimed Sender / Number** (Optional) | Matching against published CERT-In / DoT Chakshu spam lists. | Voluntary citizen submission. | Hashed with SHA-256 in audit logs; never published in public suspect directories. |
| **State / District** (Optional) | Identifying regional cyber fraud waves (e.g., electricity discom impersonation). | Voluntary citizen submission. | Aggregated anonymously with zero citizen identifiers. |

---

## 3. Storage Limitation & Cryptographic Shredding (Section 8)

All uploaded screenshots, documents, and media files are stored outside the public web root in private, encrypted object vaults. After 30 days, files undergo automated **Cryptographic Shredding** (pseudo-random byte overwriting) before deletion to prevent forensic reconstruction.

---

## 4. Your Rights as a Data Principal (Section 11)

Under the DPDP Act 2023, you retain full rights over your data:
- **Right to Access [Sec. 11(1)]**: View any audit record tied to your generated UUID report token.
- **Right to Correction [Sec. 11(2)]**: Flag false positive warnings for human reviewer triage.
- **Right to Erasure [Sec. 11(3)]**: Trigger immediate, cascading deletion of your report and associated forensic tokens using the one-click **"DPDPA Right to Erase"** control in the app.

---

## 5. Contact & Grievance Redressal

For questions regarding data processing or to submit a statutory grievance:
- **Designated Data Protection Contact**: `privacy@janvaani.in`
- **Official Cyber Fraud Assistance**: Call **1930** or visit [cybercrime.gov.in](https://cybercrime.gov.in).
