import Foundation

/// On-device scam rules shared by the iOS extensions. This is a Swift port of
/// `ScamRules.kt` (Android), so a message gets the same verdict on both platforms.
/// The result is a risk indicator, never proof. Text is treated strictly as data.
enum ScamRules {
    struct Rule {
        let tactic: String
        let weight: Int
        let pattern: NSRegularExpression
    }

    struct Verdict {
        let score: Int
        let level: String          // "HIGH", "MEDIUM" or "LOW"
        let tactics: [String]
    }

    /// Minimum score that counts as a likely scam.
    static let alertThreshold = 4

    private static func rule(_ tactic: String, _ weight: Int, _ pattern: String) -> Rule? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return nil
        }
        return Rule(tactic: tactic, weight: weight, pattern: regex)
    }

    // Weights: 5 = strong on its own, 3 = suspicious, 2 = supporting signal.
    private static let rules: [Rule] = [
        rule("Asks for OTP / UPI PIN / password", 5,
             #"\b(share|send|tell|enter|provide|forward)\b.{0,30}\b(otp|upi\s*pin|atm\s*pin|cvv|password|mpin)\b"#),
        rule("UPI PIN to 'receive' money", 5,
             #"(upi\s*pin|scan.{0,15}qr).{0,40}\b(receive|get|claim|credit)"#),
        rule("Digital arrest / fake police threat", 5,
             #"digital\s*arrest|\b(cbi|ncb|narcotics|crime\s*branch|customs|ed\s+officer|cyber\s*cell)\b.{0,60}\b(arrest|warrant|case|parcel|video\s*call|skype)"#),
        rule("Remote-access app request", 5,
             #"\b(anydesk|teamviewer|quick\s*support|rustdesk|airdroid)\b"#),
        rule("Install APK file", 5,
             #"\.apk\b|install\s+(this|the)\s+app\s+from\s+(link|here)"#),
        rule("KYC / account block threat", 3,
             #"\b(kyc|pan|aadhaar)\b.{0,40}\b(update|expire|expired|block|blocked|suspend|deactivat)|\b(account|sim|card)\b.{0,20}\b(blocked|suspended|deactivated|will be closed)"#),
        rule("Electricity disconnection threat", 4,
             #"(electricity|bijli|power)\b.{0,60}\b(disconnect|cut|tonight|9[.:]30)"#),
        rule("Lottery / prize / cashback lure", 3,
             #"\b(lottery|jackpot|you\s+(have\s+)?won|winner|lucky\s+draw|cash\s*prize|kbc)\b"#),
        rule("Part-time job / task scam", 3,
             #"\b(part[-\s]?time|work\s+from\s+home|daily\s+income|earn\s+(rs|₹|inr)?\s*\d+)\b.{0,80}\b(telegram|whatsapp|like|review|task|rating)"#),
        rule("Fake parcel / courier / customs", 3,
             #"\b(parcel|courier|fedex|dhl|india\s*post|shipment)\b.{0,60}\b(held|seized|pending|undelivered|address|customs|fee)"#),
        rule("Investment / trading tip group", 3,
             #"\b(stock|ipo|crypto|trading|forex)\b.{0,60}\b(guaranteed|double|\d{2,3}\s*%|vip\s+group|profit)"#),
        rule("Urgency pressure", 2,
             #"\b(urgent|immediately|within\s+\d+\s*(min|hour|hrs)|today\s+only|last\s+chance|act\s+now|turant)\b"#),
        rule("Shortened / hidden link", 2,
             #"\b(bit\.ly|tinyurl\.com|is\.gd|t\.ly|cutt\.ly|rb\.gy|shorturl\.at|goo\.gl)/"#),
        rule("Raw IP or suspicious link", 3,
             #"https?://(\d{1,3}\.){3}\d{1,3}|https?://[^\s/]*(\.xyz|\.top|\.click|\.buzz|\.icu|\.live|\.shop)\b"#),
        rule("Call a personal mobile number", 2,
             #"\b(call|contact|whatsapp)\b.{0,25}(\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b"#),
    ].compactMap { $0 }

    static func evaluate(_ raw: String) -> Verdict {
        // Bound the work regardless of input size.
        let text = String(raw.prefix(4000))
        let range = NSRange(text.startIndex..., in: text)
        let hits = rules.filter { $0.pattern.firstMatch(in: text, options: [], range: range) != nil }
        let score = hits.reduce(0) { $0 + $1.weight }
        let level: String
        if hits.contains(where: { $0.weight >= 5 }) || score >= 7 {
            level = "HIGH"
        } else if score >= alertThreshold {
            level = "MEDIUM"
        } else {
            level = "LOW"
        }
        return Verdict(score: score, level: level, tactics: hits.map { $0.tactic })
    }
}
