package `in`.janvaani.cybershield.guard

/**
 * On-device first-pass scam rules used for background alerts.
 *
 * This is deliberately conservative and deterministic: it runs inside a
 * BroadcastReceiver / NotificationListenerService where we cannot wait for the
 * JS engine or the network. Its output is a *risk indicator*, never proof.
 * The full TypeScript engine re-analyses the text when the user opens the alert.
 *
 * Submitted text is treated strictly as data: nothing in it is executed,
 * fetched, or followed.
 */
object ScamRules {

  data class Rule(val tactic: String, val weight: Int, val pattern: Regex)

  data class Verdict(val score: Int, val level: String, val tactics: List<String>)

  private fun r(p: String) = Regex(p, setOf(RegexOption.IGNORE_CASE))

  // Weights: 5 = strong on its own, 3 = suspicious, 2 = supporting signal.
  private val RULES = listOf(
    Rule("Asks for OTP / UPI PIN / password", 5,
      r("""\b(share|send|tell|enter|provide|forward)\b.{0,30}\b(otp|upi\s*pin|atm\s*pin|cvv|password|mpin)\b""")),
    Rule("UPI PIN to 'receive' money", 5,
      r("""(upi\s*pin|scan.{0,15}qr).{0,40}\b(receive|get|claim|credit)""")),
    Rule("Digital arrest / fake police threat", 5,
      r("""digital\s*arrest|\b(cbi|ncb|narcotics|crime\s*branch|customs|ed\s+officer|cyber\s*cell)\b.{0,60}\b(arrest|warrant|case|parcel|video\s*call|skype)""")),
    Rule("Remote-access app request", 5,
      r("""\b(anydesk|teamviewer|quick\s*support|rustdesk|airdroid)\b""")),
    Rule("Install APK file", 5,
      r("""\.apk\b|install\s+(this|the)\s+app\s+from\s+(link|here)""")),
    Rule("KYC / account block threat", 3,
      r("""\b(kyc|pan|aadhaar)\b.{0,40}\b(update|expire|expired|block|blocked|suspend|deactivat)|\b(account|sim|card)\b.{0,20}\b(blocked|suspended|deactivated|will be closed)""")),
    Rule("Electricity disconnection threat", 4,
      r("""(electricity|bijli|power)\b.{0,60}\b(disconnect|cut|tonight|9[.:]30)""")),
    Rule("Lottery / prize / cashback lure", 3,
      r("""\b(lottery|jackpot|you\s+(have\s+)?won|winner|lucky\s+draw|cash\s*prize|kbc)\b""")),
    Rule("Part-time job / task scam", 3,
      r("""\b(part[-\s]?time|work\s+from\s+home|daily\s+income|earn\s+(rs|₹|inr)?\s*\d+)\b.{0,80}\b(telegram|whatsapp|like|review|task|rating)""")),
    Rule("Fake parcel / courier / customs", 3,
      r("""\b(parcel|courier|fedex|dhl|india\s*post|shipment)\b.{0,60}\b(held|seized|pending|undelivered|address|customs|fee)""")),
    Rule("Investment / trading tip group", 3,
      r("""\b(stock|ipo|crypto|trading|forex)\b.{0,60}\b(guaranteed|double|\d{2,3}\s*%|vip\s+group|profit)""")),
    Rule("Urgency pressure", 2,
      r("""\b(urgent|immediately|within\s+\d+\s*(min|hour|hrs)|today\s+only|last\s+chance|act\s+now|turant)\b""")),
    Rule("Shortened / hidden link", 2,
      r("""\b(bit\.ly|tinyurl\.com|is\.gd|t\.ly|cutt\.ly|rb\.gy|shorturl\.at|goo\.gl)/""")),
    Rule("Raw IP or suspicious link", 3,
      r("""https?://(\d{1,3}\.){3}\d{1,3}|https?://[^\s/]*(\.xyz|\.top|\.click|\.buzz|\.icu|\.live|\.shop)\b""")),
    Rule("Call a personal mobile number", 2,
      r("""\b(call|contact|whatsapp)\b.{0,25}(\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b""")),
  )

  /** Minimum score that raises a user-visible alert. */
  const val ALERT_THRESHOLD = 4

  fun evaluate(raw: String): Verdict {
    // Bound work regardless of input size (resource-exhaustion guard).
    val text = raw.take(4000)
    val hits = RULES.filter { it.pattern.containsMatchIn(text) }.toMutableList()
    if (hasLookalikeHost(text)) {
      hits.add(Rule("Bank / govt name in a non-official link", 4, BRAND))
    }
    val score = hits.sumOf { it.weight }
    val level = when {
      hits.any { it.weight >= 5 } || score >= 7 -> "HIGH"
      score >= ALERT_THRESHOLD -> "MEDIUM"
      else -> "LOW"
    }
    return Verdict(score, level, hits.map { it.tactic })
  }

  private val HOST = r("""https?://([^\s/:?#]+)""")
  private val BRAND = r("""sbi|hdfc|icici|axis|kotak|paytm|phonepe|npci|incometax|pmkisan|pm-kisan|epfo|uidai|aadhaar|indiapost""")
  private val OFFICIAL_SUFFIXES = listOf(
    ".gov.in", ".nic.in", ".bank.in", "onlinesbi.sbi", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com", "paytm.com", "phonepe.com", "npci.org.in",
  )

  /** A link whose host borrows a bank/government brand but isn't on its official domain. */
  private fun hasLookalikeHost(text: String): Boolean =
    HOST.findAll(text).any { m ->
      val host = m.groupValues[1].lowercase()
      BRAND.containsMatchIn(host) &&
        OFFICIAL_SUFFIXES.none { host == it.trimStart('.') || host.endsWith(if (it.startsWith(".")) it else ".$it") || host == it }
    }
}
