package `in`.janvaani.cybershield.guard

/**
 * Describes the *kind* of sender ID. It cannot say who the sender really is: numbers and
 * display names are easy to fake. The kind is still a useful clue (a bank texting from an
 * ordinary mobile number is a red flag).
 */
object SenderKind {
  private val BUSINESS_HEADER = Regex("""^[A-Za-z0-9]{2}-[A-Za-z0-9]{3,8}$""")
  private val INDIAN_MOBILE = Regex("""^(\+?91)?[6-9]\d{9}$""")
  private val INTERNATIONAL = Regex("""^\+\d{7,15}$""")
  private val SHORT_CODE = Regex("""^\d{3,6}$""")

  fun describe(rawSender: String): String {
    val sender = rawSender.trim()
    if (sender.isEmpty()) return "unknown sender"
    val digits = sender.replace(Regex("""[\s()-]"""), "")
    return when {
      BUSINESS_HEADER.matches(sender) -> "business sender ID (can be imitated)"
      INDIAN_MOBILE.matches(digits) -> "ordinary mobile number"
      INTERNATIONAL.matches(digits) && !digits.startsWith("+91") -> "international number"
      SHORT_CODE.matches(digits) -> "short code"
      else -> "unverified name"
    }
  }
}
