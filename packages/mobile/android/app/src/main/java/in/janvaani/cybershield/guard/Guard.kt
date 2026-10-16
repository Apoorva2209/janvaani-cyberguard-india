package `in`.janvaani.cybershield.guard

import android.content.Context
import android.util.Log

/** Single entry point used by every background source (SMS, notifications). */
object Guard {
  private const val TAG = "JanVaaniGuard"

  fun inspect(ctx: Context, source: String, sender: String, text: String) {
    try {
      if (text.isBlank() || !AlertStore.isEnabled(ctx)) return
      val verdict = ScamRules.evaluate(text)
      if (verdict.score < ScamRules.ALERT_THRESHOLD) return
      val id = AlertStore.add(ctx, source, sender, text, verdict) ?: return
      AlertNotifier.notify(ctx, id, source, sender, verdict)
      // Log only metadata — never message content or sender numbers.
      Log.i(TAG, "alert source=$source level=${verdict.level} score=${verdict.score}")
    } catch (e: Exception) {
      Log.w(TAG, "inspect failed: ${e.javaClass.simpleName}")
    }
  }
}
