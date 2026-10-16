package `in`.janvaani.cybershield.guard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

/**
 * Receives incoming SMS (RECEIVE_SMS). Read-only: we never block, delete,
 * reply to, or forward the message. Multi-part messages are joined per sender.
 */
class SmsReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent) {
    if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
    val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
    val pending = goAsync()
    Thread {
      try {
        parts.groupBy { it.displayOriginatingAddress ?: "" }.forEach { (sender, msgs) ->
          Guard.inspect(context, "SMS", sender, msgs.joinToString("") { it.displayMessageBody ?: "" })
        }
      } finally {
        pending.finish()
      }
    }.start()
  }
}
