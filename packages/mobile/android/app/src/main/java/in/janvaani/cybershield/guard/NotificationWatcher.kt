package `in`.janvaani.cybershield.guard

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * Watches notifications from messaging and email apps so WhatsApp, Gmail,
 * Outlook, Telegram etc. are covered without reading their private data stores.
 *
 * Only an allow-list of communication apps is inspected; everything else
 * (banking apps, OTP notifications from other apps, etc.) is ignored.
 * The user must grant "Notification access" explicitly in Android settings.
 */
class NotificationWatcher : NotificationListenerService() {

  private val watched = mapOf(
    "com.whatsapp" to "WhatsApp",
    "com.whatsapp.w4b" to "WhatsApp Business",
    "org.telegram.messenger" to "Telegram",
    "com.google.android.gm" to "Gmail",
    "com.microsoft.office.outlook" to "Outlook",
    "com.yahoo.mobile.client.android.mail" to "Yahoo Mail",
    "in.zoho.mail" to "Zoho Mail",
    "com.google.android.apps.messaging" to "Messages",
    "com.samsung.android.messaging" to "Messages",
    "com.truecaller" to "Truecaller",
    "com.instagram.android" to "Instagram",
    "com.facebook.orca" to "Messenger",
    "jio.chat" to "JioChat",
    "com.Slack" to "Slack",
  )

  override fun onNotificationPosted(sbn: StatusBarNotification) {
    val source = watched[sbn.packageName] ?: return
    val n = sbn.notification ?: return
    if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return
    if (sbn.isOngoing) return

    val extras = n.extras ?: return
    val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
    val body = (extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
      ?: extras.getCharSequence(Notification.EXTRA_TEXT))?.toString().orEmpty()
    if (body.isBlank()) return

    val ctx = applicationContext
    Thread { Guard.inspect(ctx, source, title, body) }.start()
  }
}
