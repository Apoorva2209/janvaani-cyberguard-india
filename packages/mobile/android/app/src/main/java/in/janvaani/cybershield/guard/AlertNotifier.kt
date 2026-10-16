package `in`.janvaani.cybershield.guard

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/** Posts the "possible scam" notification. The notification never shows the full message. */
object AlertNotifier {
  private const val CHANNEL_ID = "janvaani_scam_alerts"

  fun ensureChannel(ctx: Context) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
    val nm = ctx.getSystemService(NotificationManager::class.java)
    if (nm.getNotificationChannel(CHANNEL_ID) != null) return
    nm.createNotificationChannel(
      NotificationChannel(CHANNEL_ID, "Scam alerts", NotificationManager.IMPORTANCE_HIGH).apply {
        description = "Warns you when an incoming SMS, email or chat looks like a scam"
        enableVibration(true)
        lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
      }
    )
  }

  fun notify(ctx: Context, alertId: String, source: String, sender: String, verdict: ScamRules.Verdict) {
    if (Build.VERSION.SDK_INT >= 33 &&
      ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) return
    ensureChannel(ctx)

    val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    val open = Intent(Intent.ACTION_VIEW, Uri.parse("in.janvaani.cybershield://alert/$alertId"))
      .setPackage(ctx.packageName)
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    val openPi = PendingIntent.getActivity(ctx, alertId.hashCode(), open, flags)
    val dial = Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    val dialPi = PendingIntent.getActivity(ctx, alertId.hashCode() + 1, dial, flags)

    val title = if (verdict.level == "HIGH") "⚠️ Likely scam from $source" else "Check carefully: $source message"
    val who = if (sender.isNotBlank()) "From ${sender.take(40)}. " else ""
    val why = verdict.tactics.take(2).joinToString(" • ")
    val body = "${who}Warning signs: $why. Don't share OTP/PIN or click links. Tap for details & reporting."

    val n = NotificationCompat.Builder(ctx, CHANNEL_ID)
      .setSmallIcon(android.R.drawable.stat_sys_warning)
      .setContentTitle(title)
      .setContentText(body)
      .setStyle(NotificationCompat.BigTextStyle().bigText(body))
      .setPriority(NotificationCompat.PRIORITY_HIGH)
      .setCategory(NotificationCompat.CATEGORY_MESSAGE)
      .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
      .setColor(0xFFEF4444.toInt())
      .setAutoCancel(true)
      .setContentIntent(openPi)
      .addAction(0, "Details & report", openPi)
      .addAction(0, "Lost money? Call 1930", dialPi)
      .build()

    try {
      NotificationManagerCompat.from(ctx).notify(alertId.hashCode(), n)
    } catch (_: SecurityException) {
      // Permission revoked between check and post; alert is still in the inbox.
    }
  }
}
