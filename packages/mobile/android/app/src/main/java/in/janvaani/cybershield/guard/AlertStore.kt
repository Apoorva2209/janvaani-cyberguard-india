package `in`.janvaani.cybershield.guard

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID

/**
 * Local, encrypted, size- and time-bounded store of scam alerts.
 *
 * Privacy:
 *  - Data never leaves the device from here; nothing is uploaded.
 *  - Stored with AES-256 (Android Keystore-backed EncryptedSharedPreferences).
 *  - Only a bounded excerpt of the message is kept, and alerts auto-expire.
 *  - The user can delete one alert or wipe everything from the app.
 */
object AlertStore {
  private const val FILE = "janvaani_guard_secure"
  private const val KEY_ALERTS = "alerts"
  private const val KEY_ENABLED = "enabled"
  private const val KEY_SEEN = "seen_hashes"
  private const val MAX_ALERTS = 100
  private const val MAX_EXCERPT = 600
  const val RETENTION_MS = 30L * 24 * 60 * 60 * 1000 // 30 days

  @Volatile private var prefs: SharedPreferences? = null

  private fun prefs(ctx: Context): SharedPreferences =
    prefs ?: synchronized(this) {
      prefs ?: run {
        val app = ctx.applicationContext
        val key = MasterKey.Builder(app).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        EncryptedSharedPreferences.create(
          app, FILE, key,
          EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
          EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        ).also { prefs = it }
      }
    }

  fun isEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY_ENABLED, true)

  fun setEnabled(ctx: Context, enabled: Boolean) {
    prefs(ctx).edit().putBoolean(KEY_ENABLED, enabled).apply()
  }

  /**
   * Returns the new alert id, or null when this exact text was already alerted
   * (notification listeners often re-post the same message).
   */
  @Synchronized
  fun add(ctx: Context, source: String, sender: String, text: String, verdict: ScamRules.Verdict): String? {
    val p = prefs(ctx)
    val hash = sha256(source + "|" + sender + "|" + text)
    val seen = JSONArray(p.getString(KEY_SEEN, "[]"))
    for (i in 0 until seen.length()) if (seen.getString(i) == hash) return null

    val id = UUID.randomUUID().toString()
    val alert = JSONObject()
      .put("id", id)
      .put("source", source)
      .put("sender", sender.take(80))
      .put("excerpt", text.take(MAX_EXCERPT))
      .put("level", verdict.level)
      .put("score", verdict.score)
      .put("tactics", JSONArray(verdict.tactics))
      .put("receivedAt", System.currentTimeMillis())

    val list = prune(JSONArray(p.getString(KEY_ALERTS, "[]")))
    val next = JSONArray().put(alert)
    for (i in 0 until minOf(list.length(), MAX_ALERTS - 1)) next.put(list.get(i))

    val nextSeen = JSONArray().put(hash)
    for (i in 0 until minOf(seen.length(), 300)) nextSeen.put(seen.get(i))

    p.edit().putString(KEY_ALERTS, next.toString()).putString(KEY_SEEN, nextSeen.toString()).apply()
    return id
  }

  @Synchronized
  fun all(ctx: Context): JSONArray {
    val p = prefs(ctx)
    val pruned = prune(JSONArray(p.getString(KEY_ALERTS, "[]")))
    p.edit().putString(KEY_ALERTS, pruned.toString()).apply()
    return pruned
  }

  @Synchronized
  fun delete(ctx: Context, id: String) {
    val p = prefs(ctx)
    val list = JSONArray(p.getString(KEY_ALERTS, "[]"))
    val next = JSONArray()
    for (i in 0 until list.length()) {
      val o = list.getJSONObject(i)
      if (o.optString("id") != id) next.put(o)
    }
    p.edit().putString(KEY_ALERTS, next.toString()).apply()
  }

  @Synchronized
  fun clear(ctx: Context) {
    prefs(ctx).edit().remove(KEY_ALERTS).remove(KEY_SEEN).apply()
  }

  private fun prune(list: JSONArray): JSONArray {
    val cutoff = System.currentTimeMillis() - RETENTION_MS
    val out = JSONArray()
    for (i in 0 until list.length()) {
      val o = list.optJSONObject(i) ?: continue
      if (o.optLong("receivedAt") >= cutoff) out.put(o)
    }
    return out
  }

  private fun sha256(s: String): String =
    MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
}
