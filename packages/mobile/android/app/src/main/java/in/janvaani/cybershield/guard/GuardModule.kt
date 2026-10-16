package `in`.janvaani.cybershield.guard

import android.Manifest
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.uimanager.ViewManager

/** JS bridge: `NativeModules.JanVaaniGuard`. */
class GuardModule(private val ctx: ReactApplicationContext) : ReactContextBaseJavaModule(ctx) {
  override fun getName() = "JanVaaniGuard"

  companion object {
    @Volatile var pendingShare: String? = null
  }

  /** Returns (and clears) text shared into the app from another app, or null. */
  @ReactMethod
  fun takeSharedText(promise: Promise) {
    val t = pendingShare
    pendingShare = null
    promise.resolve(t)
  }

  @ReactMethod
  fun getStatus(promise: Promise) {
    val m = Arguments.createMap()
    m.putBoolean("enabled", AlertStore.isEnabled(ctx))
    m.putBoolean("smsPermission", granted(Manifest.permission.RECEIVE_SMS))
    m.putBoolean("notificationPermission",
      if (Build.VERSION.SDK_INT >= 33) granted(Manifest.permission.POST_NOTIFICATIONS) else true)
    m.putBoolean("notificationAccess",
      NotificationManagerCompat.getEnabledListenerPackages(ctx).contains(ctx.packageName))
    promise.resolve(m)
  }

  @ReactMethod
  fun setEnabled(enabled: Boolean, promise: Promise) {
    AlertStore.setEnabled(ctx, enabled)
    promise.resolve(enabled)
  }

  @ReactMethod
  fun getAlerts(promise: Promise) {
    try {
      promise.resolve(AlertStore.all(ctx).toString())
    } catch (e: Exception) {
      promise.reject("E_STORE", "Could not read alerts")
    }
  }

  @ReactMethod
  fun deleteAlert(id: String, promise: Promise) {
    AlertStore.delete(ctx, id)
    promise.resolve(true)
  }

  @ReactMethod
  fun clearAlerts(promise: Promise) {
    AlertStore.clear(ctx)
    promise.resolve(true)
  }

  /** Runs the background rules on sample text so users can test alerts end to end. */
  @ReactMethod
  fun simulate(text: String, promise: Promise) {
    Thread {
      Guard.inspect(ctx, "Test", "JanVaani demo", text.take(2000))
      promise.resolve(true)
    }.start()
  }

  @ReactMethod
  fun openNotificationAccessSettings() {
    val i = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
    if (Build.VERSION.SDK_INT >= 30) {
      i.action = Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS
      i.putExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME,
        ComponentName(ctx, NotificationWatcher::class.java).flattenToString())
    }
    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    try {
      ctx.startActivity(i)
    } catch (_: Exception) {
      ctx.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
  }

  private fun granted(p: String) =
    ContextCompat.checkSelfPermission(ctx, p) == PackageManager.PERMISSION_GRANTED
}

class GuardPackage : ReactPackage {
  override fun createNativeModules(ctx: ReactApplicationContext): List<NativeModule> = listOf(GuardModule(ctx))
  override fun createViewManagers(ctx: ReactApplicationContext): List<ViewManager<*, *>> = emptyList()
}
