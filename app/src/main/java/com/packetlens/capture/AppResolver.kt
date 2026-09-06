package com.packetlens.capture

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap

/**
 * Resolves UID to package name for app attribution.
 * Maps network packets to the app that generated them.
 */
class AppResolver(private val context: Context) {

    private val pm: PackageManager = context.packageManager
    private val uidCache = ConcurrentHashMap<Int, AppInfo>()

    data class AppInfo(
        val uid: Int,
        val packageName: String,
        val appName: String,
        val icon: Int = 0
    )

    /**
     * Resolve a UID to app info.
     * Returns system/unknown for UID 0 or unknown UIDs.
     */
    fun resolve(uid: Int): AppInfo {
        uidCache[uid]?.let { return it }

        val info = try {
            val packages = pm.getPackagesForUid(uid)
            if (packages != null && packages.isNotEmpty()) {
                val pkg = packages[0]
                val appInfo = pm.getApplicationInfo(pkg, 0)
                val label = pm.getApplicationLabel(appInfo).toString()
                AppInfo(uid, pkg, label, appInfo.icon)
            } else {
                resolveSystemApp(uid)
            }
        } catch (e: Exception) {
            resolveSystemApp(uid)
        }

        uidCache[uid] = info
        return info
    }

    private fun resolveSystemApp(uid: Int): AppInfo {
        return when (uid) {
            0 -> AppInfo(uid, "android", "Android System")
            1000 -> AppInfo(uid, "android.phone", "Phone")
            1013 -> AppInfo(uid, "media", "Media Server")
            1014 -> AppInfo(uid, "drmserver", "DRM Server")
            1021 -> AppInfo(uid, "gps", "GPS")
            1051 -> AppInfo(uid, "nfc", "NFC")
            10000 -> AppInfo(uid, "shell", "Shell")
            else -> AppInfo(uid, "uid_$uid", "UID $uid")
        }
    }

    /**
     * Get the TUN interface address used by VPNService.
     */
    fun getVpnInterfaceAddress(): String {
        return "10.0.0.2" // Standard VPN TUN address
    }

    /**
     * Check if a connection is going through the VPN tunnel.
     */
    fun isVpnConnection(srcIp: String, dstIp: String): Boolean {
        // Traffic to/from the TUN interface
        return srcIp.startsWith("10.0.0.") || dstIp.startsWith("10.0.0.")
    }

    /**
     * Get all installed packages for display.
     */
    fun getAllInstalledApps(): List<AppInfo> {
        val apps = mutableListOf<AppInfo>()
        val mainIntent = android.content.Intent(android.content.Intent.ACTION_MAIN, null)
        mainIntent.addCategory(android.content.Intent.CATEGORY_LAUNCHER)

        val list = pm.queryIntentActivities(mainIntent, 0)
        for (info in list) {
            apps.add(
                AppInfo(
                    uid = info.activityInfo.applicationInfo.uid,
                    packageName = info.activityInfo.packageName,
                    appName = info.loadLabel(pm).toString(),
                    icon = info.activityInfo.applicationInfo.icon
                )
            )
        }
        return apps.sortedBy { it.appName }
    }
}
