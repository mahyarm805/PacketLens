package com.packetlens.capture

import android.content.Context
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Resolves UID to package name for app attribution.
 * Maps network packets to the app that generated them.
 *
 * Uses /proc/net/tcp to map (srcPort) → UID, then UID → package info.
 */
class AppResolver(private val context: Context) {

    private val pm: PackageManager = context.packageManager
    private val uidCache = ConcurrentHashMap<Int, AppInfo>()
    private val portUidCache = ConcurrentHashMap<Int, Int>()  // port → uid

    data class AppInfo(
        val uid: Int,
        val packageName: String,
        val appName: String,
        val iconResId: Int = 0
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

    /**
     * Resolve a source port to a UID by reading /proc/net/tcp.
     * The local_port field in /proc/net/tcp matches the app's ephemeral port.
     *
     * Format of /proc/net/tcp:
     *   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     *   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
     *
     * local_address is hex: hex_ip:hex_port
     */
    fun resolvePortToUid(srcPort: Int): Int {
        portUidCache[srcPort]?.let { return it }

        try {
            java.io.File("/proc/net/tcp").bufferedReader().useLines { lines ->
                for (line in lines) {
                    if (!line.contains(":")) continue
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size < 8) continue

                    val localAddr = parts[1]
                    val colonIdx = localAddr.lastIndexOf(':')
                    if (colonIdx < 0) continue

                    val portHex = localAddr.substring(colonIdx + 1)
                    val port = portHex.toIntOrNull(16) ?: continue

                    if (port == srcPort) {
                        val uid = parts[7].toIntOrNull() ?: 0
                        portUidCache[srcPort] = uid
                        return uid
                    }
                }
            }
        } catch (_: Exception) {}

        // Also check /proc/net/tcp6 for IPv6 connections
        try {
            java.io.File("/proc/net/tcp6").bufferedReader().useLines { lines ->
                for (line in lines) {
                    if (!line.contains(":")) continue
                    val parts = line.trim().split("\\s+".toRegex())
                    if (parts.size < 8) continue

                    val localAddr = parts[1]
                    val colonIdx = localAddr.lastIndexOf(':')
                    if (colonIdx < 0) continue

                    val portHex = localAddr.substring(colonIdx + 1)
                    val port = portHex.toIntOrNull(16) ?: continue

                    if (port == srcPort) {
                        val uid = parts[7].toIntOrNull() ?: 0
                        portUidCache[srcPort] = uid
                        return uid
                    }
                }
            }
        } catch (_: Exception) {}

        return -1
    }

    /**
     * Clear port cache (call periodically or on capture restart).
     */
    fun clearPortCache() {
        portUidCache.clear()
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
                    iconResId = info.activityInfo.applicationInfo.icon
                )
            )
        }
        return apps.sortedBy { it.appName }
    }
}
