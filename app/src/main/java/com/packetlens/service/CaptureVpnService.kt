package com.packetlens.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.packetlens.MainActivity
import com.packetlens.capture.AppResolver
import com.packetlens.capture.PacketParser
import com.packetlens.model.CapturedPacket
import com.packetlens.model.Direction
import com.packetlens.model.Protocol
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import javax.inject.Inject

@AndroidEntryPoint
class CaptureVpnService : VpnService() {

    companion object {
        private const val TAG = "CaptureVPN"
        private const val NOTIFICATION_CHANNEL = "capture_channel"
        private const val NOTIFICATION_ID = 1
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_MASK = "0"
        private const val MTU = 1500
        private const val SELF_UID = -1 // Will be set to our own UID to avoid loops

        private val _packets = MutableSharedFlow<CapturedPacket>(replay = 0, extraBufferCapacity = 256)
        val packets: SharedFlow<CapturedPacket> = _packets

        private val _isRunning = MutableSharedFlow<Boolean>(replay = 1, extraBufferCapacity = 1)
        val isRunning: SharedFlow<Boolean> = _isRunning

        var isCapturing = false
            private set
    }

    @Inject lateinit var appResolver: AppResolver

    private var vpnInterface: ParcelFileDescriptor? = null
    private var captureJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "START" -> startCapture()
            "STOP" -> stopCapture()
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (isCapturing) return

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())

        val builder = Builder()
            .setSession("PacketLens")
            .setMtu(MTU)
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, VPN_MASK.toInt())
            .addDnsServer("8.8.8.8")
            .addDnsServer("8.8.4.4")
            .addDisallowedApplication(packageName) // Don't capture our own traffic

        vpnInterface = builder.establish()
        if (vpnInterface == null) {
            Log.e(TAG, "Failed to establish VPN interface")
            stopSelf()
            return
        }

        isCapturing = true
        scope.launch {
            _isRunning.emit(true)
        }

        captureJob = scope.launch { runCaptureLoop() }
        Log.i(TAG, "Capture started")
    }

    private fun stopCapture() {
        isCapturing = false
        captureJob?.cancel()
        captureJob = null

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        scope.launch {
            _isRunning.emit(false)
        }

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Capture stopped")
    }

    private fun runCaptureLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(fd)
        val outputStream = FileOutputStream(fd)
        val buffer = ByteArray(MTU)

        while (isCapturing && !Thread.currentThread().isInterrupted) {
            try {
                val length = inputStream.read(buffer)
                if (length <= 0) {
                    Thread.sleep(1)
                    continue
                }

                val data = buffer.copyOf(length)
                processPacket(data, outputStream)
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isCapturing) {
                    Log.e(TAG, "Error reading packet", e)
                }
            }
        }
    }

    private fun processPacket(data: ByteArray, outputStream: FileOutputStream) {
        val ipHeader = PacketParser.parseIPv4(data) ?: return

        val packet = when (ipHeader.protocol) {
            PacketParser.TCP -> processTCP(data, ipHeader)
            PacketParser.UDP -> processUDP(data, ipHeader)
            else -> null
        }

        if (packet != null) {
            scope.launch {
                _packets.emit(packet)
            }
        }

        // Forward packet to real destination
        forwardPacket(data, outputStream)
    }

    private fun processTCP(data: ByteArray, ipHeader: PacketParser.IpHeader): CapturedPacket? {
        val tcpHeader = PacketParser.parseTCP(data, ipHeader.headerLength) ?: return null
        val payloadOffset = ipHeader.headerLength + tcpHeader.headerLength
        val payloadSize = maxOf(0, ipHeader.totalLength - ipHeader.headerLength - tcpHeader.headerLength)

        // Get app info
        val appInfo = try {
            // Note: In production, we'd use ConnectivityManager to map connection to UID
            // For MVP, we'll use a placeholder
            AppResolver.AppInfo(-1, "unknown", "Unknown App")
        } catch (e: Exception) {
            AppResolver.AppInfo(-1, "unknown", "Unknown App")
        }

        var protocol = Protocol.TCP
        var httpMethod: String? = null
        var httpHost: String? = null
        var httpPath: String? = null
        var httpStatusCode: Int? = null
        var requestHeaders = emptyMap<String, String>()
        var tlsSni: String? = null
        var dnsQuery: String? = null
        var dnsType: String? = null
        var payloadPreview = ""

        if (payloadSize > 0) {
            val payload = data.copyOfRange(payloadOffset, minOf(payloadOffset + payloadSize, data.size))

            // Check for TLS ClientHello
            if (PacketParser.isTLSClientHello(payload, 0, payload.size)) {
                protocol = Protocol.TLS
                tlsSni = PacketParser.extractSNI(payload, 0, payload.size)
                httpHost = tlsSni
                payloadPreview = "TLS ClientHello SNI=$tlsSni"
            }
            // Check for HTTP
            else if (PacketParser.isHTTPRequest(payload, 0, payload.size)) {
                val httpInfo = PacketParser.extractHTTPInfo(payload, 0, payload.size)
                if (httpInfo != null) {
                    protocol = Protocol.HTTP
                    httpMethod = httpInfo.method
                    httpHost = httpInfo.host
                    httpPath = httpInfo.path
                    requestHeaders = httpInfo.headers
                    payloadPreview = "$httpMethod ${httpInfo.host ?: ""}${httpInfo.path}"
                }
            }
            // Check for DNS over TCP (port 53)
            else if (tcpHeader.dstPort == 53 || tcpHeader.srcPort == 53) {
                protocol = Protocol.DNS
                val dnsInfo = PacketParser.parseDNS(payload, 0, payload.size)
                if (dnsInfo != null) {
                    dnsQuery = dnsInfo.queryName
                    dnsType = dnsInfo.queryType
                    payloadPreview = "DNS ${if (dnsInfo.isResponse) "Response" else "Query"}: ${dnsInfo.queryName} (${dnsInfo.queryType})"
                }
            }
            else {
                payloadPreview = buildString {
                    append("[${payload.size} bytes] ")
                    append(payload.take(64).joinToString(" ") { "%02X".format(it) })
                }
            }
        }

        return CapturedPacket(
            protocol = protocol,
            srcIp = ipHeader.srcIp,
            dstIp = ipHeader.dstIp,
            srcPort = tcpHeader.srcPort,
            dstPort = tcpHeader.dstPort,
            appId = appInfo.uid,
            appName = appInfo.appName,
            packageName = appInfo.packageName,
            length = ipHeader.totalLength,
            direction = if (tcpHeader.isSyn && !tcpHeader.isAck) Direction.OUTGOING else Direction.OUTGOING,
            httpMethod = httpMethod,
            httpHost = httpHost,
            httpPath = httpPath,
            requestHeaders = requestHeaders,
            tlsSni = tlsSni,
            dnsQuery = dnsQuery,
            dnsType = dnsType,
            payloadPreview = payloadPreview
        )
    }

    private fun processUDP(data: ByteArray, ipHeader: PacketParser.IpHeader): CapturedPacket? {
        val udpHeader = PacketParser.parseUDP(data, ipHeader.headerLength) ?: return null
        val payloadOffset = ipHeader.headerLength + 8
        val payloadSize = maxOf(0, ipHeader.totalLength - ipHeader.headerLength - 8)

        var protocol = Protocol.UDP
        var dnsQuery: String? = null
        var dnsType: String? = null
        var dnsResponse: String? = null
        var payloadPreview = ""

        if (payloadSize > 0 && (udpHeader.dstPort == 53 || udpHeader.srcPort == 53)) {
            protocol = Protocol.DNS
            val dnsInfo = PacketParser.parseDNS(data, payloadOffset, payloadSize)
            if (dnsInfo != null) {
                dnsQuery = dnsInfo.queryName
                dnsType = dnsInfo.queryType
                dnsResponse = if (dnsInfo.isResponse) "Answers: ${dnsInfo.answerCount}" else null
                payloadPreview = "DNS ${if (dnsInfo.isResponse) "Response" else "Query"}: ${dnsInfo.queryName} (${dnsInfo.queryType})"
            }
        } else {
            payloadPreview = buildString {
                append("[${payloadSize} bytes UDP] ")
                append("Port ${udpHeader.srcPort} → ${udpHeader.dstPort}")
            }
        }

        return CapturedPacket(
            protocol = protocol,
            srcIp = ipHeader.srcIp,
            dstIp = ipHeader.dstIp,
            srcPort = udpHeader.srcPort,
            dstPort = udpHeader.dstPort,
            length = ipHeader.totalLength,
            direction = Direction.OUTGOING,
            dnsQuery = dnsQuery,
            dnsType = dnsType,
            dnsResponse = dnsResponse,
            payloadPreview = payloadPreview
        )
    }

    private fun forwardPacket(data: ByteArray, outputStream: FileOutputStream) {
        try {
            outputStream.write(data)
            outputStream.flush()
        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding packet", e)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL,
                "Capture Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "PacketLens network capture service"
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, CaptureVpnService::class.java).setAction("STOP"),
            PendingIntent.FLAG_IMMUTABLE
        )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL)
                .setContentTitle("PacketLens")
                .setContentText("Capturing network traffic...")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setContentIntent(pendingIntent)
                .addAction(
                    Notification.Action.Builder(
                        null, "Stop", stopIntent
                    ).build()
                )
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("PacketLens")
                .setContentText("Capturing network traffic...")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopCapture()
        scope.cancel()
    }
}
