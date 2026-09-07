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
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random
import javax.inject.Inject

/**
 * VPN-based network traffic capture service with proper TCP proxy.
 *
 * Architecture:
 *   App → TUN (read) → Parse/Inspect → Real Socket (protect) → Internet
 *   Internet → Real Socket (read) → Build IP packet → TUN (write) → App
 *
 * Key: We use protect() on real sockets so they bypass the VPN tunnel
 * and go directly to the internet, avoiding infinite loops.
 *
 * For TCP: We maintain per-connection state (localSeq / remoteSeq) so that
 * every packet sent to/from the TUN has correct, incrementing sequence and
 * acknowledgement numbers. Without this the kernel drops all response packets.
 *
 * IMPORTANT: When writing raw IP packets to a TUN device, the kernel does NOT
 * fill in checksums. We must compute IP header checksums, TCP checksums
 * (with pseudo-header), and UDP checksums ourselves, or the local TCP/IP
 * stack will silently drop the packets.
 */
@AndroidEntryPoint
class CaptureVpnService : VpnService() {

    companion object {
        private const val TAG = "CaptureVPN"
        private const val NOTIFICATION_CHANNEL = "capture_channel"
        private const val NOTIFICATION_ID = 1
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_DNS = "10.0.0.1"
        private const val MTU = 1500

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

    // ========================================================================
    // Per-connection TCP state — the heart of the proper proxy
    // ========================================================================

    /**
     * Tracks the TCP state for one proxied connection.
     *
     * @param socket     The protected real socket to the remote server.
     * @param remoteIp   Real server IP (as seen in original outgoing packet).
     * @param remotePort Real server port.
     * @param localPort  The app's ephemeral source port (dst port in packets we send back).
     * @param localSeq   Sequence number WE send to the app (server→app direction).
     *                   Starts at a random value, incremented by each payload we write to TUN.
     * @param remoteSeq  Sequence number the APP sends to us (app→server direction).
     *                   Starts at the SYN seq + 1 (the SYN consumes one seq), updated
     *                   from the app's ACK / data packets.
     * @param closed     Set to true once FIN or RST has been processed.
     */
    private data class TcpConnectionState(
        val socket: Socket,
        val remoteIp: String,
        val remotePort: Int,
        val localPort: Int,
        var localSeq: Long,
        var remoteSeq: Long,
        var closed: Boolean = false
    )

    /** Key = app's source port (unique per connection from the app's perspective). */
    private val tcpConnections = ConcurrentHashMap<Int, TcpConnectionState>()

    /** Set of source ports that currently have a reader coroutine active. */
    private val activeTcpReaders = ConcurrentHashMap.newKeySet<Int>()

    /** Key = app's source port. */
    private val udpSessions = ConcurrentHashMap<Int, DatagramSocket>()

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
            .addRoute("0.0.0.0", 0) // Capture all IPv4 traffic
            .addDnsServer("8.8.8.8")
            .addDnsServer("8.8.4.4")
            .addDisallowedApplication(packageName) // Don't capture our own traffic!

        vpnInterface = builder.establish()
        if (vpnInterface == null) {
            Log.e(TAG, "Failed to establish VPN interface")
            stopSelf()
            return
        }

        isCapturing = true
        scope.launch { _isRunning.emit(true) }

        // Main loop: read from TUN → parse → forward → response → write to TUN
        captureJob = scope.launch { runCaptureLoop() }

        Log.i(TAG, "Capture started")
    }

    private fun stopCapture() {
        isCapturing = false
        captureJob?.cancel()
        captureJob = null

        // Close all tracked connections
        tcpConnections.values.forEach { state ->
            state.closed = true
            try { state.socket.close() } catch (_: Exception) {}
        }
        tcpConnections.clear()
        activeTcpReaders.clear()
        udpSessions.values.forEach { try { it.close() } catch (_: Exception) {} }
        udpSessions.clear()

        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        scope.launch { _isRunning.emit(false) }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "Capture stopped")
    }

    // ==========================================================================
    // Main capture loop
    // ==========================================================================

    private fun runCaptureLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val tunIn = FileInputStream(fd)
        val tunOut = FileOutputStream(fd)
        val buffer = ByteArray(MTU)

        while (isCapturing && !Thread.currentThread().isInterrupted) {
            try {
                val length = tunIn.read(buffer)
                if (length <= 0) {
                    Thread.sleep(1)
                    continue
                }

                val packet = buffer.copyOf(length)
                processIncomingPacket(packet, tunOut)
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isCapturing) {
                    Log.e(TAG, "Error in capture loop", e)
                }
            }
        }
    }

    // ==========================================================================
    // Process packet from TUN (app → internet direction)
    // ==========================================================================

    private fun processIncomingPacket(packet: ByteArray, tunOut: FileOutputStream) {
        val ipHeader = PacketParser.parseIPv4(packet) ?: return

        when (ipHeader.protocol) {
            6 -> handleTCP(packet, ipHeader, tunOut)   // TCP
            17 -> handleUDP(packet, ipHeader, tunOut)  // UDP
            else -> {
                // Unknown protocol — still forward to keep connectivity
                forwardRawPacket(packet, tunOut)
            }
        }
    }

    // ==========================================================================
    // TCP Handling
    // ==========================================================================

    private fun handleTCP(packet: ByteArray, ipHeader: PacketParser.IpHeader, tunOut: FileOutputStream) {
        val tcpHeader = PacketParser.parseTCP(packet, ipHeader.headerLength) ?: run {
            forwardRawPacket(packet, tunOut)
            return
        }

        val srcPort = tcpHeader.srcPort   // app's ephemeral port
        val dstIp = ipHeader.dstIp        // real server IP
        val dstPort = tcpHeader.dstPort   // real server port

        // Emit for capture/display
        emitTcpPacket(packet, ipHeader, tcpHeader)

        // ---------------------------------------------------------------
        // SYN = new connection request
        // ---------------------------------------------------------------
        if (tcpHeader.isSyn && !tcpHeader.isAck) {
            launchNewTcpConnection(srcPort, dstIp, dstPort, tcpHeader.seqNum, tunOut)
            return
        }

        // ---------------------------------------------------------------
        // FIN / RST = close connection
        // ---------------------------------------------------------------
        if (tcpHeader.isFin || tcpHeader.isRst) {
            handleTcpClose(srcPort, ipHeader, tcpHeader, tunOut)
            return
        }

        // ---------------------------------------------------------------
        // ACK (possibly with data) — update remoteSeq and forward payload
        // ---------------------------------------------------------------
        val state = tcpConnections[srcPort]
        if (state == null || state.closed) return

        // Update the app's sequence tracker.
        // The app's remoteSeq should equal the seq it sent + payloadSize.
        // We use the payload size from the TCP header to advance.
        val payloadOffset = ipHeader.headerLength + tcpHeader.headerLength
        val payloadSize = packet.size - payloadOffset
        if (payloadSize > 0) {
            // Data packet from the app → forward payload to real server
            state.remoteSeq = tcpHeader.seqNum + payloadSize
            val flagsStr = buildList {
                if (tcpHeader.isSyn) add("SYN")
                if (tcpHeader.isAck) add("ACK")
                if (tcpHeader.isFin) add("FIN")
                if (tcpHeader.isRst) add("RST")
            }.joinToString("+")
            Log.i(TAG, "TCP DATA   [${ipHeader.srcIp}:${srcPort} → ${state.remoteIp}:${state.remotePort}] flags=$flagsStr seq=${tcpHeader.seqNum} ack=${tcpHeader.ackNum} payload=${payloadSize}B localSeq=${state.localSeq} remoteSeq=${state.remoteSeq}")
            try {
                val payload = packet.copyOfRange(payloadOffset, packet.size)
                state.socket.getOutputStream().write(payload)
                state.socket.getOutputStream().flush()
                Log.d(TAG, "TCP FWD OK [${ipHeader.srcIp}:${srcPort} → ${state.remoteIp}:${state.remotePort}] ${payloadSize}B forwarded to real socket")
            } catch (e: Exception) {
                Log.e(TAG, "TCP write error to remote: $srcPort → ${state.remoteIp}:${state.remotePort}", e)
                handleTcpClose(srcPort, ipHeader, tcpHeader, tunOut)
                return
            }
        } else {
            // Pure ACK — just update remoteSeq (ack of our data, or handshake ACK)
            state.remoteSeq = tcpHeader.seqNum
            val flagsStr = buildList {
                if (tcpHeader.isSyn) add("SYN")
                if (tcpHeader.isAck) add("ACK")
                if (tcpHeader.isFin) add("FIN")
                if (tcpHeader.isRst) add("RST")
            }.joinToString("+")
            Log.i(TAG, "TCP ACK    [${ipHeader.srcIp}:${srcPort} → ${state.remoteIp}:${state.remotePort}] flags=$flagsStr seq=${tcpHeader.seqNum} ack=${tcpHeader.ackNum} localSeq=${state.localSeq} remoteSeq=${state.remoteSeq}")
        }

        // Ensure we have a reader thread pulling from the real socket
        ensureTcpReader(srcPort, state, tunOut)
    }

    /**
     * Handle a new TCP SYN from the app.
     *
     * Flow:
     * 1. App sends SYN  → we read from TUN
     * 2. We create a protected Socket to real IP:port
     * 3. We send SYN-ACK back to TUN:
     *      src = remote server, dst = app
     *      seq = random local start, ack = app SYN seq + 1
     * 4. App will send ACK → handled in handleTCP → connection established
     */
    private fun launchNewTcpConnection(
        srcPort: Int,
        dstIp: String,
        dstPort: Int,
        appSynSeq: Long,
        tunOut: FileOutputStream
    ) {
        scope.launch {
            try {
                val socket = Socket()
                // protect() — bypass VPN tunnel, go directly to internet
                protect(socket)
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(dstIp, dstPort), 5000)

                // Random local sequence start for the server→app direction
                val localStartSeq = Random.nextLong(1L, 0xFFFFFFFFL)

                val state = TcpConnectionState(
                    socket = socket,
                    remoteIp = dstIp,
                    remotePort = dstPort,
                    localPort = srcPort,
                    localSeq = localStartSeq + 1,  // SYN consumes 1 seq — first DATA must use seq+1
                    remoteSeq = appSynSeq + 1       // SYN consumes 1 sequence number
                )
                tcpConnections[srcPort] = state

                // Send SYN-ACK back to TUN (towards the app)
                val synAck = buildTcpPacket(
                    srcIp = dstIp, srcPort = dstPort,
                    dstIp = VPN_ADDRESS, dstPort = srcPort,
                    seqNum = localStartSeq,
                    ackNum = appSynSeq + 1,  // ACK the SYN (seq + 1)
                    flags = 0x12  // SYN+ACK
                )
                synchronized(tunOut) {
                    tunOut.write(synAck)
                    tunOut.flush()
                }

                Log.i(TAG, "TCP SYN    [${VPN_ADDRESS}:${srcPort} → $dstIp:$dstPort] appSeq=$appSynSeq")
                Log.i(TAG, "TCP SYN-ACK[seq=$localStartSeq, ack=${appSynSeq + 1}] ${VPN_ADDRESS}:${srcPort} ← $dstIp:$dstPort")
                Log.i(TAG, "TCP STATE  [${VPN_ADDRESS}:${srcPort} ↔ $dstIp:$dstPort] localSeq=${state.localSeq} remoteSeq=${state.remoteSeq} → waiting for ACK")

            } catch (e: Exception) {
                Log.e(TAG, "TCP connect failed: $srcPort → $dstIp:$dstPort", e)
                // Send RST back to app
                val rst = buildTcpPacket(
                    srcIp = dstIp, srcPort = dstPort,
                    dstIp = VPN_ADDRESS, dstPort = srcPort,
                    seqNum = 0, ackNum = 0,
                    flags = 0x04 // RST
                )
                try {
                    synchronized(tunOut) {
                        tunOut.write(rst)
                        tunOut.flush()
                    }
                    Log.i(TAG, "TCP RST    [${VPN_ADDRESS}:${srcPort} ← $dstIp:$dstPort] (connect failed)")
                } catch (_: Exception) {}
            }
        }
    }

    /**
     * Start a coroutine that reads data from the protected real socket
     * and writes properly-addressed IP packets back into the TUN.
     *
     * Only one reader coroutine is launched per srcPort.
     */
    private fun ensureTcpReader(srcPort: Int, state: TcpConnectionState, tunOut: FileOutputStream) {
        if (!activeTcpReaders.add(srcPort)) return // already running

        scope.launch {
            val buffer = ByteArray(MTU)
            Log.i(TAG, "TCP READER [${VPN_ADDRESS}:${srcPort} ← ${state.remoteIp}:${state.remotePort}] started, localSeq=${state.localSeq} remoteSeq=${state.remoteSeq}")
            try {
                val input = state.socket.getInputStream()
                while (isCapturing && state.socket.isConnected && !state.socket.isClosed) {
                    val read = input.read(buffer)
                    if (read <= 0) break

                    val data = buffer.copyOf(read)

                    // Build response packet: src = real server, dst = app
                    val responsePacket = buildTcpPacket(
                        srcIp = state.remoteIp, srcPort = state.remotePort,
                        dstIp = VPN_ADDRESS, dstPort = state.localPort,
                        seqNum = state.localSeq,
                        ackNum = state.remoteSeq,
                        flags = 0x18,  // PSH+ACK
                        payload = data
                    )

                    Log.i(TAG, "TCP DATA   [${VPN_ADDRESS}:${srcPort} ← ${state.remoteIp}:${state.remotePort}] flags=PSH+ACK seq=${state.localSeq} ack=${state.remoteSeq} payload=${data.size}B localSeq=${state.localSeq} → ${state.localSeq + data.size}")

                    // Advance localSeq by the amount of data we sent
                    state.localSeq += data.size

                    synchronized(tunOut) {
                        tunOut.write(responsePacket)
                        tunOut.flush()
                    }
                }
            } catch (e: Exception) {
                if (isCapturing) Log.d(TAG, "TCP reader closed: $srcPort — ${e.message}")
            } finally {
                activeTcpReaders.remove(srcPort)
                handleTcpCloseFromReader(srcPort, state, tunOut)
            }
        }
    }

    /**
     * Handle FIN/RST from the app side.
     */
    private fun handleTcpClose(
        srcPort: Int,
        ipHeader: PacketParser.IpHeader,
        tcpHeader: PacketParser.TcpHeader,
        tunOut: FileOutputStream
    ) {
        val state = tcpConnections.remove(srcPort) ?: return
        state.closed = true
        activeTcpReaders.remove(srcPort)
        try { state.socket.close() } catch (_: Exception) {}

        // Send FIN+ACK back to the app
        try {
            val finAck = buildTcpPacket(
                srcIp = state.remoteIp, srcPort = state.remotePort,
                dstIp = VPN_ADDRESS, dstPort = srcPort,
                seqNum = state.localSeq,
                ackNum = state.remoteSeq + 1,  // ACK the FIN (consumes 1 seq)
                flags = 0x11  // FIN+ACK
            )
            synchronized(tunOut) {
                tunOut.write(finAck)
                tunOut.flush()
            }
            // FIN consumes 1 sequence number
            state.localSeq += 1
            Log.i(TAG, "TCP FIN-ACK[${VPN_ADDRESS}:${srcPort} ← ${state.remoteIp}:${state.remotePort}] seq=${state.localSeq - 1} ack=${state.remoteSeq + 1} localSeq=${state.localSeq} remoteSeq=${state.remoteSeq + 1}")
        } catch (_: Exception) {}
    }

    /**
     * Handle close from the reader side (real server closed or error).
     * Sends FIN to the app so it knows the connection is gone.
     */
    private fun handleTcpCloseFromReader(srcPort: Int, state: TcpConnectionState, tunOut: FileOutputStream) {
        val removed = tcpConnections.remove(srcPort)
        if (removed != null) {
            state.closed = true
            try { state.socket.close() } catch (_: Exception) {}

            try {
                val fin = buildTcpPacket(
                    srcIp = state.remoteIp, srcPort = state.remotePort,
                    dstIp = VPN_ADDRESS, dstPort = srcPort,
                    seqNum = state.localSeq,
                    ackNum = state.remoteSeq,
                    flags = 0x11  // FIN+ACK
                )
                synchronized(tunOut) {
                    tunOut.write(fin)
                    tunOut.flush()
                }
                // FIN consumes 1 sequence number
                state.localSeq += 1
                Log.i(TAG, "TCP FIN    [${VPN_ADDRESS}:${srcPort} ← ${state.remoteIp}:${state.remotePort}] seq=${state.localSeq - 1} ack=${state.remoteSeq} localSeq=${state.localSeq}")
            } catch (_: Exception) {}
        }
    }

    // ==========================================================================
    // UDP Handling
    // ==========================================================================

    private fun handleUDP(packet: ByteArray, ipHeader: PacketParser.IpHeader, tunOut: FileOutputStream) {
        val udpHeader = PacketParser.parseUDP(packet, ipHeader.headerLength) ?: run {
            forwardRawPacket(packet, tunOut)
            return
        }

        val srcPort = udpHeader.srcPort
        val dstIp = ipHeader.dstIp
        val dstPort = udpHeader.dstPort

        emitUdpPacket(packet, ipHeader, udpHeader)

        // DNS (port 53) — handle specially
        if (dstPort == 53) {
            handleDns(packet, ipHeader, udpHeader, tunOut)
            return
        }

        // Get or create UDP session
        var udpSocket = udpSessions[srcPort]
        if (udpSocket == null) {
            try {
                udpSocket = DatagramSocket()
                protect(udpSocket) // Bypass VPN tunnel
                udpSessions[srcPort] = udpSocket
                ensureUdpReader(srcPort, ipHeader, udpHeader, tunOut)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create UDP socket for port $srcPort", e)
                return
            }
        }

        // Forward payload
        val payloadOffset = ipHeader.headerLength + 8
        val payloadSize = packet.size - payloadOffset
        if (payloadSize > 0) {
            scope.launch {
                try {
                    val payload = packet.copyOfRange(payloadOffset, packet.size)
                    val destAddr = InetAddress.getByName(dstIp)
                    val dgPacket = DatagramPacket(payload, payload.size, destAddr, dstPort)
                    udpSocket.send(dgPacket)
                } catch (e: Exception) {
                    Log.e(TAG, "UDP forward error", e)
                }
            }
        }
    }

    private fun handleDns(packet: ByteArray, ipHeader: PacketParser.IpHeader, udpHeader: PacketParser.UdpHeader, tunOut: FileOutputStream) {
        val payloadOffset = ipHeader.headerLength + 8
        val payloadSize = packet.size - payloadOffset
        if (payloadSize <= 0) return

        scope.launch {
            try {
                val payload = packet.copyOfRange(payloadOffset, packet.size)
                val socket = DatagramSocket()
                protect(socket) // Bypass VPN
                socket.soTimeout = 5000

                val dnsPacket = DatagramPacket(payload, payload.size, InetAddress.getByName("8.8.8.8"), 53)
                socket.send(dnsPacket)

                val responseBuf = ByteArray(1024)
                val responsePacket = DatagramPacket(responseBuf, responseBuf.size)
                socket.receive(responsePacket)
                socket.close()

                // Build IP+UDP packet with DNS response and write to TUN
                // dstIp must be the APP (10.0.0.2), NOT the DNS server (8.8.8.8)
                val responseIpPacket = buildUdpPacket(
                    srcIp = "8.8.8.8",
                    srcPort = 53,
                    dstIp = ipHeader.srcIp,   // ← FIX: was ipHeader.dstIp (server), must be srcIp (app)
                    dstPort = udpHeader.srcPort,
                    payload = responseBuf.copyOf(responsePacket.length)
                )

                synchronized(tunOut) {
                    tunOut.write(responseIpPacket)
                    tunOut.flush()
                }
            } catch (e: Exception) {
                Log.e(TAG, "DNS forward error", e)
            }
        }
    }

    private fun ensureUdpReader(srcPort: Int, ipHeader: PacketParser.IpHeader, udpHeader: PacketParser.UdpHeader, tunOut: FileOutputStream) {
        val udpSocket = udpSessions[srcPort] ?: return

        scope.launch {
            val buffer = ByteArray(MTU)
            try {
                while (isCapturing && !udpSocket.isClosed) {
                    val dgPacket = DatagramPacket(buffer, buffer.size)
                    try {
                        udpSocket.receive(dgPacket)
                    } catch (_: java.net.SocketTimeoutException) {
                        continue
                    }

                    val payload = buffer.copyOf(dgPacket.length)
                    val responsePacket = buildUdpPacket(
                        srcIp = dgPacket.address.hostAddress ?: "0.0.0.0",
                        srcPort = dgPacket.port,
                        dstIp = ipHeader.srcIp,   // ← FIX: was ipHeader.dstIp (server), must be srcIp (app)
                        dstPort = srcPort,
                        payload = payload
                    )

                    synchronized(tunOut) {
                        tunOut.write(responsePacket)
                        tunOut.flush()
                    }
                }
            } catch (e: Exception) {
                if (isCapturing) Log.d(TAG, "UDP reader closed: $srcPort")
            } finally {
                udpSessions.remove(srcPort)
                try { udpSocket.close() } catch (_: Exception) {}
            }
        }
    }

    // ==========================================================================
    // Checksum calculation helpers (RFC 1071)
    // ==========================================================================

    /**
     * Compute IP header checksum over the first [length] bytes of [data].
     *
     * Algorithm (RFC 1071):
     *   1. Sum all 16-bit words.
     *   2. Fold the 32-bit carry back into the lower 16 bits.
     *   3. Take the one's complement.
     */
    private fun computeIpChecksum(data: ByteArray, length: Int): Int {
        var sum = 0L
        var i = 0
        // Sum 16-bit words
        while (i + 1 < length) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        // If odd byte left over, add it as-is (zero-padded high byte)
        if (i < length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        // Fold 32-bit sum into 16 bits
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.toInt().inv() and 0xFFFF
    }

    /**
     * Compute TCP or UDP checksum including the pseudo-header.
     *
     * Pseudo-header (12 bytes):
     *   src IP (4) + dst IP (4) + zero (1) + protocol (1) + TCP/UDP length (2)
     *
     * The transport data starts at [transportOffset] in [fullPacket] and is
     * [transportLength] bytes long (header + payload).
     */
    private fun computeTransportChecksum(
        fullPacket: ByteArray,
        transportOffset: Int,
        transportLength: Int,
        srcIp: InetAddress,
        dstIp: InetAddress,
        protocol: Int // 6=TCP, 17=UDP
    ): Int {
        // Pseudo-header: srcIP(4) + dstIP(4) + zero(1) + proto(1) + segLen(2)
        var sum = 0L

        // Add pseudo-header
        val srcAddr = srcIp.address
        val dstAddr = dstIp.address
        for (i in srcAddr.indices step 2) {
            sum += ((srcAddr[i].toInt() and 0xFF) shl 8) or (srcAddr[i + 1].toInt() and 0xFF)
        }
        for (i in dstAddr.indices step 2) {
            sum += ((dstAddr[i].toInt() and 0xFF) shl 8) or (dstAddr[i + 1].toInt() and 0xFF)
        }
        sum += protocol // zero byte + protocol byte as 16-bit word
        sum += transportLength

        // Add transport header + payload (16-bit words)
        var i = transportOffset
        val end = transportOffset + transportLength
        while (i + 1 < end) {
            sum += ((fullPacket[i].toInt() and 0xFF) shl 8) or (fullPacket[i + 1].toInt() and 0xFF)
            i += 2
        }
        // Odd trailing byte: pad with zero
        if (i < end) {
            sum += (fullPacket[i].toInt() and 0xFF) shl 8
        }

        // Fold carry bits
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.toInt().inv() and 0xFFFF
    }

    // ==========================================================================
    // Packet builders (construct IP packets to write back to TUN)
    //
    // All checksums are computed here — the kernel will NOT fill them
    // in for packets written to a TUN file descriptor.
    // ==========================================================================

    private fun buildTcpPacket(
        srcIp: String, srcPort: Int,
        dstIp: String, dstPort: Int,
        seqNum: Long, ackNum: Long,
        flags: Int,
        payload: ByteArray = byteArrayOf()
    ): ByteArray {
        val tcpHeaderSize = 20
        val ipHeaderSize = 20
        val totalSize = ipHeaderSize + tcpHeaderSize + payload.size

        val buffer = ByteBuffer.allocate(totalSize)

        // IP Header (20 bytes) — checksum placeholder
        buffer.put(0x45.toByte()) // Version 4, IHL 5
        buffer.put(0x00.toByte()) // DSCP
        buffer.putShort(totalSize.toShort()) // Total length
        buffer.putShort(0) // ID
        buffer.putShort(0x4000.toShort()) // Flags: Don't Fragment
        buffer.put(64.toByte()) // TTL
        buffer.put(6.toByte()) // Protocol: TCP
        buffer.putShort(0) // Checksum — computed below
        buffer.put(InetAddress.getByName(srcIp).address)
        buffer.put(InetAddress.getByName(dstIp).address)

        // Compute IP header checksum over the first 20 bytes
        val ipChecksum = computeIpChecksum(buffer.array(), ipHeaderSize)
        buffer.putShort(ipHeaderSize + 10, ipChecksum.toShort())

        // TCP Header (20 bytes)
        val tcpStart = ipHeaderSize
        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        buffer.putInt(seqNum.toInt())
        buffer.putInt(ackNum.toInt())
        buffer.put(((5 shl 4) or 0).toByte()) // Data offset: 5 words, reserved 0
        buffer.put(flags.toByte())
        buffer.putShort(65535.toShort()) // Window size
        buffer.putShort(0) // Checksum — computed below
        buffer.putShort(0) // Urgent pointer

        // Payload
        buffer.put(payload)

        val packet = buffer.array()

        // Compute TCP checksum with pseudo-header
        val srcAddr = InetAddress.getByName(srcIp)
        val dstAddr = InetAddress.getByName(dstIp)
        val tcpLen = tcpHeaderSize + payload.size
        val tcpChecksum = computeTransportChecksum(
            packet, tcpStart, tcpLen, srcAddr, dstAddr, 6
        )
        packet[tcpStart + 16] = ((tcpChecksum shr 8) and 0xFF).toByte()
        packet[tcpStart + 17] = (tcpChecksum and 0xFF).toByte()

        return packet
    }

    private fun buildUdpPacket(
        srcIp: String, srcPort: Int,
        dstIp: String, dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpHeaderSize = 8
        val ipHeaderSize = 20
        val totalSize = ipHeaderSize + udpHeaderSize + payload.size

        val buffer = ByteBuffer.allocate(totalSize)

        // IP Header — checksum placeholder
        buffer.put(0x45.toByte())
        buffer.put(0x00.toByte())
        buffer.putShort(totalSize.toShort())
        buffer.putShort(0)
        buffer.putShort(0x4000.toShort())
        buffer.put(64.toByte())
        buffer.put(17.toByte()) // Protocol: UDP
        buffer.putShort(0) // Checksum — computed below
        buffer.put(InetAddress.getByName(srcIp).address)
        buffer.put(InetAddress.getByName(dstIp).address)

        // Compute IP header checksum
        val ipChecksum = computeIpChecksum(buffer.array(), ipHeaderSize)
        buffer.putShort(ipHeaderSize + 10, ipChecksum.toShort())

        // UDP Header
        val udpStart = ipHeaderSize
        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        buffer.putShort((udpHeaderSize + payload.size).toShort())
        buffer.putShort(0) // Checksum — computed below

        // Payload
        buffer.put(payload)

        val packet = buffer.array()

        // Compute UDP checksum with pseudo-header.
        // For UDP over IPv4, checksum=0 means "not computed". However,
        // some kernels (and Android's local stack) may drop zero-checksum
        // UDP packets. Compute it properly for reliability.
        val srcAddr = InetAddress.getByName(srcIp)
        val dstAddr = InetAddress.getByName(dstIp)
        val udpLen = udpHeaderSize + payload.size
        val udpChecksum = computeTransportChecksum(
            packet, udpStart, udpLen, srcAddr, dstAddr, 17
        )
        packet[udpStart + 6] = ((udpChecksum shr 8) and 0xFF).toByte()
        packet[udpStart + 7] = (udpChecksum and 0xFF).toByte()

        return packet
    }

    private fun forwardRawPacket(packet: ByteArray, tunOut: FileOutputStream) {
        // DON'T write back to TUN — that causes an infinite loop!
        // Unknown protocols (ICMP etc) are simply dropped. This is safe
        // because only TCP/UDP need forwarding; ICMP doesn't affect connectivity.
        Log.d(TAG, "Dropped unknown protocol packet (${packet.size} bytes)")
    }

    // ==========================================================================
    // Emit packets for display
    // ==========================================================================

    private fun emitTcpPacket(packet: ByteArray, ipHeader: PacketParser.IpHeader, tcpHeader: PacketParser.TcpHeader) {
        val payloadOffset = ipHeader.headerLength + tcpHeader.headerLength
        val payloadSize = packet.size - payloadOffset

        var protocol = Protocol.TCP
        var httpMethod: String? = null
        var httpHost: String? = null
        var httpPath: String? = null
        var tlsSni: String? = null
        var dnsQuery: String? = null
        var dnsType: String? = null
        var payloadPreview = ""

        if (payloadSize > 0) {
            val payload = packet.copyOfRange(payloadOffset, minOf(payloadOffset + payloadSize, packet.size))

            when {
                PacketParser.isTLSClientHello(payload, 0, payload.size) -> {
                    protocol = Protocol.TLS
                    tlsSni = PacketParser.extractSNI(payload, 0, payload.size)
                    httpHost = tlsSni
                    payloadPreview = "TLS ClientHello SNI=$tlsSni"
                }
                PacketParser.isHTTPRequest(payload, 0, payload.size) -> {
                    val httpInfo = PacketParser.extractHTTPInfo(payload, 0, payload.size)
                    if (httpInfo != null) {
                        protocol = Protocol.HTTP
                        httpMethod = httpInfo.method
                        httpHost = httpInfo.host
                        httpPath = httpInfo.path
                        payloadPreview = "$httpMethod ${httpInfo.host ?: ""}${httpInfo.path}"
                    }
                }
                tcpHeader.dstPort == 53 || tcpHeader.srcPort == 53 -> {
                    protocol = Protocol.DNS
                    val dnsInfo = PacketParser.parseDNS(payload, 0, payload.size)
                    if (dnsInfo != null) {
                        dnsQuery = dnsInfo.queryName
                        dnsType = dnsInfo.queryType
                        payloadPreview = "DNS: ${dnsInfo.queryName} (${dnsInfo.queryType})"
                    }
                }
                else -> {
                    payloadPreview = "[${payload.size} bytes TCP]"
                }
            }
        }

        scope.launch {
            _packets.emit(CapturedPacket(
                protocol = protocol,
                srcIp = ipHeader.srcIp, dstIp = ipHeader.dstIp,
                srcPort = tcpHeader.srcPort, dstPort = tcpHeader.dstPort,
                length = ipHeader.totalLength,
                direction = Direction.OUTGOING,
                httpMethod = httpMethod, httpHost = httpHost, httpPath = httpPath,
                tlsSni = tlsSni,
                dnsQuery = dnsQuery, dnsType = dnsType,
                payloadPreview = payloadPreview
            ))
        }
    }

    private fun emitUdpPacket(packet: ByteArray, ipHeader: PacketParser.IpHeader, udpHeader: PacketParser.UdpHeader) {
        val payloadOffset = ipHeader.headerLength + 8
        val payloadSize = packet.size - payloadOffset

        var protocol = Protocol.UDP
        var dnsQuery: String? = null
        var dnsType: String? = null
        var payloadPreview = ""

        if (payloadSize > 0 && (udpHeader.dstPort == 53 || udpHeader.srcPort == 53)) {
            protocol = Protocol.DNS
            val dnsInfo = PacketParser.parseDNS(packet, payloadOffset, payloadSize)
            if (dnsInfo != null) {
                dnsQuery = dnsInfo.queryName
                dnsType = dnsInfo.queryType
                payloadPreview = "DNS: ${dnsInfo.queryName} (${dnsInfo.queryType})"
            }
        } else {
            payloadPreview = "[${payloadSize} bytes UDP] Port ${udpHeader.srcPort}→${udpHeader.dstPort}"
        }

        scope.launch {
            _packets.emit(CapturedPacket(
                protocol = protocol,
                srcIp = ipHeader.srcIp, dstIp = ipHeader.dstIp,
                srcPort = udpHeader.srcPort, dstPort = udpHeader.dstPort,
                length = ipHeader.totalLength,
                direction = Direction.OUTGOING,
                dnsQuery = dnsQuery, dnsType = dnsType,
                payloadPreview = payloadPreview
            ))
        }
    }

    // ==========================================================================
    // Notification
    // ==========================================================================

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL, "Capture Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "PacketLens capture" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stopPi = PendingIntent.getService(this, 1,
            Intent(this, CaptureVpnService::class.java).setAction("STOP"), PendingIntent.FLAG_IMMUTABLE)

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL)
                .setContentTitle("PacketLens")
                .setContentText("Capturing network traffic...")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setContentIntent(pi)
                .addAction(Notification.Action.Builder(null, "Stop", stopPi).build())
                .setOngoing(true).build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("PacketLens")
                .setContentText("Capturing network traffic...")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setContentIntent(pi).setOngoing(true).build()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopCapture()
        scope.cancel()
    }
}
