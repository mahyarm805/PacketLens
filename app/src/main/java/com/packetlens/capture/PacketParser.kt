package com.packetlens.capture

import java.nio.ByteBuffer

/**
 * Parses raw IP packets from the TUN interface.
 * Extracts IP headers, TCP/UDP headers, and application-layer data.
 */
object PacketParser {

    // Protocol numbers
    const val TCP = 6
    const val UDP = 17

    data class IpHeader(
        val version: Int,
        val headerLength: Int,
        val totalLength: Int,
        val protocol: Int,
        val srcIp: String,
        val dstIp: String
    )

    data class TcpHeader(
        val srcPort: Int,
        val dstPort: Int,
        val seqNum: Long,
        val ackNum: Long,
        val headerLength: Int,
        val flags: Int,
        val windowSize: Int,
        val payloadOffset: Int,
        val payloadSize: Int
    ) {
        val isSyn get() = (flags and 0x02) != 0
        val isAck get() = (flags and 0x10) != 0
        val isFin get() = (flags and 0x01) != 0
        val isRst get() = (flags and 0x04) != 0
        val isPsh get() = (flags and 0x08) != 0
    }

    data class UdpHeader(
        val srcPort: Int,
        val dstPort: Int,
        val length: Int,
        val payloadOffset: Int,
        val payloadSize: Int
    )

    /**
     * Parse an IPv4 header from raw bytes.
     */
    fun parseIPv4(data: ByteArray, offset: Int = 0): IpHeader? {
        if (data.size < offset + 20) return null

        val firstByte = data[offset].toInt() and 0xFF
        val version = (firstByte shr 4) and 0x0F
        if (version != 4) return null

        val ihl = firstByte and 0x0F
        val headerLength = ihl * 4

        val totalLength = ((data[offset + 2].toInt() and 0xFF) shl 8) or
                (data[offset + 3].toInt() and 0xFF)

        val protocol = data[offset + 9].toInt() and 0xFF

        val srcIp = "${data[offset + 12].toInt() and 0xFF}.${data[offset + 13].toInt() and 0xFF}." +
                "${data[offset + 14].toInt() and 0xFF}.${data[offset + 15].toInt() and 0xFF}"

        val dstIp = "${data[offset + 16].toInt() and 0xFF}.${data[offset + 17].toInt() and 0xFF}." +
                "${data[offset + 18].toInt() and 0xFF}.${data[offset + 19].toInt() and 0xFF}"

        return IpHeader(version, headerLength, totalLength, protocol, srcIp, dstIp)
    }

    /**
     * Parse a TCP header from raw bytes.
     */
    fun parseTCP(data: ByteArray, offset: Int): TcpHeader? {
        if (data.size < offset + 20) return null

        val srcPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        val dstPort = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)

        val seqNum = ((data[offset + 4].toInt() and 0xFF).toLong() shl 24) or
                ((data[offset + 5].toInt() and 0xFF).toLong() shl 16) or
                ((data[offset + 6].toInt() and 0xFF).toLong() shl 8) or
                (data[offset + 7].toInt() and 0xFF).toLong()

        val ackNum = ((data[offset + 8].toInt() and 0xFF).toLong() shl 24) or
                ((data[offset + 9].toInt() and 0xFF).toLong() shl 16) or
                ((data[offset + 10].toInt() and 0xFF).toLong() shl 8) or
                (data[offset + 11].toInt() and 0xFF).toLong()

        val dataOffset = (data[offset + 12].toInt() and 0xF0) shr 4
        val headerLength = dataOffset * 4
        val flags = data[offset + 13].toInt() and 0xFF

        val windowSize = ((data[offset + 14].toInt() and 0xFF) shl 8) or
                (data[offset + 15].toInt() and 0xFF)

        val payloadOffset = offset + headerLength
        val payloadSize = maxOf(0, data.size - payloadOffset)

        return TcpHeader(srcPort, dstPort, seqNum, ackNum, headerLength, flags, windowSize, payloadOffset, payloadSize)
    }

    /**
     * Parse a UDP header from raw bytes.
     */
    fun parseUDP(data: ByteArray, offset: Int): UdpHeader? {
        if (data.size < offset + 8) return null

        val srcPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        val dstPort = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
        val length = ((data[offset + 4].toInt() and 0xFF) shl 8) or (data[offset + 5].toInt() and 0xFF)

        val payloadOffset = offset + 8
        val payloadSize = maxOf(0, length - 8)

        return UdpHeader(srcPort, dstPort, length, payloadOffset, payloadSize)
    }

    /**
     * Parse DNS query from UDP payload.
     */
    fun parseDNS(data: ByteArray, offset: Int, length: Int): DnsInfo? {
        if (length < 12) return null

        try {
            val txId = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
            val flags = ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
            val isResponse = (flags and 0x8000) != 0
            val qdCount = ((data[offset + 4].toInt() and 0xFF) shl 8) or (data[offset + 5].toInt() and 0xFF)
            val anCount = ((data[offset + 12].toInt() and 0xFF) shl 8) or (data[offset + 13].toInt() and 0xFF)

            // Parse question
            var pos = offset + 12
            val queryName = StringBuilder()
            while (pos < offset + length) {
                val labelLen = data[pos].toInt() and 0xFF
                if (labelLen == 0) { pos++; break }
                if (queryName.isNotEmpty()) queryName.append(".")
                pos++
                for (i in 0 until labelLen) {
                    if (pos < offset + length) {
                        queryName.append(data[pos].toInt().toChar())
                        pos++
                    }
                }
            }

            val qType = if (pos + 1 < offset + length) {
                ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            } else 0

            val typeName = when (qType) {
                1 -> "A"
                28 -> "AAAA"
                5 -> "CNAME"
                15 -> "MX"
                16 -> "TXT"
                else -> "TYPE$qType"
            }

            return DnsInfo(
                transactionId = txId,
                isResponse = isResponse,
                queryName = queryName.toString(),
                queryType = typeName,
                answerCount = anCount
            )
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Check if payload looks like HTTP.
     */
    fun isHTTPRequest(data: ByteArray, offset: Int, length: Int): Boolean {
        if (length < 4) return false
        val methods = arrayOf("GET ", "POST", "PUT ", "DELE", "PATC", "HEAD", "OPTI")
        val header = String(data, offset, minOf(length, 8))
        return methods.any { header.startsWith(it) }
    }

    /**
     * Extract HTTP method and host from payload.
     */
    fun extractHTTPInfo(data: ByteArray, offset: Int, length: Int): HttpInfo? {
        if (length < 10) return null
        try {
            val payload = String(data, offset, minOf(length, 2048))
            val lines = payload.split("\r\n")
            if (lines.isEmpty()) return null

            // Parse request line: METHOD /path HTTP/1.1
            val requestLine = lines[0]
            val parts = requestLine.split(" ")
            if (parts.size < 2) return null

            val method = parts[0]
            val path = parts[1]

            // Parse headers
            val headers = mutableMapOf<String, String>()
            var host: String? = null
            for (i in 1 until lines.size) {
                val line = lines[i]
                if (line.isEmpty()) break
                val colonIdx = line.indexOf(':')
                if (colonIdx > 0) {
                    val key = line.substring(0, colonIdx).trim()
                    val value = line.substring(colonIdx + 1).trim()
                    headers[key] = value
                    if (key.equals("Host", ignoreCase = true)) host = value
                }
            }

            return HttpInfo(method, host, path, headers)
        } catch (e: Exception) {
            return null
        }
    }

    /**
     * Check if payload looks like TLS ClientHello.
     */
    fun isTLSClientHello(data: ByteArray, offset: Int, length: Int): Boolean {
        if (length < 5) return false
        return data[offset] == 0x16.toByte() && // ContentType: Handshake
                data[offset + 1] == 0x03.toByte() && // Version major
                data[offset + 2] in 0x00..0x03 && // Version minor
                data[offset + 5] == 0x01.toByte() // HandshakeType: ClientHello
    }

    /**
     * Extract SNI from TLS ClientHello.
     */
    fun extractSNI(data: ByteArray, offset: Int, length: Int): String? {
        try {
            if (length < 43) return null
            var pos = offset + 5 // Skip record header
            pos += 4 // Skip handshake header
            pos += 2 // Skip client version
            pos += 32 // Skip random

            val sessionIdLen = data[pos].toInt() and 0xFF
            pos += 1 + sessionIdLen

            val cipherSuitesLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2 + cipherSuitesLen

            val compressionLen = data[pos].toInt() and 0xFF
            pos += 1 + compressionLen

            if (pos >= offset + length) return null

            // Extensions
            val extensionsLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2

            val extEnd = pos + extensionsLen
            while (pos + 4 <= extEnd && pos + 4 <= offset + length) {
                val extType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
                val extLen = ((data[pos + 2].toInt() and 0xFF) shl 8) or (data[pos + 3].toInt() and 0xFF)
                pos += 4

                if (extType == 0x0000) { // SNI extension
                    pos += 2 // skip server name list length
                    pos += 1 // skip server name type
                    val nameLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
                    pos += 2
                    if (pos + nameLen <= offset + length) {
                        return String(data, pos, nameLen)
                    }
                }
                pos += extLen
            }
        } catch (e: Exception) {
            return null
        }
        return null
    }

    data class DnsInfo(
        val transactionId: Int,
        val isResponse: Boolean,
        val queryName: String,
        val queryType: String,
        val answerCount: Int
    )

    data class HttpInfo(
        val method: String,
        val host: String?,
        val path: String,
        val headers: Map<String, String>
    )
}
