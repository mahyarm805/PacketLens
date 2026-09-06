package com.packetlens.model

/**
 * Represents a captured network packet/connection
 */
data class CapturedPacket(
    val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val protocol: Protocol,
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val appId: Int = -1,
    val appName: String = "",
    val packageName: String = "",
    val length: Int = 0,
    val direction: Direction = Direction.OUTGOING,
    // HTTP info
    val httpMethod: String? = null,
    val httpUrl: String? = null,
    val httpHost: String? = null,
    val httpPath: String? = null,
    val httpStatusCode: Int? = null,
    val httpContentType: String? = null,
    val requestBody: String? = null,
    val responseBody: String? = null,
    val requestHeaders: Map<String, String> = emptyMap(),
    val responseHeaders: Map<String, String> = emptyMap(),
    // DNS info
    val dnsQuery: String? = null,
    val dnsType: String? = null,
    val dnsResponse: String? = null,
    // TLS info
    val tlsSni: String? = null,
    val tlsVersion: String? = null,
    val tlsCipherSuite: String? = null,
    // Timing
    val connectTimeMs: Long = 0,
    val totalTimeMs: Long = 0,
    // Raw
    val payloadPreview: String = ""
)

enum class Protocol {
    TCP, UDP, HTTP, HTTPS, DNS, TLS, UNKNOWN
}

enum class Direction {
    INCOMING, OUTGOING
}
