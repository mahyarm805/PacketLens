package com.packetlens.data.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "captured_packets")
data class CapturedPacketEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val protocol: String,
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val appId: Int = -1,
    val appName: String = "",
    val packageName: String = "",
    val length: Int = 0,
    val direction: String = "OUTGOING",
    val httpMethod: String? = null,
    val httpUrl: String? = null,
    val httpHost: String? = null,
    val httpPath: String? = null,
    val httpStatusCode: Int? = null,
    val httpContentType: String? = null,
    val requestBody: String? = null,
    val responseBody: String? = null,
    val requestHeadersJson: String? = null,
    val responseHeadersJson: String? = null,
    val dnsQuery: String? = null,
    val dnsType: String? = null,
    val dnsResponse: String? = null,
    val tlsSni: String? = null,
    val tlsVersion: String? = null,
    val tlsCipherSuite: String? = null,
    val connectTimeMs: Long = 0,
    val totalTimeMs: Long = 0,
    val payloadPreview: String = ""
)
