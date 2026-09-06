package com.packetlens.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.packetlens.model.CapturedPacket
import com.packetlens.model.Protocol
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun PacketRow(
    packet: CapturedPacket,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val protocolColor = when (packet.protocol) {
        Protocol.HTTP -> Color(0xFF4CAF50)
        Protocol.HTTPS -> Color(0xFF2196F3)
        Protocol.TLS -> Color(0xFF9C27B0)
        Protocol.DNS -> Color(0xFFFF9800)
        Protocol.TCP -> Color(0xFF607D8B)
        Protocol.UDP -> Color(0xFF795548)
        Protocol.UNKNOWN -> Color.Gray
    }

    val protocolLabel = when (packet.protocol) {
        Protocol.HTTP -> "HTTP"
        Protocol.HTTPS -> "HTTPS"
        Protocol.TLS -> "TLS"
        Protocol.DNS -> "DNS"
        Protocol.TCP -> "TCP"
        Protocol.UDP -> "UDP"
        Protocol.UNKNOWN -> "?"
    }

    val statusIcon = when {
        packet.protocol == Protocol.DNS -> "🌐"
        packet.httpStatusCode != null && packet.httpStatusCode in 200..299 -> "✅"
        packet.httpStatusCode != null && packet.httpStatusCode in 300..399 -> "↪️"
        packet.httpStatusCode != null && packet.httpStatusCode in 400..599 -> "❌"
        packet.tlsSni != null -> "🔒"
        else -> "📡"
    }

    val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
    val timeStr = timeFormat.format(Date(packet.timestamp))

    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 4.dp),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Protocol badge
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(protocolColor.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = protocolLabel,
                    color = protocolColor,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            // Connection info
            Column(modifier = Modifier.weight(1f)) {
                // Top line: Host/URL + Status icon
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = statusIcon,
                        fontSize = 14.sp,
                        modifier = Modifier.padding(end = 4.dp)
                    )
                    Text(
                        text = packet.httpHost ?: packet.tlsSni ?: packet.dnsQuery
                                ?: "${packet.dstIp}:${packet.dstPort}",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }

                Spacer(modifier = Modifier.height(2.dp))

                // Bottom line: App name + Method + Path
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = packet.appName.ifEmpty { packet.packageName.ifEmpty { "System" } },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )

                    if (packet.httpMethod != null) {
                        Text(
                            text = " · ${packet.httpMethod}",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = when (packet.httpMethod) {
                                "GET" -> Color(0xFF4CAF50)
                                "POST" -> Color(0xFF2196F3)
                                "PUT" -> Color(0xFFFF9800)
                                "DELETE" -> Color(0xFFF44336)
                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                            }
                        )
                    }

                    if (packet.httpPath != null) {
                        Text(
                            text = " ${packet.httpPath}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    if (packet.dnsQuery != null) {
                        Text(
                            text = " · ${packet.dnsType ?: "A"}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                // Third line: Preview
                if (packet.payloadPreview.isNotEmpty() && packet.httpMethod == null && packet.dnsQuery == null) {
                    Text(
                        text = packet.payloadPreview,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp
                    )
                }
            }

            // Right side: Size + Time
            Column(
                horizontalAlignment = Alignment.End,
                modifier = Modifier.padding(start = 8.dp)
            ) {
                Text(
                    text = formatBytes(packet.length),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = FontFamily.Monospace
                )
                Text(
                    text = timeStr,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    fontSize = 10.sp
                )
            }
        }
    }
}

private fun formatBytes(bytes: Int): String {
    return when {
        bytes < 1024 -> "${bytes}B"
        bytes < 1024 * 1024 -> "%.1fKB".format(bytes / 1024.0)
        else -> "%.1fMB".format(bytes / (1024.0 * 1024))
    }
}
