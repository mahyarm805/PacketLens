package com.packetlens.ui.screens

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.activity.ComponentActivity
import com.packetlens.model.CapturedPacket
import com.packetlens.ui.viewmodel.CaptureViewModel
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionDetailScreen(
    packetId: Long,
    onBack: () -> Unit,
    viewModel: CaptureViewModel = hiltViewModel(
        viewModelStoreOwner = LocalContext.current as ComponentActivity
    )
) {
    val packets by viewModel.packets.collectAsState()
    val packet = packets.find { it.id == packetId }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Connection Detail") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { paddingValues ->
        if (packet == null) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                contentAlignment = Alignment.Center
            ) {
                Text("Packet not found", color = MaterialTheme.colorScheme.error)
            }
            return@Scaffold
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
        ) {
            // Application section (at top)
            ApplicationSection(packet)

            // Overview section
            DetailSection(title = "📋 Overview") {
                DetailRow("Protocol", packet.protocol.name)
                DetailRow("Source", "${packet.srcIp}:${packet.srcPort}")
                DetailRow("Destination", "${packet.dstIp}:${packet.dstPort}")
                DetailRow("Direction", packet.direction.name)
                DetailRow("Size", formatBytes(packet.length.toLong()))
            }

            // HTTP section
            if (packet.httpMethod != null) {
                DetailSection(title = "🌐 HTTP Request") {
                    DetailRow("Method", packet.httpMethod)
                    DetailRow("Host", packet.httpHost ?: "N/A")
                    DetailRow("Path", packet.httpPath ?: "N/A")
                    DetailRow("Status", packet.httpStatusCode?.toString() ?: "Pending")

                    if (packet.requestHeaders.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "Request Headers:",
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.primary
                        )
                        packet.requestHeaders.forEach { (key, value) ->
                            DetailRow(key, value)
                        }
                    }

                    if (packet.responseHeaders.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "Response Headers:",
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.primary
                        )
                        packet.responseHeaders.forEach { (key, value) ->
                            DetailRow(key, value)
                        }
                    }
                }
            }

            // TLS section
            if (packet.tlsSni != null) {
                DetailSection(title = "🔒 TLS") {
                    DetailRow("SNI", packet.tlsSni)
                    DetailRow("Version", packet.tlsVersion ?: "Unknown")
                    DetailRow("Cipher", packet.tlsCipherSuite ?: "Unknown")
                }
            }

            // DNS section
            if (packet.dnsQuery != null) {
                DetailSection(title = "🌐 DNS") {
                    DetailRow("Query", packet.dnsQuery)
                    DetailRow("Type", packet.dnsType ?: "A")
                    DetailRow("Response", packet.dnsResponse ?: "Pending")
                }
            }

            // Timing section
            DetailSection(title = "⏱️ Timing") {
                DetailRow("Timestamp", formatTimestamp(packet.timestamp))
                DetailRow("Connect", "${packet.connectTimeMs}ms")
                DetailRow("Total", "${packet.totalTimeMs}ms")
            }

            // Raw payload preview
            if (packet.payloadPreview.isNotEmpty()) {
                DetailSection(title = "📦 Payload Preview") {
                    Text(
                        text = packet.payloadPreview,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
private fun ApplicationSection(packet: CapturedPacket) {
    val context = LocalContext.current
    val appIcon = remember(packet.packageName) {
        if (packet.packageName.isNotEmpty()) {
            try {
                val appInfo = context.packageManager.getApplicationInfo(packet.packageName, 0)
                val icon = context.packageManager.getApplicationIcon(appInfo)
                val bitmap = BitmapFactory.decodeResource(context.resources, appInfo.icon)
                bitmap?.asImageBitmap()
            } catch (e: Exception) {
                null
            }
        } else null
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // App icon
            if (appIcon != null) {
                Image(
                    bitmap = appIcon,
                    contentDescription = packet.appName,
                    modifier = Modifier
                        .size(64.dp)
                        .clip(RoundedCornerShape(16.dp))
                )
            } else {
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .background(MaterialTheme.colorScheme.surfaceVariant),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = packet.appName.take(1).uppercase(),
                        style = MaterialTheme.typography.headlineMedium
                    )
                }
            }

            Spacer(modifier = Modifier.width(16.dp))

            // App info
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = packet.appName.ifEmpty { "Unknown Application" },
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = packet.packageName.ifEmpty { "N/A" },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "UID: ${if (packet.appId >= 0) packet.appId.toString() else "N/A"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun DetailSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = title,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            content()
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp)
    ) {
        Text(
            text = "$label:",
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(100.dp)
        )
        Text(
            text = value,
            fontSize = 13.sp,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes < 1024 -> "${bytes}B"
        bytes < 1024 * 1024 -> "%.1fKB".format(bytes / 1024.0)
        bytes < 1024 * 1024 * 1024 -> "%.1fMB".format(bytes / (1024.0 * 1024))
        else -> "%.1fGB".format(bytes / (1024.0 * 1024 * 1024))
    }
}

private fun formatTimestamp(timestamp: Long): String {
    val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())
    return sdf.format(Date(timestamp))
}
