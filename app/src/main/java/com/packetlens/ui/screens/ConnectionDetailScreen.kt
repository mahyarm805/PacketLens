package com.packetlens.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.compose.ui.platform.LocalContext
import androidx.activity.ComponentActivity
import com.packetlens.model.CapturedPacket
import com.packetlens.ui.viewmodel.CaptureViewModel

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
                contentAlignment = androidx.compose.ui.Alignment.Center
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
            // Overview section
            DetailSection(title = "📋 Overview") {
                DetailRow("Protocol", packet.protocol.name)
                DetailRow("App", packet.appName.ifEmpty { packet.packageName.ifEmpty { "System" } })
                DetailRow("Package", packet.packageName)
                DetailRow("Source", "${packet.srcIp}:${packet.srcPort}")
                DetailRow("Destination", "${packet.dstIp}:${packet.dstPort}")
                DetailRow("Direction", packet.direction.name)
                DetailRow("Size", "${packet.length} bytes")
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
