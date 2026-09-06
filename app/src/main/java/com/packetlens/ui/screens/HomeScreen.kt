package com.packetlens.ui.screens

import android.app.Activity
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.compose.ui.platform.LocalContext
import androidx.activity.ComponentActivity
import com.packetlens.ui.components.PacketRow
import com.packetlens.ui.viewmodel.CaptureViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onPacketClick: (Long) -> Unit,
    viewModel: CaptureViewModel = hiltViewModel(
        viewModelStoreOwner = LocalContext.current as ComponentActivity
    )
) {
    val packets by viewModel.packets.collectAsState()
    val isCapturing by viewModel.isCapturing.collectAsState()
    val filter by viewModel.filter.collectAsState()
    val stats by viewModel.stats.collectAsState()

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.onVpnPermissionGranted()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "📡",
                            fontSize = 24.sp,
                            modifier = Modifier.padding(end = 8.dp)
                        )
                        Text(
                            text = "PacketLens",
                            fontWeight = FontWeight.Bold
                        )
                    }
                },
                actions = {
                    // Start/Stop button
                    val buttonColor by animateColorAsState(
                        if (isCapturing) Color(0xFFF44336) else Color(0xFF4CAF50),
                        label = "buttonColor"
                    )
                    Button(
                        onClick = {
                            if (isCapturing) {
                                viewModel.stopCapture()
                            } else {
                                val vpnIntent = viewModel.checkVpnPermission()
                                if (vpnIntent != null) {
                                    vpnPermissionLauncher.launch(vpnIntent)
                                } else {
                                    viewModel.startCapture()
                                }
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = buttonColor),
                        shape = RoundedCornerShape(20.dp)
                    ) {
                        Icon(
                            imageVector = if (isCapturing) Icons.Default.Stop else Icons.Default.PlayArrow,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(if (isCapturing) "Stop" else "Start")
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    // Clear button
                    IconButton(onClick = { viewModel.clearPackets() }) {
                        Icon(Icons.Default.Delete, contentDescription = "Clear")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            // Stats bar
            StatsBar(stats)

            // Filter chips
            FilterChips(filter) { viewModel.setFilter(it) }

            // Packet list
            if (packets.isEmpty()) {
                EmptyState(isCapturing)
            } else {
                val listState = rememberLazyListState()
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize()
                ) {
                    items(
                        items = packets,
                        key = { it.id }
                    ) { packet ->
                        PacketRow(
                            packet = packet,
                            onClick = { onPacketClick(packet.id) }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StatsBar(stats: CaptureViewModel.Stats) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            StatItem("Total", stats.totalPackets.toString())
            StatItem("HTTP", stats.httpCount.toString(), Color(0xFF4CAF50))
            StatItem("DNS", stats.dnsCount.toString(), Color(0xFFFF9800))
            StatItem("TLS", stats.tlsCount.toString(), Color(0xFF9C27B0))
            StatItem("Data", formatBytes(stats.totalBytes))
        }
    }
}

@Composable
private fun StatItem(label: String, value: String, color: Color = MaterialTheme.colorScheme.onSurface) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            color = color
        )
        Text(
            text = label,
            fontSize = 10.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun FilterChips(
    currentFilter: CaptureViewModel.ProtocolFilter,
    onFilterChange: (CaptureViewModel.ProtocolFilter) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        CaptureViewModel.ProtocolFilter.entries.forEach { f ->
            FilterChip(
                selected = currentFilter == f,
                onClick = { onFilterChange(f) },
                label = {
                    Text(
                        text = f.name,
                        fontSize = 12.sp
                    )
                },
                leadingIcon = if (currentFilter == f) {
                    { Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(14.dp)) }
                } else null
            )
        }
    }
}

@Composable
private fun EmptyState(isCapturing: Boolean) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = if (isCapturing) "📡" else "🚀",
                fontSize = 64.sp
            )
            Text(
                text = if (isCapturing) "Listening for traffic..." else "Tap Start to begin capture",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (isCapturing) {
                CircularProgressIndicator(
                    modifier = Modifier.size(24.dp),
                    strokeWidth = 2.dp
                )
            }
        }
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
