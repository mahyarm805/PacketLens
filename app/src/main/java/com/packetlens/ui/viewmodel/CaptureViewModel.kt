package com.packetlens.ui.viewmodel

import android.app.Application
import android.content.Intent
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.packetlens.capture.AppResolver
import com.packetlens.model.CapturedPacket
import com.packetlens.model.Protocol
import com.packetlens.service.CaptureVpnService
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class CaptureViewModel @Inject constructor(
    private val app: Application,
    private val appResolver: AppResolver
) : AndroidViewModel(app) {

    private val _packets = MutableStateFlow<List<CapturedPacket>>(emptyList())
    val packets: StateFlow<List<CapturedPacket>> = _packets.asStateFlow()

    private val _selectedPacket = MutableStateFlow<CapturedPacket?>(null)
    val selectedPacket: StateFlow<CapturedPacket?> = _selectedPacket.asStateFlow()

    private val _isCapturing = MutableStateFlow(false)
    val isCapturing: StateFlow<Boolean> = _isCapturing.asStateFlow()

    private val _filter = MutableStateFlow(ProtocolFilter.ALL)
    val filter: StateFlow<ProtocolFilter> = _filter.asStateFlow()

    private val _stats = MutableStateFlow(Stats())
    val stats: StateFlow<Stats> = _stats.asStateFlow()

    // App filter state
    private val _appFilterMode = MutableStateFlow(AppFilterMode.ALL)
    val appFilterMode: StateFlow<AppFilterMode> = _appFilterMode.asStateFlow()

    private val _selectedApps = MutableStateFlow<Set<String>>(emptySet())
    val selectedApps: StateFlow<Set<String>> = _selectedApps.asStateFlow()

    private val allPackets = mutableListOf<CapturedPacket>()
    private var packetIdCounter = 0L

    // Available apps for filter (cached)
    private val _availableApps = MutableStateFlow<List<AppResolver.AppInfo>>(emptyList())
    val availableApps: StateFlow<List<AppResolver.AppInfo>> = _availableApps.asStateFlow()

    init {
        // Listen for packets from VPNService
        viewModelScope.launch {
            CaptureVpnService.packets.collect { packet ->
                val packetWithId = packet.copy(id = packetIdCounter++)
                allPackets.add(0, packetWithId)
                if (allPackets.size > 5000) {
                    allPackets.removeLast()
                }
                applyFilter()
                updateStats()
            }
        }

        // Listen for capture state
        viewModelScope.launch {
            CaptureVpnService.isRunning.collect { running ->
                _isCapturing.value = running
            }
        }

        // Load available apps
        loadAvailableApps()
    }

    fun startCapture() {
        appResolver.clearPortCache()
        val intent = Intent(app, CaptureVpnService::class.java).setAction("START")
        app.startForegroundService(intent)
    }

    fun stopCapture() {
        val intent = Intent(app, CaptureVpnService::class.java).setAction("STOP")
        app.startForegroundService(intent)
    }

    fun checkVpnPermission(): Intent? {
        return VpnService.prepare(app)
    }

    fun onVpnPermissionGranted() {
        startCapture()
    }

    fun selectPacket(packet: CapturedPacket) {
        _selectedPacket.value = packet
    }

    fun clearSelection() {
        _selectedPacket.value = null
    }

    fun setFilter(filter: ProtocolFilter) {
        _filter.value = filter
        applyFilter()
    }

    fun clearPackets() {
        allPackets.clear()
        packetIdCounter = 0
        _packets.value = emptyList()
        _stats.value = Stats()
    }

    // App filter functions
    fun setAppFilterMode(mode: AppFilterMode) {
        _appFilterMode.value = mode
        if (mode == AppFilterMode.ALL) {
            _selectedApps.value = emptySet()
        }
        applyFilter()
    }

    fun toggleAppFilter(packageName: String) {
        val current = _selectedApps.value.toMutableSet()
        if (current.contains(packageName)) {
            current.remove(packageName)
        } else {
            current.add(packageName)
        }
        _selectedApps.value = current
        applyFilter()
    }

    fun setSelectedApps(apps: Set<String>) {
        _selectedApps.value = apps
        applyFilter()
    }

    fun clearAppFilter() {
        _selectedApps.value = emptySet()
        _appFilterMode.value = AppFilterMode.ALL
        applyFilter()
    }

    private fun loadAvailableApps() {
        viewModelScope.launch {
            val apps = appResolver.getAllInstalledApps()
            _availableApps.value = apps
        }
    }

    private fun applyFilter() {
        val protocolFilter = _filter.value
        val appMode = _appFilterMode.value
        val selectedApps = _selectedApps.value

        _packets.value = allPackets.filter { packet ->
            // Protocol filter
            val protocolMatch = when (protocolFilter) {
                ProtocolFilter.ALL -> true
                ProtocolFilter.HTTP -> packet.protocol == Protocol.HTTP || packet.protocol == Protocol.HTTPS
                ProtocolFilter.DNS -> packet.protocol == Protocol.DNS
                ProtocolFilter.TLS -> packet.protocol == Protocol.TLS
                ProtocolFilter.TCP -> packet.protocol == Protocol.TCP
                ProtocolFilter.UDP -> packet.protocol == Protocol.UDP
            }

            // App filter
            val appMatch = when (appMode) {
                AppFilterMode.ALL -> true
                AppFilterMode.SELECTED -> {
                    if (selectedApps.isEmpty()) true
                    else packet.packageName in selectedApps
                }
            }

            protocolMatch && appMatch
        }
    }

    private fun updateStats() {
        _stats.value = Stats(
            totalPackets = allPackets.size,
            httpCount = allPackets.count { it.protocol == Protocol.HTTP || it.protocol == Protocol.HTTPS },
            dnsCount = allPackets.count { it.protocol == Protocol.DNS },
            tlsCount = allPackets.count { it.protocol == Protocol.TLS },
            totalBytes = allPackets.sumOf { it.length.toLong() }
        )
    }

    data class Stats(
        val totalPackets: Int = 0,
        val httpCount: Int = 0,
        val dnsCount: Int = 0,
        val tlsCount: Int = 0,
        val totalBytes: Long = 0
    )

    enum class ProtocolFilter {
        ALL, HTTP, DNS, TLS, TCP, UDP
    }

    enum class AppFilterMode {
        ALL, SELECTED
    }
}
