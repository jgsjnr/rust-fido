package dev.aegiskey.app.net

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import dev.aegiskey.app.log.DeviceLog
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Descoberta mDNS (NsdManager): filtra servicos `_http._tcp.` cujo host
 * comeca com `aegiskey-` (ex.: `aegiskey-00AF.local`).
 * Sem permissao nova: usa so INTERNET (ja declarada). CHANGE_WIFI_MULTICAST
 * e ACCESS_FINE_LOCATION NAO sao pedidas (constraint: nada alem de USB host).
 * IP manual continua disponivel na tela (fallback primario).
 * Sem PII no log: so conta de achados + eventos, nunca host/IP.
 */
class WifiDiscovery(context: Context) {

    data class Found(val name: String, val host: String, val port: Int)

    private val nsd: NsdManager? =
        runCatching { context.getSystemService(Context.NSD_SERVICE) as NsdManager }.getOrNull()

    private val _found = MutableStateFlow<List<Found>>(emptyList())
    val found: StateFlow<List<Found>> = _found.asStateFlow()

    private val _scanning = MutableStateFlow(false)
    val scanning: StateFlow<Boolean> = _scanning.asStateFlow()

    private var discoveryListener: NsdManager.DiscoveryListener? = null

    fun start() {
        val manager = nsd ?: return
        if (_scanning.value) return
        _found.value = emptyList()
        _scanning.value = true
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(regType: String) {
                DeviceLog.append(DeviceLog.Category.WIFI, "mDNS discovery started")
            }
            override fun onServiceFound(service: NsdServiceInfo) {
                val name = service.serviceName ?: return
                if (!name.startsWith("aegiskey-", ignoreCase = true)) return
                runCatching { manager.resolveService(service, resolveListener()) }
            }
            override fun onServiceLost(service: NsdServiceInfo) {
                val name = service.serviceName ?: return
                _found.value = _found.value.filterNot { it.name == name }
            }
            override fun onDiscoveryStopped(serviceType: String) {
                _scanning.value = false
            }
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                _scanning.value = false
                DeviceLog.append(DeviceLog.Category.WIFI, "mDNS start failed")
            }
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                _scanning.value = false
            }
        }
        discoveryListener = listener
        runCatching {
            manager.discoverServices("_http._tcp.", NsdManager.PROTOCOL_DNS_SD, listener)
        }.onFailure {
            _scanning.value = false
        }
    }

    fun stop() {
        val manager = nsd ?: run {
            _scanning.value = false
            return
        }
        runCatching {
            discoveryListener?.let { manager.stopServiceDiscovery(it) }
        }
        discoveryListener = null
        _scanning.value = false
    }

    private fun resolveListener(): NsdManager.ResolveListener =
        object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = Unit
            override fun onServiceResolved(serviceInfo: NsdServiceInfo) {
                val name = serviceInfo.serviceName ?: return
                val host = runCatching {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        serviceInfo.hostAddresses.firstOrNull()?.hostAddress
                    } else {
                        @Suppress("DEPRECATION")
                        serviceInfo.host?.hostAddress
                    }
                }.getOrNull() ?: return
                val port = serviceInfo.port
                if (port <= 0) return
                val entry = Found(name.take(64), host.take(64), port)
                _found.value = (_found.value.filterNot { it.name == entry.name } + entry).take(16)
                DeviceLog.append(DeviceLog.Category.WIFI, "mDNS found count=" + _found.value.size)
            }
        }
}
