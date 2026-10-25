package dev.aegiskey.app.data.local

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dev.aegiskey.app.data.debug.DebugHardwareChipMock
import dev.aegiskey.app.domain.model.AccessKeyType
import dev.aegiskey.app.domain.model.ConnectedKeyDevice
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecurityToggles
import dev.aegiskey.app.domain.model.TotpAccountItem
import dev.aegiskey.app.domain.model.VaultKeyEntry
import org.json.JSONArray
import org.json.JSONObject

/**
 * Storage seguro para dispositivos pareados, entradas do cofre e contas TOTP sincronizadas.
 * Utiliza [EncryptedSharedPreferences] no Android com MasterKey AES256_GCM,
 * e possui fallback em memória para execução em JVM/testes unitários.
 */
class EncryptedKeysStore(private val context: Context?) {

    private val prefs: SharedPreferences? = try {
        if (context != null) {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                PREFS_FILE_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } else null
    } catch (_: Throwable) {
        null
    }

    private val inMemoryFallback = mutableMapOf<String, String>()

    init {
        DebugHardwareChipMock.purgeResidualMockData(this)
    }

    fun removeKeyVaultAndTotp(keyId: String) {
        putString(KEY_VAULT_PREFIX + keyId, null)
        putString(KEY_TOTP_PREFIX + keyId, null)
    }

    @Synchronized
    private fun getString(key: String): String? {
        return prefs?.getString(key, null) ?: inMemoryFallback[key]
    }

    @Synchronized
    private fun putString(key: String, value: String?) {
        if (value == null) {
            inMemoryFallback.remove(key)
            prefs?.edit()?.remove(key)?.apply()
        } else {
            inMemoryFallback[key] = value
            prefs?.edit()?.putString(key, value)?.apply()
        }
    }

    // --- Connected Keys ---

    fun loadConnectedKeys(): List<ConnectedKeyDevice> {
        val raw = getString(KEY_CONNECTED_DEVICES) ?: return emptyList()
        return try {
            val array = JSONArray(raw)
            val list = mutableListOf<ConnectedKeyDevice>()
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                val transportName = obj.optString("transportType", ConnectionTransportType.BLE.name)
                val transport = try {
                    ConnectionTransportType.valueOf(transportName)
                } catch (_: IllegalArgumentException) {
                    ConnectionTransportType.BLE
                }
                list.add(
                    ConnectedKeyDevice(
                        id = obj.getString("id"),
                        displayName = obj.optString("displayName", "AegisKey"),
                        hardwareAddressOrId = obj.optString("hardwareAddressOrId", ""),
                        bindingIdHex = obj.optString("bindingIdHex", ""),
                        transportType = transport,
                        isCurrentlyConnected = obj.optBoolean("isCurrentlyConnected", false),
                        firmwareRevision = obj.optInt("firmwareRevision", 1),
                        lastConnectedEpochMs = obj.optLong("lastConnectedEpochMs", System.currentTimeMillis()),
                        toggles = SecurityToggles(
                            lockOnWalkAway = obj.optBoolean("lockOnWalkAway", true),
                            requireBiometricsOnOpen = obj.optBoolean("requireBiometricsOnOpen", false),
                            requireTouchForEveryCode = obj.optBoolean("requireTouchForEveryCode", true)
                        )
                    )
                )
            }
            list
        } catch (_: Throwable) {
            emptyList()
        }
    }

    fun saveConnectedKeys(keys: List<ConnectedKeyDevice>) {
        val array = JSONArray()
        for (key in keys) {
            val obj = JSONObject().apply {
                put("id", key.id)
                put("displayName", key.displayName)
                put("hardwareAddressOrId", key.hardwareAddressOrId)
                put("bindingIdHex", key.bindingIdHex)
                put("transportType", key.transportType.name)
                put("isCurrentlyConnected", key.isCurrentlyConnected)
                put("firmwareRevision", key.firmwareRevision)
                put("lastConnectedEpochMs", key.lastConnectedEpochMs)
                put("lockOnWalkAway", key.toggles.lockOnWalkAway)
                put("requireBiometricsOnOpen", key.toggles.requireBiometricsOnOpen)
                put("requireTouchForEveryCode", key.toggles.requireTouchForEveryCode)
            }
            array.put(obj)
        }
        putString(KEY_CONNECTED_DEVICES, array.toString())
    }

    // --- Active Key ID ---

    fun loadActiveKeyId(): String? = getString(KEY_ACTIVE_KEY_ID)

    fun saveActiveKeyId(keyId: String?) {
        putString(KEY_ACTIVE_KEY_ID, keyId)
    }

    // --- Vault Entries per Key ---

    fun loadVaultEntries(keyId: String): List<VaultKeyEntry> {
        val raw = getString(KEY_VAULT_PREFIX + keyId) ?: return emptyList()
        return try {
            val array = JSONArray(raw)
            val list = mutableListOf<VaultKeyEntry>()
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                val typeName = obj.optString("type", AccessKeyType.PASSKEY_FIDO.name)
                val accessType = try {
                    AccessKeyType.valueOf(typeName)
                } catch (_: IllegalArgumentException) {
                    AccessKeyType.PASSKEY_FIDO
                }
                list.add(
                    VaultKeyEntry(
                        slotId = obj.getInt("slotId"),
                        label = obj.getString("label"),
                        type = accessType,
                        publicSummary = obj.optString("publicSummary", ""),
                        createdAtEpochMs = obj.optLong("createdAtEpochMs", System.currentTimeMillis()),
                        algorithmOrCurve = obj.optString("algorithmOrCurve", "ES256 (P-256)"),
                        usageDescription = obj.optString("usageDescription", "Autenticação e Assinatura"),
                        derivationPathOrSlotCode = obj.optString("derivationPathOrSlotCode", ""),
                        envelopeHex = obj.optString("envelopeHex", ""),
                        requiresPhysicalTouch = obj.optBoolean("requiresPhysicalTouch", true)
                    )
                )
            }
            list
        } catch (_: Throwable) {
            emptyList()
        }
    }

    fun saveVaultEntries(keyId: String, entries: List<VaultKeyEntry>) {
        val array = JSONArray()
        for (entry in entries) {
            val obj = JSONObject().apply {
                put("slotId", entry.slotId)
                put("label", entry.label)
                put("type", entry.type.name)
                put("publicSummary", entry.publicSummary)
                put("createdAtEpochMs", entry.createdAtEpochMs)
                put("algorithmOrCurve", entry.algorithmOrCurve)
                put("usageDescription", entry.usageDescription)
                put("derivationPathOrSlotCode", entry.derivationPathOrSlotCode)
                put("envelopeHex", entry.envelopeHex)
                put("requiresPhysicalTouch", entry.requiresPhysicalTouch)
            }
            array.put(obj)
        }
        putString(KEY_VAULT_PREFIX + keyId, array.toString())
    }

    // --- TOTP Accounts per Key ---

    fun loadTotpAccounts(keyId: String): List<TotpAccountItem> {
        val raw = getString(KEY_TOTP_PREFIX + keyId) ?: return emptyList()
        return try {
            val array = JSONArray(raw)
            val list = mutableListOf<TotpAccountItem>()
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                list.add(
                    TotpAccountItem(
                        id = obj.getString("id"),
                        issuer = obj.optString("issuer", ""),
                        accountName = obj.optString("accountName", ""),
                        currentCode = obj.optString("currentCode", "------"),
                        formattedCode = obj.optString("formattedCode", "--- ---"),
                        remainingSeconds = obj.optInt("remainingSeconds", 30),
                        periodSeconds = obj.optInt("periodSeconds", 30),
                        digits = obj.optInt("digits", 6),
                        requiresTouchToRefresh = obj.optBoolean("requiresTouchToRefresh", false),
                        isHotp = obj.optBoolean("isHotp", false),
                        counter = obj.optLong("counter", 0L),
                        algorithm = obj.optString("algorithm", "SHA1")
                    )
                )
            }
            list
        } catch (_: Throwable) {
            emptyList()
        }
    }

    fun saveTotpAccounts(keyId: String, accounts: List<TotpAccountItem>) {
        val array = JSONArray()
        for (item in accounts) {
            val obj = JSONObject().apply {
                put("id", item.id)
                put("issuer", item.issuer)
                put("accountName", item.accountName)
                put("currentCode", item.currentCode)
                put("formattedCode", item.formattedCode)
                put("remainingSeconds", item.remainingSeconds)
                put("periodSeconds", item.periodSeconds)
                put("digits", item.digits)
                put("requiresTouchToRefresh", item.requiresTouchToRefresh)
                put("isHotp", item.isHotp)
                put("counter", item.counter)
                put("algorithm", item.algorithm)
            }
            array.put(obj)
        }
        putString(KEY_TOTP_PREFIX + keyId, array.toString())
    }

    fun clearAll() {
        inMemoryFallback.clear()
        prefs?.edit()?.clear()?.apply()
    }

    companion object {
        private const val PREFS_FILE_NAME = "aegis_keys_vault_prefs"
        private const val KEY_CONNECTED_DEVICES = "connected_devices_list"
        private const val KEY_ACTIVE_KEY_ID = "active_key_id"
        private const val KEY_VAULT_PREFIX = "vault_entries_"
        private const val KEY_TOTP_PREFIX = "totp_accounts_"
    }
}
