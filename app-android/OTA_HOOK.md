# OTA Hook (ota2 engine — unwired)

The offline firmware.bin OTA engine is landed but NOT wired: no manifest,
settings, or nav change in this commit (other lane owns `app-android/**`
edits). Wire it with these 3 lines:

1. Production key (Application init, before any OTA screen):
   `Ota2Keys.configureReleaseKey(BuildConfig.OTA_RELEASE_PUBKEY_HEX)`
   — add `buildConfigField("String", "OTA_RELEASE_PUBKEY_HEX", "\"<64 hex>\"")`
   to `app/build.gradle.kts` (release key hex; dev builds use the denied
   `DEV_PUBKEY_HEX` placeholder, never ship nonzero).
2. Settings entry (in `FriendlySettingsAndThemeScreen`, next to the other
   `SettingsNavigationItemCard` rows):
   `SettingsNavigationItemCard(..., onClick = { navController.navigate("ota2") })`
   + `composable("ota2") { Ota2Screen(transport = appContainer.keyTransport, currentVersion = <device-reported>) }`
   — BLE transport preferred (`BleKeyTransport.asOta2Transport()`), USB
   (`UsbKeyTransport`) fallback; `currentVersion` is authority device data.
3. No manifest change: SAF `OpenDocument` needs no permission; USB/BLE
   permissions already declared.

Protocol matched (firmware `ota.rs` + `stores/ota_store.rs`): manifest
104 B (`version||size||sha256||sig`), Ed25519-verify-strict over the 40
signed bytes, anti-rollback `version > current`, CHUNK `offset BE||data`
in-order with u32-BE received ack, status `0x00 OK / 0x01 NEED_UP /
0x04 FAIL`, 896 KiB storage budget under the 2 MiB wire ceiling.
No `0x33` COMMIT anywhere in ota2: after FINISH the device holds
Verified and waits for the physical-UP + USB ritual (owned by the
bootloader path). File layout: `firmware.bin = manifest(104 B) || image`.
