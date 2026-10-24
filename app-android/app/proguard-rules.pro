# UniFFI / JNA symbols must survive minification.
-keep class uniffi.aegis_bridge.** { *; }
-keep class dev.aegiskey.app.bridge.** { *; }

# Google Tink / ErrorProne annotation suppressions for R8
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
