# UniFFI / JNA symbols must survive minification.
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class uniffi.** { *; }
-dontwarn java.awt.**
-keep class dev.aegiskey.app.bridge.** { *; }
-keep class dev.aegiskey.app.autofill.AegisAutofillService { *; }

# Google Tink / ErrorProne annotation suppressions for R8
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
