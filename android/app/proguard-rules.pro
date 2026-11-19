# AegisGuard Android ProGuard / R8 rules
-keep class com.aegisguard.app.admin.AegisDeviceAdminReceiver { *; }
-keep class com.aegisguard.app.accessibility.ContentGuardAccessibilityService { *; }
-keep class com.aegisguard.app.vpn.AegisVpnService { *; }
-keep class com.aegisguard.app.boot.BootReceiver { *; }
-dontwarn org.tensorflow.lite.**
