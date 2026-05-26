-keep class com.alaa.securehello.** { *; }
-keepclassmembers class com.alaa.securehello.SecurityHelper {
    native <methods>;
}
-dontwarn **
-obfuscatecode
-repackageclasses ''
-allowaccessmodification
-optimizationpasses 5
