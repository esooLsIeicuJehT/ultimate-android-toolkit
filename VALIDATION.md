# Validation — 2026-10-11

All 35 tests passed on Linux x86_64, with every optional integration test enabled.

Validated with actual tools:

- Apktool 3.0.3: compiled APK decoding, XML recipe edits, smali/resource rebuild.
- JADX 1.5.6: Java source decompilation.
- JDK 21 and Android build-tools 35: private keystore creation, alignment, v1/v2/v3 signing, verification, certificate inspection, same-key batch signing, and wrong-password rejection.
- Frida 17.2.14: read-only module/export enumeration of a test-owned live process.
- Ghidra 12.1.4: native library analysis, function/assembly/reference export, and actual pseudocode recovery for a compiled test function.
- MCP stdio: protocol responses, workspace boundaries, argument validation, searches, and native function report filtering.

Core checks cover safe extraction, hashes/provenance, searches across chunk boundaries, deterministic edits, patch failure isolation, DEX checks, and a bounded memory snapshot of the test process's own mapping. The built Python wheel includes the provider scripts.

Not established by these checks: Android phone installation, Termux ARM64 dependency behavior, Android root/SELinux access, ADB/SSH connectivity, or licensed IDA execution. The IDA adapter has invocation/output tests and needs testing against the user's licensed installation. See docs/testing.md.

The toolkit is maintained in the separate `esooLsIeicuJehT/ultimate-android-toolkit` repository. Distribution files contain the toolkit source and provider scripts; they do not include analyzed APKs, private keystores, or the external tool distributions.
