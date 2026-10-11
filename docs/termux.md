# Termux notes

Run `uat doctor` first. A missing executable affects only commands that need it. `uat doctor --root` explicitly calls `su` and may show a root-manager prompt on the device.

**Package installation:** use a current official Termux build and `termux-change-repo` if a mirror is unavailable. The installer does not upgrade Termux's pip separately. `aapt` supplies `zipalign`; `aapt2` supplies the native resource compiler. The rebuild wrapper explicitly selects Termux's aapt2 instead of Apktool's embedded desktop binary.

**Memory usage:** JADX defaults to two threads. Large apps may need fewer threads (`--threads 1`) and more free memory. Set `JAVA_TOOL_OPTIONS='-Xmx1g'` when needed; the JVM requires enough free device memory for that choice. APK extraction is bounded to 2 GiB total and 512 MiB per entry. For large archives use specialized tools.

**Shared storage:** use `termux-setup-storage` to access Downloads. Work inside Termux's private home directory; shared-storage mounts can restrict executable files and permissions. Signing keys should stay private and backed up separately.

**Vendor frameworks:** if Apktool reports a missing framework, export the matching framework/resource APK and run `uat apk framework framework-res.apk`. This toolkit keeps its framework cache under `$XDG_DATA_HOME/uat/frameworks` or `~/.local/share/uat/frameworks`.

**Process permission failures:** unrooted Termux cannot generally read another app's memory. Root may still be constrained by SELinux. A PID can exit or change while being analyzed. Maps show only mappings available to the requested identity. The toolkit reports these failures and does not alter security policy.

**ADB:** install extras with `bash install-termux.sh --extras`. Pair/connect Android wireless debugging yourself, then check `adb devices`. Commands with `--via adb` require exactly one selected device unless `ANDROID_SERIAL` is configured. ADB access is separate from root.

**Signing:** use a new output path for each build. If a signed APK cannot update an installed app, compare certificate fingerprints with `uat apk verify` on both APKs. All split APKs need the same signing identity. Renaming a package requires coherent manifest, code, resource, provider-authority, and native changes; this toolkit does not infer those changes.

**Missing native symbols:** stripped `.so` files may have only exported dynamic symbols. Use LLVM objdump for cross-architecture disassembly. Search presets find strings and markers; they cannot recover removed symbol names.

**Engine tools:** desktop PE executables and Windows game signatures do not directly support Android ELF/ARM64 apps. IL2CPP and Unreal versions vary. A module memory snapshot includes relocated/runtime data and is not a rebuilt native library.
