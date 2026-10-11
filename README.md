# Ultimate Android Toolkit

A standalone, Termux-first toolkit for APK inspection, editing, rebuilding, signing, and Android game research. Works without root for offline files, with optional root or ADB access for device operations. The Python core has no third-party dependencies.

This is a separate project inspired by [Ultimate Game Tool](https://github.com/esooLsIeicuJehT/ultimate_game_tool). It does not require or change that repository.

## Install in Termux

Use a current Termux release from F-Droid or the official Termux GitHub releases. Keep the repository, workspaces, and signing keys in Termux's private home directory.

From the source ZIP, copy it into Termux's private home directory:

```bash
pkg install -y unzip
unzip ultimate-android-toolkit-v0.1.0.zip
cd ultimate-android-toolkit
bash install-termux.sh --extras
uat doctor
uat menu
```

After the separate GitHub repository is published, a checkout is also available with `git clone https://github.com/esooLsIeicuJehT/ultimate-android-toolkit.git`.

The installer adds Python, OpenJDK, Apktool, JADX, apksigner, native aapt/aapt2/zipalign, binutils, ripgrep, and unzip. `--extras` adds ADB, LLVM, radare2, SSH, and Frida through Termux's root repository. `--frida` adds just the Frida extras. Installing that repository does not root the phone, and no server is started automatically. Do not run the installer as root.

For access to Downloads, run `termux-setup-storage` once. Copy the input APK into your working directory before editing it. On Linux, install the external tools separately, then use `python3 -m pip install .`.

## Features

| Area | Included |
| --- | --- |
| APK analysis | Manifest XML, permissions, components, SDK declarations, ABIs, engine hints, ZIP listing, content hashes, APK comparison |
| Automatic triage | One command extracts files, inspects DEX/native headers, searches engine/JNI/endpoint/logging markers, and saves a report |
| Editing | Apktool resource/smali decoding and rebuilding; individual asset replacement; deterministic batch patch recipes |
| Signing | RSA-3072 PKCS12 key creation, existing JKS/PKCS12 keys, certificate fingerprints, alignment, v1/v2/v3 signing and verification |
| Split APKs | Extract APKS/XAPK/APKM archives, export installed split sets, sign an entire set with the same key |
| Searching | Literal, regex, hex/wildcard, and preset searches across Java, smali, XML, assets, DEX, and `.so` files |
| Native analysis | ELF headers/sections/dependencies, symbol CSV export, disassembly, strings, hexdumps, byte-pattern scans |
| DEX/Unity | DEX class summaries and integrity checks, IL2CPP metadata identification, optional user-supplied Il2CppDumper DLL integration |
| Projects | Preserved original APK, original hash validation, decoded working directory, build history |
| Agent integration | Local read-only MCP server with workspace-restricted APK/search/DEX/ELF tools |
| Ghidra / IDA | Bundled exporter scripts; local desktop or explicit SSH provider coordination for pseudocode, assembly, strings and references |
| Frida | Client/server connection checks, process/app lists, module/export snapshots, custom scripts and native/Java tracing |
| Device access | Package listing/export, installer handoff, bounded logcat snapshots, process lists, maps, bounded module memory snapshots |

Every command has `--help`. Commands can save their result with `--report FILE`. Existing output paths are rejected. External tools may leave partial decoded/build files on failure; choose a fresh path when retrying.

## Analyze and search

```bash
uat apk analyze game.apk --out work/analysis --decode --java
uat apk inspect game.apk --hashes --report work/apk-report.json
uat apk manifest game.apk --report work/manifest.xml
uat apk list game.apk --glob 'lib/*/*.so'

uat search work/analysis/java --query 'PlayerController' --ignore-case
uat search work/analysis/decoded --regex 'set[A-Za-z]+\(' --glob '*.smali'
uat search work/analysis/extracted --preset endpoints --report work/endpoints.json
uat search work/analysis/extracted --preset jni --glob '*.so'
uat search work/analysis/extracted --preset unity
uat search work/analysis/extracted --preset unreal
uat search work/analysis/extracted --hex 'AA ?? CC DD' --glob '*.so'
```

Search results include relative paths, byte offsets, text line numbers where applicable, and context. Text/regex searches skip files larger than 128 MiB and report that skip; byte scanning and `binary strings` stream larger files. Presets identify useful navigation markers; they do not prove the purpose of a function. UTF-8 literal searches and printable ASCII strings are supported. Extract or decode compressed APK entries before searching their contents.

## Decode, modify, rebuild, and sign

```bash
uat apk decode app.apk --out work/decoded
# Edit work/decoded/AndroidManifest.xml, res/, assets/, or smali/.
uat apk build work/decoded --out work/rebuilt-unsigned.apk

uat key create --out ~/.keys/my-app.p12 --alias uat
uat apk sign work/rebuilt-unsigned.apk \
  --out work/rebuilt-signed.apk --keystore ~/.keys/my-app.p12
uat apk verify work/rebuilt-signed.apk
uat apk compare app.apk work/rebuilt-signed.apk
uat device install work/rebuilt-signed.apk
```

Passwords are requested privately. The key is saved with mode `0600`. Keep the keystore and password to sign future updates with the same identity. `apk sign` aligns first, requests v1/v2/v3 signatures, disables v4 sidecars, verifies signatures, and checks alignment before exporting. Modern zipalign uses 16 KiB native-library page alignment; a legacy zipalign falls back to 4 KiB and reports that limitation.

For an existing key, use `--alias YOUR_ALIAS`. If the key and keystore passwords differ, use `--key-password-env NAME` for the key password. For automation, set your own password environment variable and pass `--password-env NAME`; passwords are not included in command arguments or reports. `uat key info KEYSTORE` prints certificate details.

Changing bytes after signing invalidates the signatures. Re-signing with a different key generally cannot update the original installed app. Decompiled Java is approximate; edit smali/resources for Apktool rebuilds. A modified app may still reject changes through its own integrity checks.

## Automatic modifications

Create a JSON recipe with the edits you want. The toolkit can apply known edits automatically; it does not guess which game instructions should change.

```bash
uat patch plan examples/patch-recipe.json --root work/decoded
uat patch apply examples/patch-recipe.json \
  --root work/decoded --out work/decoded-patched
uat apk build work/decoded-patched --out work/patched-unsigned.apk
uat apk sign work/patched-unsigned.apk \
  --out work/patched-signed.apk --keystore ~/.keys/my-app.p12
```

Customize the example paths and expected values to match your own files. All rules must pass their preconditions before an output directory is copied. The original directory stays intact. The output includes hashes, text diffs, and `uat-patch-report.json`. See [patch recipes](docs/patch-recipes.md) for text, XML, byte replacement, offset patches, and optional hash constraints.

For a single native edit, file offsets and expected bytes are explicit:

```bash
uat binary scan libexample.so --pattern '74 65 73 74'
uat binary patch libexample.so --offset 0x1000 \
  --expected '74 65 73 74' --replace '64 65 6d 6f' --out libexample-patched.so
```

Byte patches preserve length and refuse mismatched input. They edit files, not a running process. Native instructions and file offsets depend on architecture and app version.

## Native libraries and engine research

```bash
uat apk extract game.apk --out work/native --glob 'lib/*/*.so'
uat binary info work/native/lib/arm64-v8a/libil2cpp.so
uat binary elf work/native/lib/arm64-v8a/libil2cpp.so --report work/elf.txt
uat binary symbols work/native/lib/arm64-v8a/libil2cpp.so --out work/symbols.csv
uat binary disassemble work/native/lib/arm64-v8a/libil2cpp.so --out work/disassembly.txt
uat binary strings work/native/lib/arm64-v8a/libil2cpp.so --contains il2cpp --limit 2000
uat binary dex work/analysis/extracted/classes.dex
```

With a compatible `dotnet` runtime and your own Il2CppDumper DLL:

```bash
uat engine il2cpp libil2cpp.so global-metadata.dat \
  --tool /path/to/Il2CppDumper.dll --out work/il2cpp
```

The toolkit does not install .NET or promise a universal IL2CPP/Unreal SDK dumper. Some .NET tools need a separate Linux/proot environment. Encrypted metadata, stripped symbols, ARM64 signatures, and engine-version-specific layouts need additional analysis. ELF symbol values and file offsets are different from live process addresses. Unreal presets and snapshots provide research inputs, not automatic reflection recovery.

## Rooted and non-rooted devices

```bash
uat doctor --root                         # explicitly request a root capability check
uat device packages                     # visible packages; may be limited by Android
uat device export org.example.app --out work/export --via root
uat device processes --root
uat device maps 1234 --root --report work/maps.json
uat device dump-module 1234 --module libexample.so --root --out work/module.bin
uat device logcat --pid 1234 --lines 200 --via root --report work/logcat.txt
```

Omit `--root`/`--via root` for access permitted to the Termux UID. Package and log operations also support `--via adb` when ADB is already connected. Non-root installation opens Android's installer; completion happens on the phone. Root approval is handled by your device's root manager. The toolkit does not change SELinux or bypass process-access restrictions.

Module snapshots preserve virtual layout relative to the recorded base, with holes zero-filled and a JSON map alongside the binary. They are not reconstructed on-disk ELF files. Captures are bounded to 512 MiB by default and do not pause the process. Read failures abort unless `--allow-gaps` is explicitly selected.

For splits, keep the complete compatible set:

```bash
uat apk sign-set work/export --out work/signed-set --keystore ~/.keys/my-app.p12
adb install-multiple work/signed-set/*.apk
```

Archives are extracted, not merged into a universal APK. Offline APK analysis and signing do not require root. Use the toolkit on apps and files you have permission to analyze or modify.

## Projects and updates

```bash
uat project create app.apk --out work/my-app
uat project decode work/my-app
# Edit work/my-app/decoded.
uat project rebuild work/my-app --out work/build-1.apk --keystore ~/.keys/my-app.p12
uat project info work/my-app
```

Update by running `git pull` in this repository, then `python -m pip install .`. Uploaded source excludes APKs, extracted apps, memory dumps, and keystores. Tests and validation details are in [testing](docs/testing.md). Troubleshooting is in [Termux notes](docs/termux.md).

MIT license for this toolkit. External tools retain their own licenses.

For a local AI-agent workflow similar to the bridge described in the REA article, see [agent integration](docs/agents.md). Run `uat mcp --root DIRECTORY` and register it in your client. Client settings are not changed automatically.

For integrated JADX, Frida, Ghidra and IDA workflows, see [provider setup](docs/providers.md). JADX and Termux-packaged Frida run on the phone; Ghidra/IDA need separate compatible installations and can be coordinated over SSH.
