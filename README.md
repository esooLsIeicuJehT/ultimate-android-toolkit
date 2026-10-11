# Ultimate Android Toolkit

Inspect, search, edit, rebuild, and sign Android apps from Termux, with extra tools for understanding the native libraries inside them.

If you have ever unpacked an APK and ended up with thousands of smali files, unfamiliar `.so` libraries, and no clear place to start, this project is meant to make that process easier. It brings the everyday steps into one command, `uat`, while keeping the individual tools available when you need them.

You can start with a simple APK report, move into Java or smali searches, save a set of repeatable changes, and build a signed APK for testing. For deeper work, there are Frida workflows and adapters for separately installed Ghidra and IDA.

This is a standalone project inspired by [Ultimate Game Tool](https://github.com/esooLsIeicuJehT/ultimate_game_tool). It has its own source, installer, documentation, and releases. You do not need the original repository to use it.

**Current release: 0.1.0.** This version is a terminal application for Termux and compatible desktop environments. There is no standalone Android GUI APK in this release. The Python core requires Python 3.10 or newer and has no third-party Python dependencies; commands such as decoding and signing use external tools.

## Start here

For the full Termux setup:

```bash
pkg install -y git
cd "$HOME"
git clone https://github.com/esooLsIeicuJehT/ultimate-android-toolkit.git
cd ultimate-android-toolkit
bash install-termux.sh --extras
uat doctor
uat menu
```

Run these commands as your normal Termux user. The installer does not need root. The `--extras` option installs the additional packages used for ADB, native disassembly, SSH, and Frida. It does not grant root access or start a Frida server.

Already comfortable with the terminal? Try `uat --help` and jump to [your first APK analysis](#your-first-apk-analysis). Prefer prompts? `uat menu` covers the common inspection, decoding, building, signing, searching, and patching operations.

## What's in this toolkit?

| Task | What you can do |
| --- | --- |
| Understand an APK | Read its manifest, package information, permissions, components, SDK declarations, supported ABIs, and possible engine markers. |
| Get an initial overview | Extract an APK, inspect its DEX and native files, run preset searches, and save everything in an analysis folder. |
| Read app code | Decode smali and resources with Apktool, or generate approximate Java with JADX. |
| Find relevant files | Search recursively by text, regular expression, byte pattern, or presets for URLs, JNI, Unity, Unreal, and logging. |
| Make repeatable edits | Preview and apply JSON recipes for exact text replacements, XML attributes, byte replacements, and patches at known file offsets. |
| Rebuild apps | Build an Apktool directory using the native Android resource compiler available in Termux. |
| Sign your builds | Create a reusable signing key, align an APK, sign it, verify it, and inspect certificate fingerprints. |
| Handle split APKs | Extract APKS/XAPK/APKM archives, export installed APK sets, and sign every APK in a set with one key. |
| Investigate `.so` files | Inspect ELF information, export symbols, disassemble code, read strings, view hex, and search byte patterns. |
| Inspect DEX files | Get class summaries and check DEX SHA-1 and Adler-32 integrity values. |
| Research game engines | Find engine markers and IL2CPP metadata; optionally run your own compatible Il2CppDumper DLL. |
| Keep organized projects | Preserve an original APK, validate its hash, maintain a decoded directory, and record build history. |
| Inspect a running process | Use Frida to list processes, inspect modules and exports, run your own scripts, or trace selected functions. |
| Use Ghidra or IDA | Run bundled exporters through a compatible local installation or coordinate a desktop installation over SSH. |
| Work with your device | List or export packages, request APK installation, capture logs, and read accessible process maps or bounded memory snapshots. |
| Connect an AI client | Run a local MCP server that exposes read-only analysis tools inside a chosen workspace. |

These features help you find and apply changes you understand. The toolkit does not automatically know which function controls a particular game feature, or whether an arbitrary native patch will work. Automatic edits need a recipe with specific expected content.

## Installation in more detail

### Choose a current Termux build

Use a current release from [F-Droid](https://f-droid.org/packages/com.termux/) or the [official Termux GitHub releases](https://github.com/termux/termux-app/releases). Keep the toolkit and working files in Termux's private home directory, usually the directory you reach with `cd "$HOME"`.

Android shared storage is useful for moving files in and out, but it can restrict executable files and Unix permissions. A practical arrangement is to keep your projects in `~/ultimate-android-toolkit/work` and copy finished APKs to Downloads when needed.

### Choose an installation size

| Command | Packages added |
| --- | --- |
| `bash install-termux.sh` | Python, OpenJDK 21, Apktool, JADX, apksigner, aapt, aapt2, binutils, ripgrep, unzip, and Termux tools. |
| `bash install-termux.sh --frida` | The base packages plus Termux's root package repository and Frida. |
| `bash install-termux.sh --extras` | The base and Frida packages plus Android tools/ADB, LLVM, radare2, and OpenSSH. |

The installer updates package indexes and installs the Python package from this checkout. It does not install Ghidra, IDA, .NET, or an Il2CppDumper distribution. Radare2 and ripgrep are available as extra standalone tools; the current `uat` commands do not wrap every feature of those programs.

Installing `root-repo` simply makes extra Termux packages available. It does not root your device.

### Allow access to Downloads

Run this once and accept Android's storage prompt:

```bash
termux-setup-storage
mkdir -p work
cp ~/storage/downloads/my-app.apk work/input.apk
```

Replace `my-app.apk` with your filename. For a filename with spaces, use quotes: `cp "$HOME/storage/downloads/My App.apk" work/input.apk`.

### Install from a release ZIP

Downloads are available on the [release page](https://github.com/esooLsIeicuJehT/ultimate-android-toolkit/releases). Download the toolkit source ZIP, then extract it into your private home directory:

```bash
pkg install -y unzip
cd "$HOME"
unzip ~/storage/downloads/ultimate-android-toolkit-v0.1.0.zip
cd ultimate-android-toolkit
bash install-termux.sh --extras
```

The Python wheel is useful if your dependencies are already installed. The source ZIP is the more convenient option for a fresh Termux setup because it includes the installer, examples, and documentation. Neither download bundles the external applications themselves.

### Use it on Linux

The Python CLI also works on compatible Linux systems. Install the external tools needed for your chosen commands separately, then install the toolkit in a virtual environment:

```bash
git clone https://github.com/esooLsIeicuJehT/ultimate-android-toolkit.git
cd ultimate-android-toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
uat doctor
```

For local Ghidra analysis, configure a full JDK supported by your Ghidra version, including `javac`. The standard Ghidra and IDA desktop distributions need a compatible desktop environment; installing this Python package does not make their binaries run natively on Android.

## Check your setup

```bash
uat --version
uat doctor
uat apk --help
uat search --help
```

`doctor` reports the current platform and which executables it can find. A missing optional tool only matters when you use a command that needs it. For example, missing `dotnet` does not prevent APK inspection, searching, or signing.

Use `uat doctor --root` when you specifically want to test root access. That command calls `su` and may open your device's root-manager prompt. Finding a `su` executable alone does not establish that root access has been granted.

Most analysis commands print JSON. Many accept `--report FILE` to save their results; manifest, verification, hex, and ELF commands can produce text. Use the command's `--help` for its exact options. Existing output paths are rejected, so use a fresh directory or filename for each attempt.

## Your first APK analysis

Start with a quick report if you only want to know what's inside:

```bash
uat apk inspect work/input.apk --hashes --report work/apk-report.json
uat apk manifest work/input.apk --report work/manifest.xml
uat apk list work/input.apk --glob 'lib/*/*.so'
```

For a fuller starting point:

```bash
uat apk analyze work/input.apk --out work/analysis --decode --java
```

This copies the input, extracts its entries, gathers APK/DEX/native information, decodes resources and smali, generates approximate Java, and runs the built-in search presets over the extracted files. Decoding and Java output are optional: omit `--decode` or `--java` to skip those steps.

After a successful run with both options, the main files look like this:

```text
work/analysis/
├── input.apk       Copy of the input APK
├── analysis.json   Combined report and preset search results
├── extracted/      Uncompressed APK entries, including DEX and native files
├── decoded/        Apktool resources, manifest, assets, and smali
└── java/           JADX output for reading and searching
```

The report includes hashes, DEX summaries, native library information, engine hints, and search results. Engine hints are based on recognizable files and strings, so treat them as useful starting points rather than a complete description of the app.

Large applications can take time and substantial storage. If a dependency fails partway through, it may leave partial output. Read the error, fix the dependency or input issue, and retry with a new output path.

## Finding the code or data you want

Start with something recognizable: a class name, a screen label, an asset filename, a log message, or a native export. Search Java when you want readable context, then look for the corresponding smali if you intend to rebuild with Apktool.

```bash
# Find a class or identifier in the Java output.
uat search work/analysis/java --query 'PlayerController' --ignore-case

# Find references in decoded smali.
uat search work/analysis/decoded --query 'PlayerController' --glob '*.smali'

# Search XML resources for visible text.
uat search work/analysis/decoded --query 'Settings' --glob '*.xml'

# Use a regular expression when names vary.
uat search work/analysis/java --regex 'set[A-Za-z]+\(' --glob '*.java'

# Save URL markers for later review.
uat search work/analysis/extracted --preset endpoints --report work/endpoints.json

# Look for native/engine markers or a wildcard byte pattern.
uat search work/analysis/extracted --preset jni --glob '*.so'
uat search work/analysis/extracted --preset unity
uat search work/analysis/extracted --preset unreal
uat search work/analysis/extracted --preset logging
uat search work/analysis/extracted --hex 'AA ?? CC DD' --glob '*.so'
```

| Preset | Markers it looks for |
| --- | --- |
| `endpoints` | Recognizable HTTP/HTTPS URL strings. |
| `jni` | Names such as `Java_...`, `JNI_OnLoad`, and `RegisterNatives`. |
| `unity` | IL2CPP exports, `global-metadata.dat`, and `UnityEngine` names. |
| `unreal` | Strings such as `GWorld`, `GUObjectArray`, `FNamePool`, and `/Script/...`. |
| `logging` | Android and Java logging markers. |

Results include relative file paths, byte offsets, readable context, and line numbers when the file appears to be text. A reported byte offset belongs to that file; it is not automatically an address in a running process.

Searches stop at the requested result limit; the default is 500. Narrow `--glob` or raise `--limit` when appropriate. Literal searches use UTF-8 bytes, and printable string extraction uses ASCII. Text and regex searches skip files over 128 MiB and report the skip. For large native files, use streaming `uat binary scan` or `uat binary strings`.

Extract or decode an APK before searching the contents of its compressed entries. A string hit gives you a location to investigate, not proof of what surrounding code does.

## Decode, edit, rebuild, and sign

You can run each step separately when you want close control over the process:

```bash
uat apk decode work/input.apk --out work/decoded
uat apk decompile work/input.apk --out work/java

# Make your edits inside work/decoded.
uat apk build work/decoded --out work/build-1-unsigned.apk

uat key create --out ~/.keys/my-app.p12 --alias uat
uat apk sign work/build-1-unsigned.apk \
  --out work/build-1-signed.apk --keystore ~/.keys/my-app.p12

uat apk verify work/build-1-signed.apk
uat apk compare work/input.apk work/build-1-signed.apk
uat device install work/build-1-signed.apk
```

Apktool decodes editable resources, assets, manifest XML, and smali. JADX gives you approximate Java for understanding the app. Editing the Java output alone does not change the APK produced by `uat apk build`; that command builds the Apktool directory.

If a device-specific resource APK is needed, install the matching framework before decoding again:

```bash
uat apk framework framework-res.apk
```

The framework cache lives under `$XDG_DATA_HOME/uat/frameworks`, or `~/.local/share/uat/frameworks` when that environment variable is unset.

For a single asset replacement that does not need resource or smali rebuilding:

```bash
uat apk replace work/input.apk --entry assets/config.json \
  --file my-config.json --out work/asset-edit-unsigned.apk
uat apk sign work/asset-edit-unsigned.apk \
  --out work/asset-edit-signed.apk --keystore ~/.keys/my-app.p12
```

The replacement command produces an unsigned copy and strips the old signatures. It does not compile resources or validate the meaning of the replacement asset.

### Signing keys and updates

Create a key once and reuse it for later builds. A generated key is RSA-3072 in a PKCS12 keystore, saved with private `0600` permissions. Passwords are requested privately. Keep the keystore and its password backed up separately from your APK projects.

```bash
uat key info ~/.keys/my-app.p12
uat apk verify work/build-1-signed.apk --report work/signature.txt
```

`apk sign` aligns the APK, requests v1/v2/v3 signing, disables v4 sidecars, verifies the result, and checks alignment before exporting the finished file. Modern zipalign supports 16 KiB native-library page alignment. An older zipalign falls back to 4 KiB and reports that limitation.

For an existing JKS or PKCS12 keystore, specify its alias with `--alias YOUR_ALIAS`. If the key password differs from the keystore password, use `--key-password-env NAME`. Automation can supply a password through a named environment variable using `--password-env NAME`; password values are not passed as command-line arguments or included in toolkit reports.

A different signing certificate generally cannot update the original installed app. Use the same signing identity for your successive builds. Removing an existing app to install a differently signed build can remove its local data, so decide how you will test before replacing your everyday installation. Changing an APK after signing invalidates its signatures, and an app may also have its own integrity checks.

## Automatic changes with patch recipes

Recipes are useful once you know what needs changing. Instead of repeating the same manual edits, describe them in a JSON file, preview the result, and apply them to a new copy of the directory.

Here is a small example for an asset containing exactly one `"theme": "light"` value:

```json
{
  "version": 1,
  "changes": [
    {
      "path": "assets/config.json",
      "kind": "text_replace",
      "find": "\"theme\": \"light\"",
      "replace": "\"theme\": \"dark\"",
      "expected_matches": 1
    }
  ]
}
```

Save that as `theme-recipe.json`, adapt the path and values to your own app, and run:

```bash
uat patch plan theme-recipe.json --root work/decoded
uat patch apply theme-recipe.json --root work/decoded --out work/decoded-patched
uat apk build work/decoded-patched --out work/patched-unsigned.apk
uat apk sign work/patched-unsigned.apk \
  --out work/patched-signed.apk --keystore ~/.keys/my-app.p12
```

`plan` validates the rules and shows the proposed changes without writing patched files. `apply` checks every rule before copying the input and applying edits. The original directory remains intact, and the new directory includes `uat-patch-report.json` with hashes and change details.

| Recipe kind | Use it for |
| --- | --- |
| `text_replace` | An exact UTF-8 text replacement. |
| `xml_set_attribute` | A known attribute in decoded XML, with an expected previous value. |
| `bytes_replace` | Exact byte replacements throughout a selected file. |
| `binary_patch` | An equal-length byte edit at a specific file offset. |

Every rule needs an expected match count. Optional SHA-256 checks help restrict a recipe to a known input version. If the expected text, bytes, attribute, match count, or hash does not match, the operation stops before producing the patched directory. Binary replacements must preserve length.

Paths are relative to the input directory, symlinks are rejected, and the output must be outside the input tree. Recipe edits are limited to 128 MiB per file and 256 MiB across changed files. Use the streaming single-file patch command for larger binaries.

See [the full recipe guide](docs/patch-recipes.md), [the text/XML example](examples/patch-recipe.json), and [the native example](examples/native-patch-recipe.json). The examples contain placeholder paths and expected values; adapt them before use. Recipes do not rebuild or sign on their own.

## Working with native `.so` libraries

Native libraries contain compiled machine code. Java decompilation will not recover their implementations, so start with the architecture, exported symbols, strings, and disassembly.

```bash
uat apk extract work/input.apk --out work/native --glob 'lib/*/*.so'
uat binary info work/native/lib/arm64-v8a/libexample.so
uat binary elf work/native/lib/arm64-v8a/libexample.so --report work/elf.txt
uat binary symbols work/native/lib/arm64-v8a/libexample.so --out work/symbols.csv
uat binary disassemble work/native/lib/arm64-v8a/libexample.so --out work/disassembly.txt
uat binary strings work/native/lib/arm64-v8a/libexample.so --contains example --limit 2000
uat binary hex work/native/lib/arm64-v8a/libexample.so --offset 0x1000 --length 128
uat binary scan work/native/lib/arm64-v8a/libexample.so --pattern '74 65 73 74'
```

Replace the library name and ABI with entries that actually exist in your APK. `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64` identify different architectures. Disassembly needs an architecture-compatible objdump; the extra installer includes LLVM for broader support. Stripped libraries may expose very few symbols.

For an edit you have already located and understood:

```bash
uat binary patch libexample.so --offset 0x1000 \
  --expected '74 65 73 74' --replace '64 65 6d 6f' \
  --out libexample-patched.so
```

This example changes the four bytes spelling `test` to the four bytes spelling `demo`. The offset is a placeholder, not a reusable patch for an arbitrary library. The command writes a new file only when the expected bytes match and the replacement length is identical. Instruction patches also need correct architecture, instruction boundaries, and control flow; a matching byte pattern alone does not establish those conditions.

DEX files have their own inspection command:

```bash
uat binary dex work/analysis/extracted/classes.dex --limit 1000
```

### Unity, IL2CPP, and Unreal research

Engine detection and search presets help locate likely inputs. Unity IL2CPP analysis commonly involves `libil2cpp.so` and `global-metadata.dat`. With a compatible .NET runtime and your own Il2CppDumper DLL, you can invoke it through:

```bash
uat engine il2cpp libil2cpp.so global-metadata.dat \
  --tool /path/to/Il2CppDumper.dll --out work/il2cpp
```

The toolkit does not install .NET or the dumper. Some distributions require a separate Linux/proot environment. Compatibility depends on the engine version, metadata format, and the dumper you supply. Encrypted metadata and stripped or modified binaries may need further analysis.

Unreal presets find recognizable markers for investigation; this release does not recover a complete Unreal SDK or reflection layout automatically. File offsets, ELF symbol values, provider addresses, and live process addresses are different quantities, especially after relocation.

## JADX, Ghidra, IDA, and Frida

These tools are connected in different ways because they have different platform requirements:

| Tool | How it connects | Runs directly on the phone? |
| --- | --- | --- |
| JADX | The Termux package is called by `apk decompile` and `apk analyze --java`. | Yes, through Java. |
| Frida | Termux's package provides bindings, CLI tools, and server; `uat frida` coordinates inspection and instrumentation. | Yes, subject to Android process access. |
| Ghidra | Bundled Java exporter with a separately installed compatible headless analyzer. | Use a compatible desktop installation, usually over SSH. |
| IDA | Bundled Python exporter with a separately installed licensed headless analyzer. | Use a compatible desktop installation, usually over SSH. |

### Native decompilation with Ghidra or IDA

Set up a desktop provider and SSH access first. Ghidra needs its supported full JDK. IDA needs its own license, and pseudocode requires a compatible decompiler such as Hex-Rays.

Preview a provider operation:

```bash
uat native plan libexample.so --provider ghidra --out work/ghidra-plan \
  --remote me@desktop --tool /opt/ghidra/support/analyzeHeadless
```

Run analysis and retrieve the report:

```bash
uat native analyze libexample.so --provider ghidra --out work/ghidra \
  --remote me@desktop --tool /opt/ghidra/support/analyzeHeadless --limit 500

uat native analyze libexample.so --provider ida --out work/ida \
  --remote me@desktop --tool /opt/ida/idat64 --limit 500
```

Replace the SSH destination and provider paths with your own. SSH uses your existing credentials and host-key checks. The adapter uploads the selected binary and exporter into a new `/tmp/uat-...` directory, runs the provider, and retrieves `native.json`. Remote artifacts are kept for review. `--remote-work /absolute/path` selects another remote working location; use an SSH host alias for a nonstandard port.

On a compatible desktop, omit `--remote` and point `--tool` at the local installation. Reports contain function names and addresses, bounded assembly, references, strings, and pseudocode where available. Function export defaults to 500 and is limited to 5,000; each assembly preview is limited to 200 instructions. IDA reports whether a decompiler was available.

Search the exported report with `uat search`, or use the MCP `native_functions` tool to filter functions by name or pseudocode. The [provider guide](docs/providers.md) covers setup and local examples.

### Frida on a rooted phone

Install Frida with `--extras` or `--frida`. In one Termux session, explicitly start the foreground server:

```bash
uat frida server --root
```

In another session:

```bash
uat frida status --host 127.0.0.1:27042
uat frida ps --host 127.0.0.1:27042 --apps
uat frida inspect 1234 --host 127.0.0.1:27042 \
  --module libexample.so --exports --report work/live-exports.json
```

Replace `1234` with the target process ID. Built-in inspection enumerates modules and exports without installing hooks or writing process memory. The server helper binds to loopback and stays in the foreground. Keep client and server versions matched.

You can also load your own script or trace selected functions:

```bash
uat frida run 1234 --host 127.0.0.1:27042 --script my-script.js
uat frida trace 1234 --host 127.0.0.1:27042 \
  --include 'libexample.so!example_*' --out work/trace
uat frida trace 1234 --host 127.0.0.1:27042 \
  --java 'org.example.app.MainActivity!*' --out work/java-trace
```

These operations execute the instrumentation you requested and remain interactive. `--spawn` can launch an appropriate target; an inspected spawned app is resumed and left running after the session detaches. Non-root instrumentation needs permitted/debuggable access or an app-integrated Frida Gadget. Installing the client alone does not permit attachment to every app.

## What works with and without root?

| Operation | Normal Termux user | Root or connected ADB |
| --- | --- | --- |
| Inspect, extract, decode, search, patch, rebuild, sign local files | Available when the required external tools are installed. | Root is unnecessary. |
| List installed packages or export APKs | Depends on Android visibility and file permissions. | `--via root` or `--via adb` may provide the required access. |
| Install a single APK | Opens Android's installer; finish on the phone. | Root/ADB install paths are available. |
| Read logs | Limited by Android's access rules. | Root/ADB can provide broader access. |
| Read process maps or a module snapshot | Only processes/mappings the current UID can access. | Root may allow more access; SELinux still applies. |
| Inspect apps with Frida | Requires permitted access or a suitable Gadget setup. | A running compatible Frida server commonly uses root. |

Examples for device access:

```bash
uat device packages
uat device packages --via adb
uat device export org.example.app --out work/export --via root
uat device install work/build-1-signed.apk --via adb
uat device logcat --pid 1234 --lines 200 --via root --report work/logcat.txt
uat device processes --root
uat device maps 1234 --root --report work/maps.json
uat device dump-module 1234 --module libexample.so --root --out work/module.bin
```

Replace the package name and PID with your own targets. Package, export, installation, and log commands use `--via local|root|adb`; process map and snapshot commands use an explicit `--root` flag. Without a root option, the command uses the current Termux user's access.

ADB must already be paired/connected. Check `adb devices` before using `--via adb`; if more than one device is present, set `ANDROID_SERIAL` for the device you want. Your root manager handles requests from `su`. The toolkit does not alter SELinux or grant itself extra process permissions.

Module snapshots preserve mapped virtual layout relative to the recorded base, with a JSON mapping report alongside the binary. They are not reconstructed on-disk ELF files. Capture is bounded to 512 MiB by default and does not pause the process. Read failures stop the capture unless you explicitly choose `--allow-gaps`.

## Split APKs and app bundles

Many installed apps consist of a base APK plus architecture, language, or resource splits. Keep the complete compatible set together.

```bash
uat apk extract downloaded.apks --out work/bundle
uat device export org.example.app --out work/installed-set --via adb
uat apk sign-set work/installed-set --out work/signed-set --keystore ~/.keys/my-app.p12
adb install-multiple work/signed-set/*.apk
```

Archive extraction also accepts XAPK and APKM ZIP containers. It extracts their contents; it does not merge splits into a universal APK, automatically choose the right set for a device, or install bundled expansion assets. `sign-set` signs the APK files in the selected directory with the same key. Preserve package/version relationships and include the splits your app needs.

## Keep originals and build history in a project

For work that spans several sessions, use a toolkit project:

```bash
uat project create work/input.apk --out work/my-project
uat project decode work/my-project

# Edit work/my-project/decoded.
uat project rebuild work/my-project --out work/project-build-1.apk \
  --keystore ~/.keys/my-app.p12
uat project info work/my-project
```

The project keeps `original.apk`, its recorded SHA-256, a report, the decoded directory, and history in `project.json`. Loading the project validates the original hash. `project rebuild` produces an unsigned APK when no keystore is supplied, or rebuilds, signs, and verifies when one is supplied.

For recipes, you can patch a decoded directory and use the separate build/sign commands, or apply a recipe to a copied whole project and rebuild that copy. Use a new output filename for each build so previous results remain available for comparison.

## Connect a local AI client through MCP

The [Reverse Engineer Anything article](https://cybersecuritynews.com/reverse-engineer-anything-tool/amp/) describes connecting agents to analysis tools. This project includes its own small MCP stdio server for a similar workflow. It is an independent implementation, not a bundled copy of REA.

```bash
uat mcp --root /absolute/path/to/workspace
```

Here, `--root` means the allowed workspace directory; it does not request Android root access. The server reads messages from stdin and writes responses to stdout, with no network listener. Tools cover APK reports and manifest XML, file searches, binary identification, strings, byte scans, DEX/ELF reports, and filtering existing native function reports.

Configure your client to launch the server using the absolute executable path from `command -v uat`. An example for clients that use `mcpServers`:

```json
{
  "mcpServers": {
    "android-toolkit": {
      "command": "/absolute/path/to/uat",
      "args": ["mcp", "--root", "/absolute/path/to/workspace"]
    }
  }
}
```

MCP tools are read-only and restricted to that workspace. Editing, decompilation, provider execution, root operations, and signing remain explicit CLI operations. Client configuration is manual; the installer does not change it.

A useful workflow is to analyze an APK first, point the client at that analysis folder, ask it to find relevant files with supporting paths and offsets, and have it propose a recipe. Preview the recipe with `uat patch plan` before applying it. An agent still needs evidence about the actual app; a confident explanation is not a substitute for checking the code and testing the build.

See [agent integration](docs/agents.md) for client configuration, including a Codex example.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| A package cannot be downloaded | Use a current official Termux build and select a working mirror with `termux-change-repo`. Retry the installer after the package issue is resolved. |
| `pkg update` reports `EXPKEYSIG` for TermuxBlack | That third-party repository has an expired signing key. Follow [the repository recovery steps](docs/termux.md#expired-termuxblack-repository) before retrying. |
| `uat` or a dependency is missing | Run `uat doctor` if the CLI is installed. Reinstall the project with `python -m pip install .` from the repository. In a desktop virtual environment, activate it first. |
| `install-termux.sh` cannot be found | Run `cd "$HOME/ultimate-android-toolkit"`, then `bash install-termux.sh --extras`. The installer is in the repository root, not in `scripts/`. |
| Apktool tries to use an incompatible resource compiler | The wrapper selects Termux's native aapt2. Confirm `aapt2` is installed and visible to `uat doctor`. |
| Apktool reports missing framework resources | Install the matching framework/resource APK with `uat apk framework ...`, then decode to a fresh directory. |
| JADX runs out of memory | Try `uat apk decompile app.apk --out work/java-small --threads 1`. A suitable `JAVA_TOOL_OPTIONS='-Xmx1g'` can bound the JVM heap if the phone has enough available memory. |
| An output path already exists | Choose a new path. Review any partial files left by external tools before retrying. |
| A recipe fails its match count or expected value | Check the actual file and app version. Update the recipe only after confirming why the input differs. |
| An APK cannot update an installed app | Compare signing certificates with `uat apk verify`, and check the package name, version rules, and split set. |
| Native symbols are missing | The library may be stripped. Try strings, architecture-compatible disassembly, or a native provider. Removed names cannot be recovered by a text search. |
| Root/process access is denied | Check root-manager approval and Android/SELinux restrictions. A process can also exit or change during inspection. |
| Frida cannot connect or attach | Check that the server is running, the connection target and versions match, and Android permits access to that process. |
| Ghidra fails to compile its exporter | Use a full compatible JDK with `javac`, and set `JAVA_HOME` to it if needed. |
| IDA exports assembly but no pseudocode | Confirm the installation has a licensed decompiler for the binary's architecture. |
| SSH provider analysis fails | First test your SSH host alias and provider executable outside the toolkit. Review the retained remote work directory and logs. |

Extraction is bounded to 2 GiB total and 512 MiB per entry. Larger archives need a specialized workflow. More platform notes are in [Termux troubleshooting](docs/termux.md).

## Validation and current limits

All **35 tests passed on Linux x86_64** with the optional integration checks enabled during initial development. Actual-tool checks used Apktool 3.0.3, JADX 1.5.6, JDK 21, Android build-tools 35, Frida 17.2.14, and Ghidra 12.1.4.

That validation included decoding and rebuilding a compiled APK, applying an XML recipe, creating a key, signing and verifying builds, rejecting a wrong signing password, signing a set with one certificate, checking rebuilt DEX integrity, generating Java, inspecting a test-owned live process with Frida, and recovering pseudocode from a freshly compiled native test library with Ghidra.

It also checked extraction boundaries, searches across chunk boundaries, patch preconditions, source-copy isolation, project hashes, MCP workspace restrictions, provider invocation construction, and inclusion of provider scripts in the Python wheel.

The following still need testing in their target environments: installation on an Android phone, native Termux ARM64 package behavior, Android installer interaction, root/SELinux access, ADB and SSH connectivity, and licensed IDA execution. IDA currently has adapter tests rather than a test against a licensed installation. Linux test results do not establish that every feature works on every Android device.

Run the standard suite from a checkout with:

```bash
python -m unittest discover -s tests -v
```

Optional integrations are enabled separately. The repository's GitHub Actions workflow is configured for Python 3.10, 3.12, and 3.14; those CI checks do not run Android phone tests. See [testing instructions](docs/testing.md) and [the validation record](VALIDATION.md) for details.

## Updating and contributing

For a Git checkout:

```bash
git pull --ff-only
python -m pip install .
uat doctor
```

If a release needs additional Termux dependencies, rerun the relevant installer option. For a ZIP installation, extract a newer release into a separate directory and install from there; keep your workspaces and signing keys available independently of the source checkout.

Bug reports are most useful when they include your Android/Termux version, CPU architecture, toolkit version, the failing command, and the relevant error output. Remove passwords and private material from reports. Describe the APK structure or provide a small reproducible fixture when you can.

The implementation is organized under `uat/`: CLI/menu, APK and binary analysis, searching, patch recipes, signing, device access, projects, Frida, native provider adapters, and MCP. Provider scripts live in `uat/providers/`, examples in `examples/`, and supporting documentation in `docs/`.

The source repository excludes APKs, decoded applications, native dumps, signing keystores, and local work folders. Use the toolkit on apps and files you have permission to analyze or modify.

## License and external tools

The toolkit's own code is available under the [MIT license](LICENSE). External tools keep their respective licenses, platform requirements, and distribution terms. IDA binaries and licenses are not included. Ghidra and Frida integrations do not remove their dependency or access requirements.

Useful links: [Apktool](https://apktool.org/), [JADX](https://github.com/skylot/jadx), [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [IDA](https://hex-rays.com/ida-pro), and [Frida](https://frida.re/).
