# JADX, Ghidra, IDA and Frida integrations

These are integrated workflows with separate provider dependencies. The repository ships its own adapters, Ghidra/IDA exporter scripts, and a Frida module snapshot script. It does not redistribute proprietary IDA binaries or desktop binaries that cannot run natively in Termux.

## JADX on the phone

The standard installer adds Termux's JADX package. It runs directly through:

```bash
uat apk decompile app.apk --out work/java
uat search work/java --query Player --ignore-case
```

## Frida on the phone

Termux's `frida` package includes Android-native Python bindings, CLI tools, and server. Install with extras, or:

```bash
bash install-termux.sh --frida
# Equivalent provider installation:
pkg install -y root-repo
pkg install -y frida
```

Installing `root-repo` does not root the device. The installer does not start a server. On a rooted phone, run it explicitly in one Termux session:

```bash
uat frida server --root
```

Use a second session for analysis:

```bash
uat frida status --host 127.0.0.1:27042
uat frida ps --host 127.0.0.1:27042 --apps
uat frida inspect 1234 --host 127.0.0.1:27042 \
  --module libexample.so --exports --report work/live-exports.json
uat frida inspect org.example.app --spawn --wait 2 \
  --host 127.0.0.1:27042 --report work/modules.json
```

The built-in inspection script enumerates modules/exports without hooks or writes. Addresses and module-relative offsets are included. An app spawned with `--spawn` is resumed and left running after inspection; inspection detaches its session. Local Frida access is the default when neither `--host` nor `--usb` is passed. Non-root Android instrumentation needs permitted/debuggable access or an app-integrated Frida Gadget; arbitrary app attachment is not enabled by the client alone.

To load a script you wrote, or trace specific functions:

```bash
uat frida run 1234 --host 127.0.0.1:27042 --script my-script.js
uat frida trace 1234 --host 127.0.0.1:27042 \
  --include 'libexample.so!example_*' --out work/trace
uat frida trace 1234 --host 127.0.0.1:27042 \
  --java 'org.example.app.MainActivity!*' --out work/java-trace
```

`run` and `trace` execute instrumentation you explicitly requested and remain interactive. Keep Frida client/server versions matched. The server helper stays in the foreground and binds loopback only; use the device's service management if you want a persistent service.

## Ghidra and IDA providers

Ghidra's standard distribution targets desktop platforms and includes native components. It needs a full compatible JDK, including `javac`; a Java runtime alone is insufficient. Set `JAVA_HOME` to that JDK if its launcher cannot discover it. IDA also needs a compatible installation and its own license; pseudocode additionally depends on a matching decompiler. The dependable Termux path is to coordinate a separately installed desktop provider over SSH. The same adapters run locally on a compatible desktop.

Preview the exact provider invocation without running it:

```bash
uat native plan libexample.so --provider ghidra --out work/native \
  --remote me@desktop --tool /opt/ghidra/support/analyzeHeadless
```

Run Ghidra remotely:

```bash
uat native analyze libexample.so --provider ghidra --out work/ghidra \
  --remote me@desktop --tool /opt/ghidra/support/analyzeHeadless --limit 500
```

Run licensed IDA remotely:

```bash
uat native analyze libexample.so --provider ida --out work/ida \
  --remote me@desktop --tool /opt/ida/idat64 --limit 500
```

Set up SSH yourself first. The adapter uses your existing SSH credentials and host-key checking. It uploads the selected input and one exporter script into a new `/tmp/uat-...` directory, runs analysis, and retrieves `native.json`. Remote logs/results are retained in that directory for review. `--remote-work /absolute/path` changes the work location. Use an SSH host alias for nonstandard ports.

Local desktop examples:

```bash
uat native analyze libexample.so --provider ghidra \
  --tool /opt/ghidra --out work/ghidra
uat native analyze libexample.so --provider ida \
  --tool /opt/ida/idat64 --out work/ida
```

`GHIDRA_INSTALL_DIR` is also recognized. Ghidra exports function names, addresses, pseudocode where available, bounded assembly, caller references, strings, language and image base. IDA exports corresponding evidence and reports whether its decompiler was available. Function exports default to 500 and are bounded to 5,000; individual assembly previews are bounded to 200 instructions.

Results can be searched like any other text, and the MCP `native_functions` tool can filter exported functions by name or pseudocode. This connects agent reasoning to actual provider evidence. Provider addresses refer to the imported image layout, not automatically to the live process's relocated addresses.
