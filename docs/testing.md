# Testing and validation

Core tests use synthetic APK/ZIP fixtures and the Python standard library:

```bash
python -m unittest discover -s tests -v
```

They check ZIP path/symlink rejection, extraction and replacement, manifest summaries, patch preconditions and copy isolation, recipe traversal/hash/length guards, recursive text/native searching, chunk-boundary byte/string scanning, project original validation, malformed DEX/XML rejection, and a read-only snapshot of the test process's own mapped file where `/proc` is available.

Opt-in integration checks use actual Apktool, JADX, keytool, apksigner, and zipalign:

```bash
python scripts/fetch-test-fixture.py /tmp/uat-sample.apk
UAT_INTEGRATION_APK=/tmp/uat-sample.apk python -m unittest discover -s tests -v
```

The fixture is pinned to Apktool v3.0.3's `dynamic_dex` test APK and verified with SHA-256. It is downloaded for testing and is not included in this repository. It has a stale DEX SHA-1, which inspection reports; the freshly rebuilt DEX must pass both SHA-1 and Adler-32 checks.

The integration test imports the compiled APK, decodes it, changes `allowBackup` through an XML recipe, rebuilds it, creates a temporary key, aligns/signs/verifies it, checks its signing certificate, validates the new manifest and DEX, and checks that a wrong password produces no exported APK. A second check runs JADX and inspects the original DEX.

The optional runtime checks use Frida to inspect a test-owned child process's modules/exports, and Ghidra to decompile a newly compiled test library. Enable them with `UAT_FRIDA_INTEGRATION=1` and `UAT_GHIDRA_TOOL=/path/to/support/analyzeHeadless` (with a compatible full JDK configured). Provider unit tests also verify invocation construction, output validation, and Frida session cleanup; these mocks do not establish licensed IDA runtime compatibility.

Initial development validation uses Linux x86_64 with Apktool 3.0.3, JADX 1.5.6, JDK 21, Android build-tools 35, Frida 17.2.14, and Ghidra 12.1.4. The CI workflow is configured for Python 3.10, 3.12, and 3.14. Native Termux ARM64 package behavior, Android installer interaction, ADB/SSH, root-manager interaction, licensed IDA execution, and live access to other Android apps require additional testing; Linux validation does not establish those results.
