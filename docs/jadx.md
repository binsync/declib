# JADX backend

The JADX backend analyzes APK, DEX, JAR, class, Smali, AAB, and XAPK inputs
through `jadx-core`. It does not depend on MCP. DecLib starts a private,
long-lived Java worker for each JADX server and exchanges structured JSON over
the worker's standard input and output.

## Setup

The prototype worker requires Java 17 or newer and Gradle. It is built
automatically on the first JADX load:

```bash
decompiler load ./challenge.apk --backend jadx
```

To build it ahead of time:

```bash
cd declib/decompilers/jadx/worker
gradle --no-daemon test installDist
```

Set `DECLIB_JADX_WORKER` to use a prebuilt worker command. The generated
launcher accepts additional JVM arguments through
`DECLIB_JADX_WORKER_OPTS`. Its default maximum heap is 4 GiB:

```bash
export DECLIB_JADX_WORKER_OPTS="-Xmx8g"
```

## Usage

Managed-code objects use stable JVM/Dex references instead of fake native
addresses. Always copy the complete `ref` from a list command; method
descriptors distinguish overloads.

```bash
decompiler class list --filter 'challenge' --json
decompiler class source 'com.example.MainActivity' --raw

decompiler method list --class 'com.example.MainActivity' --json
decompiler method source \
  'com.example.MainActivity->checkFlag(Ljava/lang/String;)Z' --raw
decompiler method xrefs \
  'com.example.MainActivity->checkFlag(Ljava/lang/String;)Z' --json

decompiler field list --class 'com.example.MainActivity' --json
decompiler resource list --filter 'xml|json' --json
decompiler resource get 'res/values/strings.xml' --max-chars 8000 --json
decompiler manifest --raw
```

Class source, method source, text resources, and the manifest can be bounded
with `--max-chars`. Binary resources are base64 encoded and bounded to 1 MiB
by default; change that limit with `resource get --max-bytes`.

## Native API differences

JADX methods are intentionally not exposed through DecLib's address-keyed
`functions` artifact dictionary. Native operations such as memory reads,
segments, byte patches, and define/undefine have no JVM/Dex equivalent.

Callers, callees, and other xrefs can trigger JADX whole-program usage
analysis. On large applications this can take substantially more time and
memory than listing or decompiling a single class. The 4 GiB default worker
heap bounds this work; raise it explicitly for unusually large applications.
