# XOSINFO: Cross-Platform System Information CLI

[![Website](https://img.shields.io/badge/Website-XOSINFO-blue.svg)](https://ratiojuris.github.io/XOSINFO/)
[![Version](https://img.shields.io/badge/Version-1.0-brightgreen.svg)]()
[![Author](https://img.shields.io/badge/Author-Ratio_Juris-purple.svg)](https://github.com/RatioJuris)

**Version:** 1.0  
**Author:** Ratio Juris  
**Website:** [ratiojuris.github.io/XOSINFO/](https://ratiojuris.github.io/XOSINFO/)  

XOSINFO is an enterprise-grade, high-performance cross-platform Command Line Interface (CLI) utility built in pure C++17. Engineered specifically for judicial, legal, and forensic system state capture, it extracts deterministic snapshots of hardware topology, network configurations, storage infrastructure, and operating system properties, outputting them in strict compliance with standard data schema serialization layers.

---

## 🛡️ Key Core Capabilities

*   **Defensive Error Resilience:** Built defensively using clean try-catch structures down to the platform API layer. Intermittent query faults or unprivileged infrastructure states fail gracefully, storing targeted platform errors in the JSON schema without interrupting execution.
*   **Prone Defect Remediation:** Zero manual or raw memory allocations (`strcpy`, standard unsafe pointers) are utilized within runtime data pipelines. Native OS structures are safely managed via automated wrappers (`std::unique_ptr` and standard STL components) to eliminate buffer overflow vectors.
*   **Zero External Dependencies:** Compiles directly against system-level static platform APIs (Win32/IPHLPAPI, POSIX, sysctl, Linux procfs).
*   **Validated JSON Serialization:** Features an internal text-transformation sanitization routine (`Utils::escapeJson`) that filters structural properties and control flags to guarantee database-safe JSON inputs.

---

## 📊 Architectural Data Schema

Running the utility yields a unified JSON schema mapping across your corporate monitoring endpoints. Missing or unauthorized privilege attributes append an `"error"` property inline inside the corresponding node object:

```json
{
  "metadata": {
    "tool": "XOSINFO",
    "version": "1.0",
    "purpose": "Judicial, legal, and forensic system state capture."
  },
  "timestamp": "2026-08-18T00:12:00Z",
  "hostname": "FORENSIC-WORKSTATION-01",
  "os": {
    "name": "Linux",
    "release": "6.8.0-1012-aws",
    "version": "#12-Ubuntu SMP",
    "architecture": "x86_64"
  },
  "memory": {
    "total_ram_bytes": 17179869184,
    "free_ram_bytes": 12884901888
  },
  "storage": [
    {
      "path": "/",
      "total_bytes": 107374182400,
      "free_bytes": 85899345920,
      "available_bytes": 85899345920
    }
  ],
  "network": [
    {
      "interface": "eth0",
      "ipv4": "10.0.0.15",
      "ipv6": "fe80::a00:27ff:fe4e:66a1",
      "mac_address": "00:15:5d:01:ca:12"
    }
  ]
}

```

---

## 💻 Command Line Usage

### Standard Execution (stdout)

By default, executing the binary fetches all physical state properties and flushes a minified JSON data block onto the standard terminal output pipe:

```bash
./xosinfo-linux-x64

```

### Dual-Output Routing (File Persistence)

Provide an unswitched trailing path variable string as the first target index parameter (`argv[1]`). The utility streams the data map directly to `stdout` while concurrently writing and truncating the payload text safely onto an explicit local system storage unit:

```bash
.\xosinfo-win64.exe D:\Captures\case_snapshot_0826.json

```

---

## 🏗️ Compiling From Source Natively

The project is built on standard compliant toolchains supporting C++17 or newer extensions.

### Windows (MinGW 64-bit Environment)

Ensure you bind explicitly against the core IP helper and Winsock runtime libraries during linking:

```bash
g++ src/main.cpp -o build/xosinfo-win64.exe -O3 -liphlpapi -lws2_32

```

### Linux (GCC G++)

```bash
g++ src/main.cpp -o build/xosinfo-linux-x64 -O3

```

### macOS (Clang Appending Fat-Binary Universal Architecture Architecture)

Generates a fat binary supporting both legacy Intel (`x86_64`) and native Apple Silicon M-Series (`arm64`) execution matrices:

```bash
clang++ src/main.cpp -o build/xosinfo-macos -O3 -arch x86_64 -arch arm64

```

---

## ⚙️ CI/CD Delivery Pipeline

The engineering workspace features a continuous delivery lifecycle workflow (`.github/workflows/build-and-release.yml`) driven by GitHub Actions.

### Pipeline Lifecycle Steps:

1. **Matrix Cross-Compilation:** Instantiates parallel clean environment workers (`ubuntu-latest`, `windows-latest`, `macos-latest`) to build isolated native target binaries.
2. **Deterministic Folder Separation:** Outbound compilations are securely funneled into a separate temporary execution sandbox path named `build/`.
3. **Automated Tracking Analytics Generation:** Orchestrates a final automated aggregation bot (**RatioJurisBeeBot**) that downloads compiling assets, generates a versioned runtime matrix manifest named `stats.json`, updates index maps, and pushes structural components down to the main tracking branch.
4. **Autonomous Release Distribution:** Tag events (`v*.*`) flag the build core to call release hooks, upload verification tracking matrix arrays, and bind production artifacts straight onto public marketplace channels automatically.

```

```
