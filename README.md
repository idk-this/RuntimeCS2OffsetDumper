# CS2Dumper 🚀

**CS2Dumper** is an automated offset and schema extraction tool for Counter-Strike 2. It combines signature pattern scanning with dynamic Source 2 `SchemaSystem` parsing to provide a robust solution for maintaining game hacks and tools.

---

### ✨ Key Features

* **Automated Pattern Scanning**: Supports 64-bit signatures with `RIP-relative` addressing and nested sub-signatures.
* **Dynamic Schema Parsing**: Traverses the `SchemaSystem` at runtime to find class member offsets (e.g., `m_iHealth`) without static headers.
* **External Configuration**: Uses `config.json` for all signatures, allowing updates without recompilation.
* **Backend Agnostic**: Easily swap `ReadProcessMemory` for DMA or Kernel drivers via the `MemReader` struct.

---

### 📂 Project Structure

| File | Description |
| :--- | :--- |
| `CS2Dumper.hpp` | Core engine handling memory reading and offset resolution. |
| `config.json` | JSON database of patterns for `client.dll`, `engine2.dll`, etc. |
| `example.cpp` | Reference implementation for initialization and data retrieval. |

---

### 🛠 Quick Start

1. **Initialize and Scan**:
   ```cpp
   std::vector<CS2Dumper::ModuleConfig> configs = LoadConfig("config.json");
   DWORD pid = GetPID("cs2.exe");
   
   if (CS2Dumper::Setup(pid, configs)) {
       CS2Dumper::Dump(); // Scans and parses schemas
   }
   ```

2. **Access Data**:
   ```cpp
   // Global Offset
   uintptr_t entityList = CS2Dumper::GetOffset("dwEntityList");
   
   // Schema Offset
   uintptr_t health = CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_iHealth");
   ```

---

### 📋 Requirements

* **Language**: C++20.
* **OS**: Windows (x64).
* **Dependencies**: [nlohmann/json](https://github.com/nlohmann/json).

---

### ⚠️ Disclaimer
This tool is for educational purposes only. Use at your own risk.
