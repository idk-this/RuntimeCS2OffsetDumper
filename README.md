# CS2Dumper 🚀

**CS2Dumper** is a cross-language automated offset and schema extraction tool for Counter-Strike 2. It provides a robust way to handle memory offsets and dynamic `SchemaSystem` parsing using signature scanning.

## ✨ Key Features

* **Multi-Language Support**: Implementation available in C++ and C#.
* **Single-Header (C++)**: Zero-dependency, header-only implementation for easy integration.
* **Automated Pattern Scanning**: Supports 64-bit signatures with `RIP-relative` addressing and nested sub-signatures.
* **Dynamic Schema Parsing**: Traverses the `SchemaSystem` at runtime to find class member offsets (e.g., `m_iHealth`) without static headers.
* **External Configuration**: Uses `config.json` for all signatures, allowing updates without recompilation.
* **Backend Agnostic**: Easily swap the memory reading logic for DMA or Kernel drivers.

---

## 📂 Project Structure

```text
.
├── config.json         # Central database of patterns and modules
├── README.md
├── C#                  # C# Implementation
│   ├── CS2Dumper.cs    # Core logic
│   └── Example.cs      # Usage example
└── C++                 # C++ Implementation
    ├── CS2Dumper.hpp   # Core engine (Single-header)
    ├── example.cpp     # Basic usage
    └── example_2.cpp   # Advanced usage (Modules & WorldToScreen)
```

---

## 🛠 Quick Start

### C++ Integration
Copy `CS2Dumper.hpp` to your project and include it directly.
```cpp
#include "CS2Dumper.hpp"

// Setup
if (CS2Dumper::Setup(pid, configs)) {
    CS2Dumper::Dump(); 
}

// Access Data
uintptr_t entityList = CS2Dumper::GetOffset("dwEntityList");
uintptr_t health = CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_iHealth");
```

### C# Integration
Include `CS2Dumper.cs` in your solution.
```csharp
// Setup
if (CS2Dumper.Setup(pid, root.modules)) {
    CS2Dumper.Dump();
}

// Access Data
ulong entityList = CS2Dumper.GetOffset("dwEntityList");
int healthOffset = CS2Dumper.GetSchema("client.dll", "C_BaseEntity", "m_iHealth");
```

---

## ⚙️ Configuration
The `config.json` file is the source of truth for all implementations. It defines modules, primary signatures, and optional sub-signatures.

```json
{
  "name": "dwEntityList",
  "sig": "48 89 0D ? ? ? ? E9 ? ? ? ? CC",
  "offset": 3,
  "size": 7,
  "rip": true
}
```

---

## 🧩 Adding Implementations
Each language implementation is contained within its own directory. To use a specific language version:
1. Navigate to the corresponding folder.
2. Follow the language-specific examples provided in that directory.
3. Use the root `config.json` to provide pattern data to the scanner.
