#pragma once
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <set>
#include <functional>
#include <iostream>

// ---------------------------------------------------------------------------
//  Memory reader abstraction — swap this out to use your own read backend
// ---------------------------------------------------------------------------
struct MemReader {
    // Replace this function to use DMA, kernel driver, etc.
    // Returns true on success.
    static inline std::function<bool(HANDLE, uintptr_t, void*, size_t)> ReadFn =
        [](HANDLE hProc, uintptr_t addr, void* out, size_t sz) -> bool {
        return ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addr), out, sz, nullptr) != 0;
        };
};

class CS2Dumper {
public:
    struct SchemaField { std::string name, type; int32_t offset; };
    struct SchemaClass { std::string name; std::map<std::string, SchemaField> fields; };

    struct Pattern {
        std::string name, sig;
        std::string sub_name = "", sub_sig = "";
        int offset = 0, size = 0, sub_offset = 0, read_size = 4;
        bool rip = false;
    };
    struct ModuleConfig { std::string name; std::vector<Pattern> patterns; };

    using SchemaDB = std::map<std::string, std::map<std::string, SchemaClass>>;

private:
    struct ModuleData {
        uintptr_t              base = 0;
        uint32_t               size = 0;
        std::vector<uint8_t>   buffer;
        std::map<std::string, uintptr_t> offsets; // pattern name -> resolved value
    };

    static inline std::map<std::string, ModuleData> s_modules;
    static inline std::map<std::string, ModuleConfig> s_mod_configs;
    static inline SchemaDB                           s_schema_db;
    static inline HANDLE                             s_hProc = nullptr;

    template<typename T>
    static T Read(uintptr_t addr) {
        T val{};
        MemReader::ReadFn(s_hProc, addr, &val, sizeof(T));
        return val;
    }

    static std::string ReadString(uintptr_t addr) {
        if (!addr) return {};
        char buf[256]{};
        MemReader::ReadFn(s_hProc, addr, buf, sizeof(buf) - 1);
        return std::string(buf);
    }

    static size_t FindPattern(const std::vector<uint8_t>& buf, const std::string& pattern) {
        std::vector<int> bytes;
        std::stringstream ss(pattern);
        std::string tok;
        while (ss >> tok)
            bytes.push_back((tok == "?" || tok == "??") ? -1 : std::stoi(tok, nullptr, 16));

        for (size_t i = 0; i + bytes.size() <= buf.size(); ++i) {
            bool ok = true;
            for (size_t j = 0; j < bytes.size(); ++j) {
                if (bytes[j] != -1 && buf[i + j] != static_cast<uint8_t>(bytes[j])) {
                    ok = false; break;
                }
            }
            if (ok) return i;
        }
        return std::string::npos;
    }

    static void ParseUtlTsHash(uintptr_t hash_addr, const std::string& scope_name) {
        int32_t blocks_allocated = Read<int32_t>(hash_addr + 0x0C);
        if (blocks_allocated <= 0 || blocks_allocated > 100000) return;

        std::set<uintptr_t> seen;
        int found = 0;

        for (int b = 0; b < 256 && found < blocks_allocated; ++b) {
            uintptr_t bucket = hash_addr + 0x60 + b * 0x18;
            uintptr_t node_ptr = Read<uintptr_t>(bucket + 0x10);

            while (node_ptr > 0x10000 && node_ptr < 0x7FFFFFFFFFFFULL) {
                if (!seen.insert(node_ptr).second) break;

                uintptr_t data = Read<uintptr_t>(node_ptr + 0x10);
                uintptr_t next = Read<uintptr_t>(node_ptr + 0x08);

                if (data > 0x10000) {
                    std::string class_name = ReadString(Read<uintptr_t>(data + 0x8));
                    std::string dll_name = ReadString(Read<uintptr_t>(data + 0x10));
                    if (!dll_name.empty()) dll_name += ".dll";

                    std::string key = dll_name.empty() ? scope_name : dll_name;

                    if (!class_name.empty()) {
                        SchemaClass sc;
                        sc.name = class_name;

                        int16_t   f_count = Read<int16_t>(data + 0x1C);
                        uintptr_t fields_ptr = Read<uintptr_t>(data + 0x28);

                        if (f_count > 0 && f_count < 4096 && fields_ptr > 0x10000) {
                            for (int k = 0; k < f_count; ++k) {
                                uintptr_t f_addr = fields_ptr + k * 0x20;
                                SchemaField sf;
                                sf.name = ReadString(Read<uintptr_t>(f_addr + 0x00));
                                sf.offset = Read<int32_t>(f_addr + 0x10);
                                uintptr_t t_ptr = Read<uintptr_t>(f_addr + 0x08);
                                sf.type = (t_ptr > 0x10000) ? ReadString(Read<uintptr_t>(t_ptr + 0x8)) : "unknown";
                                if (!sf.name.empty())
                                    sc.fields[sf.name] = sf;
                            }
                        }

                        s_schema_db[key][class_name] = std::move(sc);
                        ++found;
                    }
                }
                node_ptr = next;
            }
        }
    }

public:


    static bool Setup(DWORD pid, const std::vector<ModuleConfig>& configs) {
        s_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!s_hProc) { std::cout << "[CS2Dumper] Failed to open process\n"; return false; }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap == INVALID_HANDLE_VALUE) return false;

        MODULEENTRY32 me{ sizeof(me) };
        if (Module32First(hSnap, &me)) {
            do {
                std::wstring ws(me.szModule);
                std::string  mName(ws.begin(), ws.end());
                for (const auto& cfg : configs) {
                    if (cfg.name != mName) continue;
                    auto& mod = s_modules[mName];
                    mod.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                    mod.size = me.modBaseSize;
                    mod.buffer.resize(mod.size);
                    MemReader::ReadFn(s_hProc, mod.base, mod.buffer.data(), mod.size);
                    s_mod_configs[mName] = cfg;
                    std::cout << "[CS2Dumper] Loaded: " << mName
                        << " @ 0x" << std::hex << mod.base << std::dec << "\n";
                }
            } while (Module32Next(hSnap, &me));
        }
        CloseHandle(hSnap);
        return !s_modules.empty();
    }

    static void Cleanup() {
        if (s_hProc) { CloseHandle(s_hProc); s_hProc = nullptr; }
        s_modules.clear();
        s_mod_configs.clear();
        s_schema_db.clear();
    }
    static void Dump() {
        DumpGlobalOffsets();
        DumpSchemas();
    }
private:
    static void DumpGlobalOffsets() {
        for (auto& [name, mod] : s_modules) {
            for (const auto& p : s_mod_configs[name].patterns) {
                size_t off = FindPattern(mod.buffer, p.sig);
                if (off == std::string::npos) continue;

                uintptr_t val = 0;
                if (p.rip) {
                    int32_t rel = *(int32_t*)(&mod.buffer[off + p.offset]);
                    val = off + p.size + rel;
                }
                else {
                    val = (p.read_size == 1) ? (uintptr_t)mod.buffer[off + p.offset] : (uintptr_t) * (uint32_t*)(&mod.buffer[off + p.offset]);
                }
                mod.offsets[p.name] = val;

                if (p.sub_sig.empty()) continue;

                size_t sub_off = FindPattern(mod.buffer, p.sub_sig);
                if (sub_off == std::string::npos) continue;

                uintptr_t delta = (uintptr_t) * (uint32_t*)(&mod.buffer[sub_off + p.sub_offset]);
                mod.offsets[p.sub_name] = val + delta;
                
            }
        }
    }
   
    static void DumpSchemas() {
        if (!s_modules.contains("schemasystem.dll")) return;
        auto& ss_mod = s_modules["schemasystem.dll"];
        if (!ss_mod.offsets.contains("dwSchemaSystem")) return;

        uintptr_t sys_inst = ss_mod.base + ss_mod.offsets["dwSchemaSystem"];
        int32_t   count = Read<int32_t>(sys_inst + 0x190);
        uintptr_t scope_arr = Read<uintptr_t>(sys_inst + 0x198);
        int32_t   reg_count = Read<int32_t>(sys_inst + 0x280);

        std::cout << "[CS2Dumper] SchemaSystem: count=" << count
            << " reg=" << reg_count
            << " arr=0x" << std::hex << scope_arr << std::dec << "\n";

        if (count <= 0 || count > 64 || scope_arr < 0x10000 || scope_arr > 0x7FFFFFFFFFFFULL)
            return;

        for (int i = 0; i < count; ++i) {
            uintptr_t scope_ptr = Read<uintptr_t>(scope_arr + i * 8);
            if (scope_ptr < 0x10000 || scope_ptr > 0x7FFFFFFFFFFFULL) continue;

            char name[256]{};
            MemReader::ReadFn(s_hProc, scope_ptr + 0x8, name, 255);
            std::cout << "[CS2Dumper] scope[" << i << "] = " << name << "\n";

            ParseUtlTsHash(scope_ptr + 0x0560, name);
        }
    }
public:
    static uintptr_t GetOffset(const std::string& name) {
        for (const auto& [mod_name, mod] : s_modules) {
            auto it = mod.offsets.find(name);
            if (it != mod.offsets.end())
                return it->second;
        }
        return 0;
    }

    static uintptr_t GetSchema(const std::string& module,
        const std::string& class_name,
        const std::string& field_name) {
        auto mod_it = s_schema_db.find(module);
        if (mod_it == s_schema_db.end()) return 0;
        auto cls_it = mod_it->second.find(class_name);
        if (cls_it == mod_it->second.end()) return 0;
        auto fld_it = cls_it->second.fields.find(field_name);
        if (fld_it == cls_it->second.fields.end()) return 0;
        return static_cast<uintptr_t>(static_cast<uint32_t>(fld_it->second.offset));
    }

    static const std::map<std::string, SchemaClass>& GetSchemaModule(const std::string& module) {
        static const std::map<std::string, SchemaClass> empty;
        auto it = s_schema_db.find(module);
        return it != s_schema_db.end() ? it->second : empty;
    }

};