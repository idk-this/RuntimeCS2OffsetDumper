#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <map>
#include <memory>
#include <string>
#include <sstream>
#include <functional>
#include <mutex>
#include <TlHelp32.h>
#include <set>

class ProcessAttach {
public:

    explicit ProcessAttach() {}
    ~ProcessAttach() { Detach(); }

    bool Attach(DWORD pid) {
        Detach();
        _hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (_hProc) return true;
        return false;
    }

    void Detach() {
        if (!_hProc) return;
        CloseHandle(_hProc);
        _hProc = nullptr;
    }

    template<typename T>
    T Read(uintptr_t addr) const {
        T val{};
        ReadProcessMemory(_hProc, reinterpret_cast<LPCVOID>(addr), &val, sizeof(T), nullptr) != 0;
        return val;
    }

    std::string ReadString(uintptr_t addr, size_t maxLen = 255) const {
        if (!addr) return {};
        std::string buf(maxLen, '\0');
        ReadProcessMemory(_hProc, reinterpret_cast<LPCVOID>(addr), buf.data(), maxLen, nullptr);
        auto end = buf.find('\0');
        return end == std::string::npos ? buf : buf.substr(0, end);
    }

    bool ReadModuleBuffer(uintptr_t base, size_t size, std::vector<uint8_t>& out) const {
        out.resize(size);
        return ReadProcessMemory(_hProc, reinterpret_cast<LPCVOID>(base), out.data(), size, nullptr) != 0;
    }

private:
    HANDLE _hProc = nullptr;
};


class CS2Dumper {
public:
    enum class LogLevel { Debug, Info, Warning, Error };

    struct IDumperLogger {
        virtual ~IDumperLogger() = default;
        virtual void Log(LogLevel level, const std::string& msg) = 0;
    };

    struct Pattern {
        std::string name, sig, sub_name, sub_sig;
        int offset = 0, size = 0, sub_offset = 0, read_size = 4;
        bool rip = false;
    };

    struct ModuleConfig {
        std::string name;
        std::vector<Pattern> patterns;
    };

    struct SchemaField { std::string name, type; int32_t offset; };
    struct SchemaClass { std::string name; std::map<std::string, SchemaField> fields; };

    struct DumpResult {
        int Paterns = 0;
        int FoundOffsets = 0;
        int Scopes = 0;
        int Classes = 0;
        int Fields = 0;
    };
    struct ModuleData {
        uintptr_t base = 0;
        uint32_t size = 0;
        std::vector<uint8_t> buffer;
        std::map<std::string, uintptr_t> offsets;
    };
    static void SetLogger(IDumperLogger* logger) { s_log = logger; }
    static void Cleanup() {
        std::lock_guard g(s_mutex);
        if (s_mem) s_mem->Detach();
        s_mem.reset();
        s_modules.clear();
        s_mod_configs.clear();
        s_schema_db.clear();
    }
    static bool Setup(DWORD pid, const std::vector<ModuleConfig>& configs) {
        Cleanup();
        s_mem = std::make_unique<ProcessAttach>();
        if (!s_mem->Attach(pid)) return false;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap == INVALID_HANDLE_VALUE) return false;

        MODULEENTRY32 me{ sizeof(me) };
        if (Module32First(hSnap, &me)) {
            do {
                std::wstring ws(me.szModule);
                std::string mName(ws.begin(), ws.end());
                for (const auto& cfg : configs) {
                    if (cfg.name != mName) continue;
                    auto& mod = s_modules[mName];
                    mod.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                    mod.size = me.modBaseSize;
                    if (!s_mem->ReadModuleBuffer(mod.base, mod.size, mod.buffer)) {
                        if (s_log) s_log->Log(LogLevel::Error, "Read error: " + mName);
                        continue;
                    }
                    s_mod_configs[mName] = cfg;
                    
                    if (s_log) s_log->Log(LogLevel::Info, "Module loaded: " + mName);
                }
            } while (Module32Next(hSnap, &me));
        }
        CloseHandle(hSnap);
        return !s_modules.empty();
    }
    static uintptr_t GetOffset(const std::string& name) {
        std::lock_guard g(s_mutex);
        for (const auto& [mName, mod] : s_modules) {
            auto it = mod.offsets.find(name);
            if (it != mod.offsets.end()) return it->second;
        }
        if (s_log) s_log->Log(LogLevel::Error, "Offset NOT FOUND: " + name);
        return 0;
    }
    static const std::map<std::string, ModuleData>& GetModules() { return s_modules; }
    static const std::map<std::string, std::map<std::string, SchemaClass>>& GetSchemaDB() { return s_schema_db; }
    static uintptr_t GetSchema(const std::string& module, const std::string& className, const std::string& fieldName) {
        std::lock_guard g(s_mutex);
        auto m = s_schema_db.find(module);
        if (m == s_schema_db.end()) { if (s_log) s_log->Log(LogLevel::Error, "Schema Mod Missing: " + module); return 0; }

        auto c = m->second.find(className);
        if (c == m->second.end()) { if (s_log) s_log->Log(LogLevel::Error, "Schema Class Missing: " + className); return 0; }

        auto f = c->second.fields.find(fieldName);
        if (f == c->second.fields.end()) { if (s_log) s_log->Log(LogLevel::Error, "Schema Field Missing: " + fieldName + " in " + className); return 0; }

        return static_cast<uintptr_t>(static_cast<uint32_t>(f->second.offset));
    }
    static DumpResult Dump() {
        DumpResult res;
        std::lock_guard g(s_mutex);
        for (auto& [mName, mod] : s_modules) {
            for (const auto& p : s_mod_configs[mName].patterns) {
                res.Paterns++;
                size_t off = FindPattern(mod.buffer, p.sig);
                if (off == std::string::npos) {
                    if (s_log) s_log->Log(LogLevel::Warning, "Pattern Fail: " + p.name);
                    continue;
                }
                uintptr_t val = p.rip ? (off + p.size + *reinterpret_cast<const int32_t*>(&mod.buffer[off + p.offset])) :
                    (p.read_size == 1 ? (uintptr_t)mod.buffer[off + p.offset] : (uintptr_t) * reinterpret_cast<const uint32_t*>(&mod.buffer[off + p.offset]));
                mod.offsets[p.name] = val;
                res.FoundOffsets++;
                if (p.sub_sig.empty()) continue;
                size_t sOff = FindPattern(mod.buffer, p.sub_sig);
                if (sOff != std::string::npos) mod.offsets[p.sub_name] = val + *reinterpret_cast<const uint32_t*>(&mod.buffer[sOff + p.sub_offset]);
            }
        }
        DumpSchemas(res);
        return res;
    }

private:
    static inline IDumperLogger* s_log = nullptr;
    static inline std::unique_ptr<ProcessAttach> s_mem;
    static inline std::map<std::string, ModuleData> s_modules;
    static inline std::map<std::string, ModuleConfig> s_mod_configs;
    static inline std::map<std::string, std::map<std::string, SchemaClass>> s_schema_db;
    static inline std::mutex s_mutex;

    static size_t FindPattern(const std::vector<uint8_t>& buf, const std::string& pattern) {
        std::vector<int> bytes;
        std::istringstream ss(pattern);
        std::string t;
        while (ss >> t) bytes.push_back((t == "?" || t == "??") ? -1 : std::stoi(t, nullptr, 16));
        for (size_t i = 0; i + bytes.size() <= buf.size(); ++i) {
            bool hit = true;
            for (size_t j = 0; j < bytes.size(); ++j) if (bytes[j] != -1 && buf[i + j] != (uint8_t)bytes[j]) { hit = false; break; }
            if (hit) return i;
        }
        return std::string::npos;
    }

    static void DumpSchemas(DumpResult& res) {
        auto ss = s_modules.find("schemasystem.dll");
        if (ss == s_modules.end() || ss->second.offsets.find("dwSchemaSystem") == ss->second.offsets.end()) return;
        uintptr_t inst = ss->second.base + ss->second.offsets["dwSchemaSystem"];
        int32_t count = s_mem->Read<int32_t>(inst + 0x190);
        uintptr_t list = s_mem->Read<uintptr_t>(inst + 0x198);
        for (int i = 0; i < count; ++i) {
            uintptr_t sPtr = s_mem->Read<uintptr_t>(list + i * 8);
            if (!sPtr) continue;
            std::string sName = s_mem->ReadString(sPtr + 0x8);
            ParseHash(sPtr + 0x0560, sName, res);
            res.Scopes++;
        }
    }

    static void ParseHash(uintptr_t addr, const std::string& sName, DumpResult& res) {
        int32_t allocated = s_mem->Read<int32_t>(addr + 0x0C);
        std::set<uintptr_t> seen;
        int found = 0;
        for (int b = 0; b < 256 && found < allocated; ++b) {
            uintptr_t nPtr = s_mem->Read<uintptr_t>(addr + 0x60 + b * 0x18 + 0x10);
            while (nPtr > 0x10000) {
                if (!seen.insert(nPtr).second) break;
                uintptr_t data = s_mem->Read<uintptr_t>(nPtr + 0x10);
                uintptr_t next = s_mem->Read<uintptr_t>(nPtr + 0x08);
                if (data > 0x10000) {
                    std::string cName = s_mem->ReadString(s_mem->Read<uintptr_t>(data + 0x8));
                    std::string dll = s_mem->ReadString(s_mem->Read<uintptr_t>(data + 0x10));
                    if (!dll.empty()) dll += ".dll";
                    std::string key = dll.empty() ? sName : dll;
                    SchemaClass sc{ cName };
                    int16_t fCount = s_mem->Read<int16_t>(data + 0x1C);
                    uintptr_t fPtr = s_mem->Read<uintptr_t>(data + 0x28);
                    for (int k = 0; k < fCount; ++k) {
                        uintptr_t fA = fPtr + k * 0x20;
                        SchemaField sf{ s_mem->ReadString(s_mem->Read<uintptr_t>(fA)), "", s_mem->Read<int32_t>(fA + 0x10) };
                        uintptr_t tP = s_mem->Read<uintptr_t>(fA + 0x08);
                        sf.type = tP > 0x10000 ? s_mem->ReadString(s_mem->Read<uintptr_t>(tP + 0x8)) : "unk";
                        if (!sf.name.empty()) { sc.fields[sf.name] = sf; res.Fields++; }
                    }
                    s_schema_db[key][cName] = std::move(sc);
                    found++; res.Classes++;
                }
                nPtr = next;
            }
        }
    }
};
