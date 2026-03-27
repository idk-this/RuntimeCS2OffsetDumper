#include <iostream>
#include <fstream>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include "json.h"
#include "CS2Dumper.hpp"

using json = nlohmann::json;

uintptr_t GetModuleBase(DWORD pid, const std::string& modName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me{ sizeof(me) };
    if (Module32First(hSnap, &me)) {
        do {
            std::wstring wname(modName.begin(), modName.end());
            if (wname == me.szModule) {
                CloseHandle(hSnap);
                return (uintptr_t)me.modBaseAddr;
            }
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
    return 0;
}

DWORD GetPID(const std::string& procName) {
    PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    if (Process32First(hSnap, &pe)) {
        do {
            std::wstring wprocName(procName.begin(), procName.end());
            if (wprocName == pe.szExeFile) {
                CloseHandle(hSnap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return 0;
}


struct Vec3 {
    float x, y, z;
};



void PrintPlayers(HANDLE hProc, uintptr_t clientBase) {
    uintptr_t entityListBase = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)(clientBase + CS2Dumper::GetOffset("dwEntityList")), &entityListBase, sizeof(entityListBase), nullptr)) {
        std::cout << "[!] Не удалось прочитать dwEntityList\n";
        return;
    }
    uintptr_t controllerArray = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)(entityListBase + 0x10), &controllerArray, sizeof(controllerArray), nullptr)) {
        std::cout << "[!] Не удалось прочитать controllerArray\n";
        return;
    }
    for (int i = 0; i < 64; ++i) {
        uintptr_t controllerPtr = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(controllerArray + i * 0x70), &controllerPtr, sizeof(controllerPtr), nullptr))
            continue;
        if (controllerPtr == 0)
            continue;

        int pawnHandle = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(controllerPtr + CS2Dumper::GetSchema("client.dll", "CCSPlayerController", "m_hPlayerPawn")), &pawnHandle, sizeof(pawnHandle), nullptr))
            continue;
        if (pawnHandle == 0)
            continue;

        uint32_t entryIndex = (pawnHandle & 0x7FFF) >> 9;
        uint32_t subIndex = pawnHandle & 0x1FF;

        uintptr_t pawnBlock = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(entityListBase + 8 * entryIndex + 0x10), &pawnBlock, sizeof(pawnBlock), nullptr))
            continue;
        if (pawnBlock == 0)
            continue;

        uintptr_t pawnPtr = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(pawnBlock + 0x70 * subIndex), &pawnPtr, sizeof(pawnPtr), nullptr))
            continue;
        if (pawnPtr == 0)
            continue;
        int health = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(pawnPtr + CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_iHealth")), &health, sizeof(health), nullptr))
            continue;

        int team = 0;
        if (!ReadProcessMemory(hProc, (LPCVOID)(pawnPtr + CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_iTeamNum")), &team, sizeof(team), nullptr))
            continue;

        Vec3 pos = { 0, 0, 0 };
        if (!ReadProcessMemory(hProc, (LPCVOID)(pawnPtr + CS2Dumper::GetSchema("client.dll", "C_BasePlayerPawn", "m_vOldOrigin")), &pos, sizeof(pos), nullptr))
            continue;

        std::cout << "[" << i << "] "
            << "Health: " << health
            << " | Team: " << (team == 2 ? "Terrorist" : team == 3 ? "Counter-Terrorist" : "Spectator")
            << " | Pos: (" << pos.x << ", " << pos.y << ", " << pos.z << ")\n";
    }
}
int main() {
    std::ifstream f("config.json");
    if (!f.is_open()) return 1;

    json data = json::parse(f);
    std::vector<CS2Dumper::ModuleConfig> configs;

    for (auto& mod : data["modules"]) {
        CS2Dumper::ModuleConfig mc;
        mc.name = mod["name"];
        for (auto& p : mod["patterns"]) {
            CS2Dumper::Pattern pat;
            pat.name = p["name"]; pat.sig = p["sig"]; pat.offset = p["offset"];
            pat.size = p["size"]; pat.rip = p["rip"];
            if (p.contains("read_size")) pat.read_size = p["read_size"];
            if (p.contains("sub_sig")) {
                pat.sub_name = p["sub_name"]; pat.sub_sig = p["sub_sig"]; pat.sub_offset = p["sub_offset"];
            }
            mc.patterns.push_back(pat);
        }
        configs.push_back(mc);
    }

    DWORD pid = GetPID("cs2.exe");
    if (!pid || !CS2Dumper::Setup(pid, configs)) return 1;

    CS2Dumper::Dump();
    uintptr_t clientBase = GetModuleBase(pid, "client.dll");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    while (!(GetAsyncKeyState(VK_END) & 0x8000)) {
        if (GetAsyncKeyState(VK_RETURN) & 0x8000) {
            std::cout << "\n--- Player List ---" << std::endl;
            PrintPlayers(hProc, clientBase);
            Sleep(300);
        }
        Sleep(10);
    }

    CloseHandle(hProc);
    CS2Dumper::Cleanup();
    return 0;
}
