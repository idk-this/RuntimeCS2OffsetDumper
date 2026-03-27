#include <iostream>
#include <fstream>
#include <windows.h>
#include <TlHelp32.h>
#include "json.h"
#include "CS2Dumper.hpp"

using json = nlohmann::json;

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

    int32_t off = CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_iTeamNum");
    std::cout << "\n=== Global offsets ===\n" << std::hex;

    uintptr_t dwEntityList = CS2Dumper::GetOffset("dwEntityList");
    uintptr_t dwLocalPlayerController = CS2Dumper::GetOffset("dwLocalPlayerController");
    uintptr_t dwLocalPlayerPawn = CS2Dumper::GetOffset("dwLocalPlayerPawn");
    uintptr_t dwViewMatrix = CS2Dumper::GetOffset("dwViewMatrix");
    uintptr_t dwCSGOInput = CS2Dumper::GetOffset("dwCSGOInput");
    uintptr_t dwGameRules = CS2Dumper::GetOffset("dwGameRules");
    uintptr_t dwGlowManager = CS2Dumper::GetOffset("dwGlowManager");
    uintptr_t dwPlantedC4 = CS2Dumper::GetOffset("dwPlantedC4");
    uintptr_t dwBuildNumber = CS2Dumper::GetOffset("dwBuildNumber");
    uintptr_t dwNetworkGameClient = CS2Dumper::GetOffset("dwNetworkGameClient");
    uintptr_t dwInputSystem = CS2Dumper::GetOffset("dwInputSystem");

    std::cout << "dwEntityList            = 0x" << dwEntityList << "\n";
    std::cout << "dwLocalPlayerController = 0x" << dwLocalPlayerController << "\n";
    std::cout << "dwLocalPlayerPawn       = 0x" << dwLocalPlayerPawn << "\n";
    std::cout << "dwViewMatrix            = 0x" << dwViewMatrix << "\n";
    std::cout << "dwCSGOInput             = 0x" << dwCSGOInput << "\n";
    std::cout << "dwGameRules             = 0x" << dwGameRules << "\n";
    std::cout << "dwGlowManager           = 0x" << dwGlowManager << "\n";
    std::cout << "dwPlantedC4             = 0x" << dwPlantedC4 << "\n";
    std::cout << "dwBuildNumber           = 0x" << dwBuildNumber << "\n";
    std::cout << "dwNetworkGameClient     = 0x" << dwNetworkGameClient << "\n";
    std::cout << "dwInputSystem           = 0x" << dwInputSystem << "\n";


    std::cout << "\n=== Schema offsets ===\n";

    uintptr_t m_iTeamNum = CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_iTeamNum");
    uintptr_t m_iHealth = CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_iHealth");
    uintptr_t m_lifeState = CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_lifeState");
    uintptr_t m_vecOrigin = CS2Dumper::GetSchema("client.dll", "CGameSceneNode", "m_vecOrigin");
    uintptr_t m_hPlayerPawn = CS2Dumper::GetSchema("client.dll", "CCSPlayerController", "m_hPlayerPawn");
    uintptr_t m_iShotsFired = CS2Dumper::GetSchema("client.dll", "C_CSPlayerPawn", "m_iShotsFired");
    uintptr_t m_fFlags = CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_fFlags");
    uintptr_t m_vecVelocity = CS2Dumper::GetSchema("client.dll", "C_BaseEntity", "m_vecVelocity");
    uintptr_t m_flFlashAlpha = CS2Dumper::GetSchema("client.dll", "C_CSPlayerPawnBase", "m_flFlashMaxAlpha");
    uintptr_t m_bIsDefusing = CS2Dumper::GetSchema("client.dll", "C_CSPlayerPawn", "m_bIsDefusing");

    std::cout << "C_BaseEntity::m_iTeamNum              = 0x" << m_iTeamNum << "\n";
    std::cout << "C_BaseEntity::m_iHealth               = 0x" << m_iHealth << "\n";
    std::cout << "C_BaseEntity::m_lifeState             = 0x" << m_lifeState << "\n";
    std::cout << "CGameSceneNode::m_vecOrigin             = 0x" << m_vecOrigin << "\n";
    std::cout << "CCSPlayerController::m_hPlayerPawn    = 0x" << m_hPlayerPawn << "\n";
    std::cout << "C_CSPlayerPawn::m_iShotsFired         = 0x" << m_iShotsFired << "\n";
    std::cout << "C_BaseEntity::m_fFlags            = 0x" << m_fFlags << "\n";
    std::cout << "C_BaseEntity::m_vecVelocity       = 0x" << m_vecVelocity << "\n";
    std::cout << "C_CSPlayerPawnBase::m_flFlashMaxAlpha = 0x" << m_flFlashAlpha << "\n";
    std::cout << "C_CSPlayerPawn::m_bIsDefusing         = 0x" << m_bIsDefusing << "\n";

    std::cout << std::dec;

    CS2Dumper::Cleanup();

    return 0;
}