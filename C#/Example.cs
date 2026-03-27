using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;


class Program
{
    static uint GetPID(string procName)
    {
        foreach (var p in Process.GetProcessesByName(
            Path.GetFileNameWithoutExtension(procName)))
            return (uint)p.Id;
        return 0;
    }

    static void Main(string[] args)
    {
        string configPath = args.Length > 0 ? args[0] : "config.json";
        if (!File.Exists(configPath)) { Console.WriteLine("config.json not found"); return; }

        var root = JsonSerializer.Deserialize<CS2Dumper.RootConfig>(File.ReadAllText(configPath));
        if (root == null) return;

        uint pid = GetPID("cs2.exe");
        if (pid == 0 || !CS2Dumper.Setup(pid, root.modules))
        {
            Console.WriteLine("Failed to attach to cs2.exe");
            return;
        }

        CS2Dumper.Dump();

        Console.WriteLine("\n=== Global offsets ===");
        Console.WriteLine($"dwEntityList            = 0x{CS2Dumper.GetOffset("dwEntityList"):X}");
        Console.WriteLine($"dwLocalPlayerController = 0x{CS2Dumper.GetOffset("dwLocalPlayerController"):X}");
        Console.WriteLine($"dwLocalPlayerPawn       = 0x{CS2Dumper.GetOffset("dwLocalPlayerPawn"):X}");
        Console.WriteLine($"dwViewMatrix            = 0x{CS2Dumper.GetOffset("dwViewMatrix"):X}");
        Console.WriteLine($"dwCSGOInput             = 0x{CS2Dumper.GetOffset("dwCSGOInput"):X}");
        Console.WriteLine($"dwGameRules             = 0x{CS2Dumper.GetOffset("dwGameRules"):X}");
        Console.WriteLine($"dwGlowManager           = 0x{CS2Dumper.GetOffset("dwGlowManager"):X}");
        Console.WriteLine($"dwPlantedC4             = 0x{CS2Dumper.GetOffset("dwPlantedC4"):X}");
        Console.WriteLine($"dwBuildNumber           = 0x{CS2Dumper.GetOffset("dwBuildNumber"):X}");
        Console.WriteLine($"dwNetworkGameClient     = 0x{CS2Dumper.GetOffset("dwNetworkGameClient"):X}");
        Console.WriteLine($"dwInputSystem           = 0x{CS2Dumper.GetOffset("dwInputSystem"):X}");

        Console.WriteLine("\n=== Schema offsets ===");
        Console.WriteLine($"C_BaseEntity::m_iTeamNum              = 0x{CS2Dumper.GetSchema("client.dll", "C_BaseEntity", "m_iTeamNum"):X}");
        Console.WriteLine($"C_BaseEntity::m_iHealth               = 0x{CS2Dumper.GetSchema("client.dll", "C_BaseEntity", "m_iHealth"):X}");
        Console.WriteLine($"C_BaseEntity::m_lifeState             = 0x{CS2Dumper.GetSchema("client.dll", "C_BaseEntity", "m_lifeState"):X}");
        Console.WriteLine($"CGameSceneNode::m_vecOrigin           = 0x{CS2Dumper.GetSchema("client.dll", "CGameSceneNode", "m_vecOrigin"):X}");
        Console.WriteLine($"CCSPlayerController::m_hPlayerPawn    = 0x{CS2Dumper.GetSchema("client.dll", "CCSPlayerController", "m_hPlayerPawn"):X}");
        Console.WriteLine($"C_CSPlayerPawn::m_iShotsFired         = 0x{CS2Dumper.GetSchema("client.dll", "C_CSPlayerPawn", "m_iShotsFired"):X}");
        Console.WriteLine($"C_BaseEntity::m_fFlags                = 0x{CS2Dumper.GetSchema("client.dll", "C_BaseEntity", "m_fFlags"):X}");
        Console.WriteLine($"C_BaseEntity::m_vecVelocity           = 0x{CS2Dumper.GetSchema("client.dll", "C_BaseEntity", "m_vecVelocity"):X}");
        Console.WriteLine($"C_CSPlayerPawnBase::m_flFlashMaxAlpha = 0x{CS2Dumper.GetSchema("client.dll", "C_CSPlayerPawnBase", "m_flFlashMaxAlpha"):X}");
        Console.WriteLine($"C_CSPlayerPawn::m_bIsDefusing         = 0x{CS2Dumper.GetSchema("client.dll", "C_CSPlayerPawn", "m_bIsDefusing"):X}");

        CS2Dumper.Cleanup();
    }
}
