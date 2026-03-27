using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public static class CS2Dumper
{
    public record SchemaField(string Name, string Type, int Offset);
    public record SchemaClass(string Name, Dictionary<string, SchemaField> Fields);

    public class PatternConfig
    {
        public string name { get; set; } = "";
        public string sig { get; set; } = "";
        public int offset { get; set; }
        public int size { get; set; }
        public bool rip { get; set; }
        public int read_size { get; set; } = 4;
        public string? sub_name { get; set; }
        public string? sub_sig { get; set; }
        public int sub_offset { get; set; }
    }

    public class ModuleConfig
    {
        public string name { get; set; } = "";
        public List<PatternConfig> patterns { get; set; } = new();
    }

    public class RootConfig
    {
        public List<ModuleConfig> modules { get; set; } = new();
    }

    public static Func<IntPtr, ulong, byte[], bool> ReadFn =
        (hProc, addr, buf) => ReadProcessMemory(hProc, addr, buf, (nuint)buf.Length, out _);

    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr hProc, ulong addr, byte[] buf, nuint size, out nuint read);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    private class ModuleData
    {
        public ulong Base;
        public uint Size;
        public byte[] Buffer = Array.Empty<byte>();
        public Dictionary<string, ulong> Offsets = new();
    }

    private static readonly Dictionary<string, ModuleData> s_modules = new();
    private static readonly Dictionary<string, ModuleConfig> s_modConfigs = new();
    private static readonly Dictionary<string, Dictionary<string, SchemaClass>> s_schemaDb = new();
    private static IntPtr s_hProc = IntPtr.Zero;

    private static T Read<T>(ulong addr) where T : struct
    {
        byte[] buf = new byte[Marshal.SizeOf<T>()];
        ReadFn(s_hProc, addr, buf);
        GCHandle h = GCHandle.Alloc(buf, GCHandleType.Pinned);
        T val = Marshal.PtrToStructure<T>(h.AddrOfPinnedObject());
        h.Free();
        return val;
    }

    private static string ReadString(ulong addr)
    {
        if (addr == 0) return "";
        byte[] buf = new byte[255];
        ReadFn(s_hProc, addr, buf);
        int end = Array.IndexOf(buf, (byte)0);
        return Encoding.ASCII.GetString(buf, 0, end < 0 ? buf.Length : end);
    }

    private static int FindPattern(byte[] buf, string pattern)
    {
        var tokens = pattern.Split(' ');
        int[] bytes = new int[tokens.Length];
        for (int i = 0; i < tokens.Length; i++)
            bytes[i] = (tokens[i] == "?" || tokens[i] == "??") ? -1 : Convert.ToInt32(tokens[i], 16);

        for (int i = 0; i <= buf.Length - bytes.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < bytes.Length; j++)
                if (bytes[j] != -1 && buf[i + j] != (byte)bytes[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    private static void ParseUtlTsHash(ulong hashAddr, string scopeName)
    {
        int blocksAllocated = Read<int>(hashAddr + 0x0C);
        if (blocksAllocated <= 0 || blocksAllocated > 100_000) return;

        var seen = new HashSet<ulong>();
        int found = 0;

        for (int b = 0; b < 256 && found < blocksAllocated; b++)
        {
            ulong bucket = hashAddr + 0x60 + (ulong)(b * 0x18);
            ulong nodePtr = Read<ulong>(bucket + 0x10);

            while (nodePtr > 0x10000 && nodePtr < 0x7FFFFFFFFFFFUL)
            {
                if (!seen.Add(nodePtr)) break;

                ulong data = Read<ulong>(nodePtr + 0x10);
                ulong next = Read<ulong>(nodePtr + 0x08);

                if (data > 0x10000)
                {
                    string className = ReadString(Read<ulong>(data + 0x8));
                    string dllName = ReadString(Read<ulong>(data + 0x10));
                    if (!string.IsNullOrEmpty(dllName)) dllName += ".dll";

                    string key = string.IsNullOrEmpty(dllName) ? scopeName : dllName;

                    if (!string.IsNullOrEmpty(className))
                    {
                        var fields = new Dictionary<string, SchemaField>();
                        short fCount = Read<short>(data + 0x1C);
                        ulong fieldsPtr = Read<ulong>(data + 0x28);

                        if (fCount > 0 && fCount < 4096 && fieldsPtr > 0x10000)
                        {
                            for (int k = 0; k < fCount; k++)
                            {
                                ulong fAddr = fieldsPtr + (ulong)(k * 0x20);
                                string fName = ReadString(Read<ulong>(fAddr + 0x00));
                                int fOffset = Read<int>(fAddr + 0x10);
                                ulong tPtr = Read<ulong>(fAddr + 0x08);
                                string fType = tPtr > 0x10000 ? ReadString(Read<ulong>(tPtr + 0x8)) : "unknown";
                                if (!string.IsNullOrEmpty(fName))
                                    fields[fName] = new SchemaField(fName, fType, fOffset);
                            }
                        }

                        if (!s_schemaDb.ContainsKey(key))
                            s_schemaDb[key] = new Dictionary<string, SchemaClass>();
                        s_schemaDb[key][className] = new SchemaClass(className, fields);
                        found++;
                    }
                }
                nodePtr = next;
            }
        }
    }

    public static bool Setup(uint pid, List<ModuleConfig> configs)
    {
        s_hProc = OpenProcess(0x1F0FFF, false, pid);
        if (s_hProc == IntPtr.Zero) return false;

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id != (int)pid) continue;
                foreach (ProcessModule pm in proc.Modules)
                {
                    foreach (var cfg in configs)
                    {
                        if (!pm.ModuleName.Equals(cfg.name, StringComparison.OrdinalIgnoreCase)) continue;
                        var mod = new ModuleData
                        {
                            Base = (ulong)(long)pm.BaseAddress,
                            Size = (uint)pm.ModuleMemorySize,
                        };
                        mod.Buffer = new byte[mod.Size];
                        ReadFn(s_hProc, mod.Base, mod.Buffer);
                        s_modules[cfg.name] = mod;
                        s_modConfigs[cfg.name] = cfg;
                        Console.WriteLine($"[CS2Dumper] Loaded: {cfg.name} @ 0x{mod.Base:X}");
                    }
                }
            }
            catch { }
        }

        return s_modules.Count > 0;
    }

    public static void Cleanup()
    {
        if (s_hProc != IntPtr.Zero) { CloseHandle(s_hProc); s_hProc = IntPtr.Zero; }
        s_modules.Clear();
        s_modConfigs.Clear();
        s_schemaDb.Clear();
    }

    public static void Dump()
    {
        DumpGlobalOffsets();
        DumpSchemas();
    }

    private static void DumpGlobalOffsets()
    {
        foreach (var (name, mod) in s_modules)
        {
            foreach (var p in s_modConfigs[name].patterns)
            {
                int off = FindPattern(mod.Buffer, p.sig);
                if (off < 0) continue;

                ulong val;
                if (p.rip)
                {
                    int rel = BitConverter.ToInt32(mod.Buffer, off + p.offset);
                    val = (ulong)(off + p.size + rel);
                }
                else
                {
                    val = p.read_size == 1
                        ? mod.Buffer[off + p.offset]
                        : (ulong)BitConverter.ToUInt32(mod.Buffer, off + p.offset);
                }
                mod.Offsets[p.name] = val;

                if (string.IsNullOrEmpty(p.sub_sig)) continue;
                int subOff = FindPattern(mod.Buffer, p.sub_sig!);
                if (subOff < 0) continue;

                ulong delta = BitConverter.ToUInt32(mod.Buffer, subOff + p.sub_offset);
                mod.Offsets[p.sub_name!] = val + delta;
            }
        }
    }

    private static void DumpSchemas()
    {
        if (!s_modules.TryGetValue("schemasystem.dll", out var ssMod)) return;
        if (!ssMod.Offsets.TryGetValue("dwSchemaSystem", out ulong schOff)) return;

        ulong sysInst = ssMod.Base + schOff;
        int count = Read<int>(sysInst + 0x190);
        ulong scopeArr = Read<ulong>(sysInst + 0x198);
        int regCount = Read<int>(sysInst + 0x280);

        Console.WriteLine($"[CS2Dumper] SchemaSystem: count={count} reg={regCount} arr=0x{scopeArr:X}");

        if (count <= 0 || count > 64 || scopeArr < 0x10000 || scopeArr > 0x7FFFFFFFFFFFUL) return;

        for (int i = 0; i < count; i++)
        {
            ulong scopePtr = Read<ulong>(scopeArr + (ulong)(i * 8));
            if (scopePtr < 0x10000 || scopePtr > 0x7FFFFFFFFFFFUL) continue;

            string scopeName = ReadString(scopePtr + 0x8);
            Console.WriteLine($"[CS2Dumper] scope[{i}] = {scopeName}");
            ParseUtlTsHash(scopePtr + 0x0560, scopeName);
        }
    }

    public static ulong GetOffset(string name)
    {
        foreach (var (_, mod) in s_modules)
            if (mod.Offsets.TryGetValue(name, out ulong val))
                return val;
        return 0;
    }

    public static ulong GetSchema(string module, string className, string fieldName)
    {
        if (!s_schemaDb.TryGetValue(module, out var classes)) return 0;
        if (!classes.TryGetValue(className, out var cls)) return 0;
        if (!cls.Fields.TryGetValue(fieldName, out var field)) return 0;
        return (ulong)(uint)field.Offset;
    }

    public static Dictionary<string, SchemaClass> GetSchemaModule(string module)
    {
        s_schemaDb.TryGetValue(module, out var result);
        return result ?? new();
    }
}
