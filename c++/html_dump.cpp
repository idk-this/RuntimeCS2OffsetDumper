#include <iostream>
#include <fstream>
#include <sstream>
#include <windows.h>
#include <TlHelp32.h>
#include <cctype>
#include <algorithm>
#include <map>
#include <set>
#include <vector>
#include "json.h"
#include "CS2Dumper.hpp"

using json = nlohmann::json;

struct ConsoleLogger : CS2Dumper::IDumperLogger {
    void Log(CS2Dumper::LogLevel level, const std::string& msg) override {
        const char* pfx[] = { "[DBG] ","[INF] ","[WRN] ","[ERR] " };
        std::cout << pfx[(int)level] << msg << "\n";
    }
};

DWORD GetPID(const std::string& procName) {
    PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    if (!Process32First(hSnap, &pe)) { CloseHandle(hSnap); return 0; }
    do {
        std::wstring wp(procName.begin(), procName.end());
        if (wp == pe.szExeFile) { CloseHandle(hSnap); return pe.th32ProcessID; }
    } while (Process32Next(hSnap, &pe));
    CloseHandle(hSnap);
    return 0;
}

static std::string ToHex(uintptr_t v) {
    if (!v) return "0x0";
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << v;
    return ss.str();
}

static std::string HE(const std::string& s) {
    std::string r; r.reserve(s.size());
    for (char c : s) {
        if (c == '&') r += "&amp;";
        else if (c == '<') r += "&lt;";
        else if (c == '>') r += "&gt;";
        else if (c == '"') r += "&quot;";
        else if (c == '\'') r += "&apos;";
        else r += c;
    }
    return r;
}

static std::string JSE(const std::string& s) {
    std::string r;
    for (char c : s) {
        if (c == '\'') r += "\\'";
        else if (c == '\\') r += "\\\\";
        else r += c;
    }
    return r;
}

static std::string Slug(const std::string& mod, const std::string& cls) {
    std::string r = mod + "__" + cls;
    for (char& c : r) if (!isalnum((unsigned char)c) && c != '_') c = '_';
    return r;
}

struct GlobalOff { std::string name, module; uintptr_t value; };
struct SchemaOff { std::string module, className, fieldName, type; uintptr_t value; };

static std::string BuildHTML(const std::vector<GlobalOff>& globals, const std::vector<SchemaOff>& schema) {
    std::map<std::string, std::map<std::string, std::vector<const SchemaOff*>>> idx;
    std::map<std::string, std::string> classToModule;
    std::set<std::string> modsWithClasses;

    for (auto& s : schema) {
        idx[s.module][s.className].push_back(&s);
        classToModule[s.className] = s.module;
        modsWithClasses.insert(s.module);
    }

    auto formatType = [&](const std::string& type) {
        if (type.empty() || type == "unk") return std::string("");
        std::string res = type;
        for (auto const& [name, mod] : classToModule) {
            size_t p = res.find(name);
            if (p != std::string::npos) {
                bool pre = (p == 0 || (!isalnum((unsigned char)res[p - 1]) && res[p - 1] != '_'));
                bool post = (p + name.size() == res.size() || (!isalnum((unsigned char)res[p + name.size()]) && res[p + name.size()] != '_'));
                if (pre && post) {
                    std::string link = "<span class='lnk' style='cursor:pointer;color:var(--primary);text-decoration:underline;' onclick=\"navCls('" + JSE(Slug(mod, name)) + "')\">" + HE(name) + "</span>";
                    res.replace(p, name.size(), link);
                    break;
                }
            }
        }
        return res;
        };

    std::ostringstream globRows;
    for (auto& g : globals) {
        std::string h = ToHex(g.value);
        std::string c = "CS2Dumper::GetOffset(\"" + g.name + "\")";
        globRows << "<tr><td>" << HE(g.name) << "</td><td>" << HE(g.module) << "</td><td class='c-hex'>" << HE(h) << "</td>"
            << "<td><div class='cg'>"
            << "<button class='icb' title='Copy Hex' onclick=\"" << HE("cp(this,'" + JSE(h) + "','Hex')") << "\"><svg viewBox='0 0 24 24'><path d='M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z'/></svg></button>"
            << "<button class='icb' title='Copy Call' onclick=\"" << HE("cp(this,'" + JSE(c) + "','Call')") << "\"><svg viewBox='0 0 24 24'><path d='M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z'/></svg></button>"
            << "</div></td></tr>";
    }

    std::ostringstream cards;
    std::vector<std::pair<std::string, std::string>> sorted;
    for (auto& [m, cls] : idx) for (auto& [c, _] : cls) sorted.push_back({ m, c });
    std::sort(sorted.begin(), sorted.end());

    for (auto& [m, c] : sorted) {
        std::string sid = Slug(m, c);
        cards << "<div class='card' id='card-" << HE(sid) << "' data-mod='" << HE(m) << "' data-cls='" << HE(c) << "'>"
            << "<div class='ch' onclick='tog2(this.parentElement)'><span class='ch-name'>" << HE(c) << "</span><span class='ch-mod'>" << HE(m) << "</span></div>"
            << "<div class='cb'><table class='ft'><thead><tr><th>Field</th><th>Type</th><th>Offset</th><th>Copy</th></tr></thead><tbody>";

        for (auto* f : idx[m][c]) {
            std::string h = ToHex(f->value);
            std::string call = "CS2Dumper::GetSchema(\"" + f->module + "\", \"" + f->className + "\", \"" + f->fieldName + "\")";
            std::string link = "?module=" + f->module + "&class=" + f->className + "&field=" + f->fieldName;

            cards << "<tr data-field='" << HE(f->fieldName) << "'><td>" << HE(f->fieldName) << "</td><td><span class='tb'>" << formatType(f->type) << "</span></td><td class='c-hex'>" << HE(h) << "</td>"
                << "<td><div class='cg'>"
                << "<button class='icb' title='Copy Hex' onclick=\"" << HE("cp(this,'" + JSE(h) + "','Hex')") << "\"><svg viewBox='0 0 24 24'><path d='M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z'/></svg></button>"
                << "<button class='icb' title='Copy Call' onclick=\"" << HE("cp(this,'" + JSE(call) + "','Call')") << "\"><svg viewBox='0 0 24 24'><path d='M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z'/></svg></button>"
                << "</div></td></tr>";
        }
        cards << "</tbody></table></div></div>";
    }

    std::ostringstream modChips;
    for (auto& m : modsWithClasses) {
        modChips << "<button class='chip' data-mod='" << HE(m) << "' onclick='filterMod(this)'>" << HE(m) << "</button>";
    }
    std::ostringstream nav;
    for (auto& [m, c] : sorted) {
        nav << "<div class='ni' onclick=\"navCls('" << JSE(Slug(m, c)) << "')\" data-cls='" << HE(c) << "'>" << HE(c) << "</div>";
    }

    std::ifstream t("dump_template.html");
    if (!t.is_open()) return "";
    std::string h((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());

    auto rep = [&](std::string k, std::string v) {
        size_t p = 0;
        while ((p = h.find(k, p)) != std::string::npos) { h.replace(p, k.length(), v); p += v.length(); }
        };

    rep("{{GLOBALS_ROWS}}", globRows.str());
    rep("{{SCHEMA_CARDS}}", cards.str());
    rep("{{CLASSES_NAV}}", nav.str());
    rep("{{ALL_MODS}}", modChips.str());
    rep("{{GLOBALS_COUNT}}", std::to_string(globals.size()));
    rep("{{TOTAL_CLASSES}}", std::to_string(sorted.size()));
    rep("{{TOTAL_FIELDS}}", std::to_string(schema.size()));

    return h;
}

int main() {
    static ConsoleLogger l;
    CS2Dumper::SetLogger(&l);
    std::ifstream f("config.json");
    if (!f.is_open()) return 1;
    json d = json::parse(f);
    std::vector<CS2Dumper::ModuleConfig> cfg;
    for (auto& m : d["modules"]) {
        CS2Dumper::ModuleConfig mc; mc.name = m["name"];
        for (auto& p : m["patterns"]) {
            CS2Dumper::Pattern pt; pt.name = p["name"]; pt.sig = p["sig"]; pt.offset = p["offset"];
            pt.size = p["size"]; pt.rip = p["rip"]; mc.patterns.push_back(pt);
        }
        cfg.push_back(mc);
    }
    DWORD pid = GetPID("cs2.exe");
    if (!pid || !CS2Dumper::Setup(pid, cfg)) return 1;
    CS2Dumper::Dump();

    std::vector<GlobalOff> go;
    for (auto& [mn, m] : CS2Dumper::GetModules())
        for (auto& [on, ov] : m.offsets) go.push_back({ on, mn, ov });

    std::vector<SchemaOff> so;
    for (auto& [mn, clsMap] : CS2Dumper::GetSchemaDB())
        for (auto& [cn, sc] : clsMap)
            for (auto& [fn, fld] : sc.fields) so.push_back({ mn, cn, fn, fld.type, (uintptr_t)fld.offset });

    std::string res = BuildHTML(go, so);
    std::ofstream out("cs2_dump.html");
    if (out.is_open()) out << res;
    CS2Dumper::Cleanup();
    return 0;
}
