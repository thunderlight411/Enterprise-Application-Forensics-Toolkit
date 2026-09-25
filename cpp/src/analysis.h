#pragma once

#include <algorithm>
#include <cstdint>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

struct ChangeSummary {
    std::string description;
    std::vector<std::string> items;
    // Present only for snapshot comparisons; omitted for other analyses.
    std::optional<bool> complete;
};

template<class Map>
struct SnapshotResult {
    Map values;
    std::vector<std::string> errors;
    bool complete() const { return errors.empty(); }
};

inline ChangeSummary incomplete_comparison(const std::string& label,
        const std::vector<std::string>& before, const std::vector<std::string>& after) {
    ChangeSummary result{label + " (onvolledig)",
        {"Vergelijking overgeslagen: onvolledige snapshot; wijzigingen zijn niet betrouwbaar vast te stellen."}, false};
    for (const auto& error : before) result.items.push_back("Voor-snapshot: " + error);
    for (const auto& error : after) result.items.push_back("Na-snapshot: " + error);
    return result;
}

using FileMap = std::map<std::string, std::pair<uintmax_t, fs::file_time_type>>;
using FileSnapshot = SnapshotResult<FileMap>;

inline FileSnapshot take_filesystem_snapshot(const fs::path& root) {
    FileSnapshot out;
    auto record_error = [&](const fs::path& path, const char* operation, const std::error_code& ec) {
        out.errors.push_back(path.u8string() + " [" + operation + ", code " +
                             std::to_string(ec.value()) + "]: " + ec.message());
    };
    // Separate iterators let an inaccessible child fail without losing its siblings.
    std::vector<fs::path> pending{root};
    while (!pending.empty()) {
        const fs::path dir = pending.back();
        pending.pop_back();
        std::error_code ec;
        fs::directory_iterator it(dir, ec), end;
        if (ec) { record_error(dir, "open directory", ec); continue; }
        while (it != end) {
            const auto entry = *it;
            const auto link_status = entry.symlink_status(ec);
            if (ec) {
                record_error(entry.path(), "symlink status", ec);
            } else {
                const auto status = entry.status(ec);
                if (ec) {
                    record_error(entry.path(), "status", ec);
                } else if (fs::is_directory(status)) {
                    if (!fs::is_symlink(link_status)) pending.push_back(entry.path());
                } else if (fs::is_regular_file(status)) {
                    const auto size = entry.file_size(ec);
                    if (ec) {
                        record_error(entry.path(), "file size", ec);
                    } else {
                        const auto time = entry.last_write_time(ec);
                        if (ec) record_error(entry.path(), "last write time", ec);
                        else out.values[entry.path().lexically_relative(root).u8string()] = {size, time};
                    }
                }
            }
            it.increment(ec);
            if (ec) { record_error(dir, "enumerate directory", ec); break; }
        }
    }
    return out;
}

inline ChangeSummary compare_filesystem_snapshots(
        const FileMap& before, const FileMap& after, const std::string& label = "") {
    std::vector<std::string> added, removed, modified;
    for (const auto& [path, info] : after) {
        auto it = before.find(path);
        if (it == before.end())
            added.push_back("+ " + path);
        else if (it->second != info)
            modified.push_back("~ " + path);
    }
    for (const auto& [path, info] : before) {
        if (after.find(path) == after.end())
            removed.push_back("- " + path);
    }

    std::vector<std::string> items;
    items.push_back("Toegevoegd:  " + std::to_string(added.size()));
    items.push_back("Gewijzigd:   " + std::to_string(modified.size()));
    items.push_back("Verwijderd:  " + std::to_string(removed.size()));
    items.insert(items.end(), added.begin(), added.end());
    items.insert(items.end(), modified.begin(), modified.end());
    items.insert(items.end(), removed.begin(), removed.end());

    return {label.empty() ? "Bestandsvergelijking" : "Bestandsvergelijking: " + label, items};
}

inline ChangeSummary compare_filesystem_snapshot_results(
        const FileSnapshot& before, const FileSnapshot& after, const std::string& label = "") {
    if (!before.complete() || !after.complete())
        return incomplete_comparison("Bestandsvergelijking: " + label, before.errors, after.errors);
    auto result = compare_filesystem_snapshots(before.values, after.values, label);
    result.complete = true;
    return result;
}

// ---------------------------------------------------------------------------
// Registry snapshot (Windows only)
// ---------------------------------------------------------------------------
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// Preserve evidence independently of its (potentially abbreviated) display text.
struct RegistryValue {
    DWORD type = REG_NONE;
    std::vector<BYTE> data;

    bool operator==(const RegistryValue& other) const {
        return type == other.type && data == other.data;
    }
    bool operator!=(const RegistryValue& other) const {
        return !(*this == other);
    }
};

using RegMap = std::map<std::string, RegistryValue>;
using RegistrySnapshot = SnapshotResult<RegMap>;

inline std::string reg_wcs_to_utf8(const wchar_t* wcs, int len = -1) {
    if (!wcs || len == 0) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, wcs, len, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string r(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wcs, len, r.data(), size, nullptr, nullptr);
    if (!r.empty() && r.back() == '\0') r.pop_back();
    return r;
}

inline std::string reg_value_repr(DWORD type, const BYTE* data, DWORD len) {
    switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            return reg_wcs_to_utf8(reinterpret_cast<const wchar_t*>(data),
                                   static_cast<int>(len / sizeof(wchar_t)));
        case REG_DWORD: {
            if (len < 4) return "?";
            DWORD v = 0; std::memcpy(&v, data, 4);
            return std::to_string(v);
        }
        case REG_QWORD: {
            if (len < 8) return "?";
            unsigned long long v = 0; std::memcpy(&v, data, 8);
            return std::to_string(v);
        }
        case REG_MULTI_SZ: {
            std::string result;
            const wchar_t* p   = reinterpret_cast<const wchar_t*>(data);
            const wchar_t* end = p + len / sizeof(wchar_t);
            while (p < end && *p) {
                if (!result.empty()) result += '|';
                const wchar_t* q = p;
                while (q < end && *q) ++q;
                result += reg_wcs_to_utf8(p, static_cast<int>(q - p));
                p = q + 1;
            }
            return result;
        }
        case REG_BINARY: {
            std::ostringstream hex;
            hex << std::hex << std::uppercase;
            for (DWORD i = 0; i < len && i < 16; ++i)
                hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i])
                    << (i + 1 < len && i + 1 < 16 ? " " : "");
            if (len > 16) hex << "...";
            return hex.str();
        }
        default:
            return "(type " + std::to_string(type) + ")";
    }
}

inline void reg_enumerate_impl(HKEY hRoot, const std::wstring& key_path, RegistrySnapshot& out,
                                std::vector<wchar_t>& name_buf, std::vector<BYTE>& data_buf,
                                const std::string& root_label = "HKLM") {
    const std::string utf8_path = root_label + "\\" + reg_wcs_to_utf8(key_path.c_str());
    auto record_error = [&](const std::string& operation, LONG code) {
        out.errors.push_back(utf8_path + " [" + operation + "]: Windows error " + std::to_string(code));
    };
    HKEY hKey = nullptr;
    const LONG opened = RegOpenKeyExW(hRoot, key_path.c_str(), 0, KEY_READ, &hKey);
    if (opened != ERROR_SUCCESS) {
        record_error("RegOpenKeyExW", opened);
        return;
    }
    struct KeyGuard {
        HKEY key;
        ~KeyGuard() { RegCloseKey(key); }
    } guard{hKey};

    for (DWORD idx = 0; ; ++idx) {
        DWORD name_len = 0, data_len = 0;
        DWORD type = 0;
        LONG ret = ERROR_MORE_DATA;
        // Retry the SAME index after growth; bound retries for continuously changing values.
        for (int attempt = 0; attempt < 8; ++attempt) {
            name_len = static_cast<DWORD>(name_buf.size());
            data_len = static_cast<DWORD>(data_buf.size());
            ret = RegEnumValueW(hKey, idx, name_buf.data(), &name_len,
                                nullptr, &type, data_buf.data(), &data_len);
            if (ret != ERROR_MORE_DATA) break;
            DWORD max_name = 0, max_data = 0;
            const LONG queried = RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, &max_name, &max_data, nullptr, nullptr);
            if (queried != ERROR_SUCCESS) { ret = queried; break; }
            if (name_buf.size() <= max_name) name_buf.resize(static_cast<std::size_t>(max_name) + 1);
            const auto required = (std::max)(max_data, data_len);
            if (data_buf.size() < required) data_buf.resize(required);
        }
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) {
            record_error("RegEnumValueW index " + std::to_string(idx), ret);
            break;
        }
        out.values[utf8_path + "\\" + reg_wcs_to_utf8(name_buf.data(), static_cast<int>(name_len))]
            = RegistryValue{type, std::vector<BYTE>(data_buf.begin(), data_buf.begin() + data_len)};
    }

    static constexpr DWORD KEY_BUF = 256;
    std::vector<wchar_t> sub(KEY_BUF);
    for (DWORD idx = 0; ; ++idx) {
        DWORD sub_len = KEY_BUF;
        LONG  ret = RegEnumKeyExW(hKey, idx, sub.data(), &sub_len,
                                   nullptr, nullptr, nullptr, nullptr);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) {
            record_error("RegEnumKeyExW index " + std::to_string(idx), ret);
            break;
        }
        reg_enumerate_impl(hRoot, key_path + L"\\" + sub.data(), out, name_buf, data_buf, root_label);
    }
}

inline RegistrySnapshot take_registry_snapshot() {
    RegistrySnapshot out;
    std::vector<wchar_t> name_buf(16384);
    std::vector<BYTE>    data_buf(65536);
    reg_enumerate_impl(HKEY_LOCAL_MACHINE, L"SOFTWARE", out, name_buf, data_buf);
    reg_enumerate_impl(HKEY_LOCAL_MACHINE, L"SYSTEM",   out, name_buf, data_buf);
    return out;
}

inline ChangeSummary compare_registry_snapshots(
        const RegMap& before, const RegMap& after, const std::string& label = "") {
    std::vector<std::string> added, removed, modified;
    for (const auto& [path, val] : after) {
        auto it = before.find(path);
        if (it == before.end())
            added.push_back("+ " + path);
        else if (it->second != val)
            modified.push_back("~ " + path);
    }
    for (const auto& [path, val] : before) {
        if (after.find(path) == after.end())
            removed.push_back("- " + path);
    }

    std::vector<std::string> items;
    items.push_back("Toegevoegd:  " + std::to_string(added.size()));
    items.push_back("Gewijzigd:   " + std::to_string(modified.size()));
    items.push_back("Verwijderd:  " + std::to_string(removed.size()));
    items.insert(items.end(), added.begin(), added.end());
    items.insert(items.end(), modified.begin(), modified.end());
    items.insert(items.end(), removed.begin(), removed.end());

    return {label.empty() ? "Registervergelijking HKLM" : "Registervergelijking: " + label, items};
}

struct Snapshot {
    FileSnapshot files;
    RegistrySnapshot registry;
};

inline Snapshot take_full_snapshot(const fs::path& dir) {
    return {take_filesystem_snapshot(dir), take_registry_snapshot()};
}

#else
using RegMap = std::map<std::string, std::string>;
using RegistrySnapshot = SnapshotResult<RegMap>;
struct Snapshot { FileSnapshot files; RegistrySnapshot registry; };
inline Snapshot take_full_snapshot(const fs::path& dir) {
    return {take_filesystem_snapshot(dir), {{}, {"Registermeting niet beschikbaar op dit platform"}}};
}
inline ChangeSummary compare_registry_snapshots(
        const RegMap&, const RegMap&, const std::string& label = "") {
    return {label.empty() ? "Registervergelijking" : label, {"Niet beschikbaar op dit platform"}};
}
#endif // _WIN32

inline ChangeSummary compare_registry_snapshot_results(
        const RegistrySnapshot& before, const RegistrySnapshot& after, const std::string& label = "") {
    if (!before.complete() || !after.complete())
        return incomplete_comparison("Registervergelijking: " + label, before.errors, after.errors);
    auto result = compare_registry_snapshots(before.values, after.values, label);
    result.complete = true;
    return result;
}

struct AnalysisReport {
    std::string installer;
    std::map<std::string, ChangeSummary> changes;
    std::vector<std::string> dependencies;
    std::vector<std::string> required_rights;
    std::string intune_msix_recommendation = "unknown";
};

struct Options {
    std::optional<fs::path> installer;
    std::optional<fs::path> procmon;
    std::optional<fs::path> procdump;
    std::optional<fs::path> fs_before;
    std::optional<fs::path> fs_after;
    fs::path output = "report.json";
    bool verbose = false;
};

inline std::string json_escape(const std::string& value) {
    std::ostringstream escaped;
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': escaped << "\\\\"; break;
            case '"':  escaped << "\\\""; break;
            case '\b': escaped << "\\b";  break;
            case '\f': escaped << "\\f";  break;
            case '\n': escaped << "\\n";  break;
            case '\r': escaped << "\\r";  break;
            case '\t': escaped << "\\t";  break;
            default:
                if (ch < 0x20) {
                    escaped << "\\u"
                            << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                            << static_cast<int>(ch)
                            << std::dec << std::nouppercase << std::setfill(' ');
                } else {
                    escaped << static_cast<char>(ch);
                }
        }
    }
    return escaped.str();
}

inline void write_string_array(std::ostream& out, const std::vector<std::string>& values, int indent) {
    const std::string pad(indent, ' ');
    out << "[";
    if (!values.empty()) {
        out << "\n";
        for (std::size_t i = 0; i < values.size(); ++i) {
            out << pad << "  \"" << json_escape(values[i]) << "\"";
            if (i + 1 < values.size()) out << ",";
            out << "\n";
        }
        out << pad;
    }
    out << "]";
}

inline std::string to_json(const AnalysisReport& report) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"installer\": \"" << json_escape(report.installer) << "\",\n";
    out << "  \"changes\": {\n";
    std::size_t change_index = 0;
    for (const auto& [name, summary] : report.changes) {
        out << "    \"" << json_escape(name) << "\": {\n";
        out << "      \"description\": \"" << json_escape(summary.description) << "\",\n";
        if (summary.complete.has_value())
            out << "      \"complete\": " << (*summary.complete ? "true" : "false") << ",\n";
        out << "      \"items\": ";
        write_string_array(out, summary.items, 6);
        out << "\n    }";
        if (++change_index < report.changes.size()) out << ",";
        out << "\n";
    }
    out << "  },\n";
    out << "  \"dependencies\": ";
    write_string_array(out, report.dependencies, 2);
    out << ",\n";
    out << "  \"required_rights\": ";
    write_string_array(out, report.required_rights, 2);
    out << ",\n";
    out << "  \"intune_msix_recommendation\": \""
        << json_escape(report.intune_msix_recommendation) << "\"\n";
    out << "}\n";
    return out.str();
}

inline std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> fields;
    std::string field;
    bool in_quotes = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '"') {
            if (in_quotes && i + 1 < line.size() && line[i + 1] == '"') {
                field.push_back('"');
                ++i;
            } else {
                in_quotes = !in_quotes;
            }
        } else if (ch == ',' && !in_quotes) {
            fields.push_back(field);
            field.clear();
        } else {
            field.push_back(ch);
        }
    }
    fields.push_back(field);
    return fields;
}

inline std::string trim(std::string value) {
    const auto first = std::find_if_not(value.begin(), value.end(),
        [](unsigned char ch) { return std::isspace(ch) != 0; });
    const auto last = std::find_if_not(value.rbegin(), value.rend(),
        [](unsigned char ch) { return std::isspace(ch) != 0; }).base();
    if (first >= last) return "";
    return std::string(first, last);
}

inline void strip_utf8_bom(std::string& value) {
    if (value.size() >= 3 &&
        static_cast<unsigned char>(value[0]) == 0xEF &&
        static_cast<unsigned char>(value[1]) == 0xBB &&
        static_cast<unsigned char>(value[2]) == 0xBF) {
        value.erase(0, 3);
    }
}

inline std::vector<std::pair<std::string, int>> top_five(const std::unordered_map<std::string, int>& counts) {
    std::vector<std::pair<std::string, int>> ordered(counts.begin(), counts.end());
    std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
        if (left.second != right.second) return left.second > right.second;
        return left.first < right.first;
    });
    if (ordered.size() > 5) ordered.resize(5);
    return ordered;
}

class ForensicsToolkitCpp {
public:
    explicit ForensicsToolkitCpp(Options options) : options_(std::move(options)) {}

    AnalysisReport run_analysis() const {
        AnalysisReport report;
        report.installer = options_.installer ? options_.installer->string() : "";

        if (options_.procmon)
            report.changes["procmon"] = analyze_procmon_file(*options_.procmon);
        else
            report.changes["procmon"] = analyze_procmon();

        if (options_.procdump)
            report.changes["procdump"] = analyze_procdump_file(*options_.procdump);

        if (options_.fs_before && options_.fs_after)
            report.changes["files"] = snapshot_files();
        report.dependencies         = scan_dependencies();
        report.required_rights      = evaluate_required_rights();
        report.intune_msix_recommendation = evaluate_intune_msix();
        return report;
    }

private:
    Options options_;

    ChangeSummary analyze_procmon() const {
        return {"ProcMon-installatieanalyse", {"placeholder: importeer en parse ProcMon CSV of ETL"}};
    }

    ChangeSummary analyze_procmon_file(const fs::path& procmon_path) const {
        if (!fs::exists(procmon_path))
            return {"ProcMon-analyse", {"Bestand niet gevonden: " + procmon_path.string()}};

        auto [operations, top_paths, registry_ops] = parse_procmon_csv(procmon_path);
        std::vector<std::string> items;

        if (!operations.empty()) {
            items.push_back("Top ProcMon-operaties:");
            for (const auto& [operation, count] : top_five(operations))
                items.push_back(operation + ": " + std::to_string(count));
        }
        if (!registry_ops.empty()) {
            items.push_back("Top registerbewerkingen:");
            for (const auto& [operation, count] : top_five(registry_ops))
                items.push_back(operation + ": " + std::to_string(count));
        }
        if (!top_paths.empty()) {
            items.push_back("Top paden opgenomen in ProcMon:");
            for (const auto& [path, count] : top_five(top_paths))
                items.push_back(path + ": " + std::to_string(count));
        }
        if (items.empty())
            items.push_back("Geen ProcMon-gegevens gevonden in CSV.");

        return {"ProcMon-analyse van " + procmon_path.filename().string(), items};
    }

    std::tuple<
        std::unordered_map<std::string, int>,
        std::unordered_map<std::string, int>,
        std::unordered_map<std::string, int>
    >
    parse_procmon_csv(const fs::path& procmon_path) const {
        std::unordered_map<std::string, int> operations, top_paths, registry_ops;
        std::ifstream input(procmon_path);
        std::string line;
        if (!std::getline(input, line)) return {operations, top_paths, registry_ops};

        strip_utf8_bom(line);
        const auto headers = parse_csv_line(line);
        std::unordered_map<std::string, std::size_t> header_index;
        for (std::size_t i = 0; i < headers.size(); ++i)
            header_index[trim(headers[i])] = i;

        const auto operation_it = header_index.find("Operation");
        const auto path_it      = header_index.find("Path");
        if (operation_it == header_index.end()) return {operations, top_paths, registry_ops};

        while (std::getline(input, line)) {
            const auto fields = parse_csv_line(line);
            const std::string operation = operation_it->second < fields.size()
                ? trim(fields[operation_it->second]) : "";
            const std::string path_value = path_it != header_index.end() && path_it->second < fields.size()
                ? trim(fields[path_it->second]) : "";

            operations[operation] += 1;
            if (!path_value.empty()) top_paths[path_value] += 1;
            if (operation.find("Reg") != std::string::npos ||
                operation.find("Registry") != std::string::npos)
                registry_ops[operation] += 1;
        }
        return {operations, top_paths, registry_ops};
    }

    ChangeSummary analyze_procdump_file(const fs::path& procdump_path) const {
        if (!fs::exists(procdump_path))
            return {"ProcDump-analyse", {"Bestand niet gevonden: " + procdump_path.string()}};

        std::string signature = "unknown";
        std::ifstream input(procdump_path, std::ios::binary);
        if (input) {
            char header[4] = {0, 0, 0, 0};
            input.read(header, sizeof(header));
            signature.assign(header, static_cast<std::size_t>(input.gcount()));
        } else {
            signature = "onleesbaar";
        }

        std::vector<std::string> items = {
            "ProcDump-bestand: " + procdump_path.filename().string(),
            "Grootte: " + std::to_string(fs::file_size(procdump_path)) + " bytes",
            "Signatuur: " + signature,
        };
        if (signature == "MDMP")
            items.push_back("Herkenning: Windows minidump-formaat");
        else if (procdump_path.extension() == ".dmp")
            items.push_back("Herkenning: mogelijk ProcDump dumpbestand");

        return {"ProcDump-analyse van " + procdump_path.filename().string(), items};
    }

    ChangeSummary snapshot_registry() const {
        return {"Registry snapshot en wijzigingen", {"placeholder: vergelijk voor/na registry snapshots"}};
    }

    ChangeSummary snapshot_files() const {
        const fs::path& before = *options_.fs_before;
        const fs::path& after  = *options_.fs_after;
        return compare_filesystem_snapshot_results(
            take_filesystem_snapshot(before),
            take_filesystem_snapshot(after),
            before.filename().string() + " vs " + after.filename().string());
    }

    std::vector<std::string> scan_dependencies() const {
        return {"placeholder: dependency scanning op PE/manifest/installer"};
    }

    std::vector<std::string> evaluate_required_rights() const {
        return {"placeholder: analyseer administrator of systeemrechten"};
    }

    std::string evaluate_intune_msix() const {
        return "placeholder: nog te implementeren";
    }
};
