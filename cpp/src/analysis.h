#pragma once

#include <algorithm>
#include <cstdint>
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
};

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

        report.changes["registry"]  = snapshot_registry();
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

        std::error_code ec;
        if (!fs::exists(before, ec))
            return {"Bestandsvergelijking", {"Voor-map niet gevonden: " + before.string()}};
        if (!fs::exists(after, ec))
            return {"Bestandsvergelijking", {"Na-map niet gevonden: " + after.string()}};

        using FileInfo = std::pair<uintmax_t, fs::file_time_type>;
        std::map<std::string, FileInfo> before_map, after_map;

        auto collect = [](const fs::path& root, std::map<std::string, FileInfo>& out) {
            std::error_code ec2;
            for (const auto& entry : fs::recursive_directory_iterator(
                    root, fs::directory_options::skip_permission_denied, ec2)) {
                if (entry.is_regular_file(ec2)) {
                    const std::string rel = fs::relative(entry.path(), root, ec2).string();
                    if (!rel.empty())
                        out[rel] = {entry.file_size(ec2), entry.last_write_time(ec2)};
                }
            }
        };

        collect(before, before_map);
        collect(after,  after_map);

        std::vector<std::string> added, removed, modified;
        for (const auto& [path, info] : after_map) {
            auto it = before_map.find(path);
            if (it == before_map.end())
                added.push_back("+ " + path);
            else if (it->second != info)
                modified.push_back("~ " + path);
        }
        for (const auto& [path, info] : before_map) {
            if (after_map.find(path) == after_map.end())
                removed.push_back("- " + path);
        }

        constexpr std::size_t MAX_DISPLAY = 30;
        std::vector<std::string> items;
        items.push_back("Toegevoegd:  " + std::to_string(added.size()));
        items.push_back("Gewijzigd:   " + std::to_string(modified.size()));
        items.push_back("Verwijderd:  " + std::to_string(removed.size()));

        auto append = [&](const std::vector<std::string>& list) {
            for (std::size_t i = 0; i < std::min(list.size(), MAX_DISPLAY); ++i)
                items.push_back(list[i]);
            if (list.size() > MAX_DISPLAY)
                items.push_back("  ... en nog " + std::to_string(list.size() - MAX_DISPLAY) + " meer");
        };
        append(added);
        append(modified);
        append(removed);

        return {"Bestandsvergelijking: " + before.filename().string()
                + " vs " + after.filename().string(), items};
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
