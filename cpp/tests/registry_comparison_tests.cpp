#include "analysis.h"
#include <iostream>

#ifndef _WIN32
#error Registry comparison tests require Windows.
#endif

static int failures = 0;

static void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

static void expect_modified(const RegistryValue& before, const RegistryValue& after,
                            const char* message) {
    const std::string key = "HKLM\\SOFTWARE\\EAFTTest\\Value";
    const auto result = compare_registry_snapshots({{key, before}}, {{key, after}});
    expect(result.items == std::vector<std::string>{
        "Toegevoegd:  0", "Gewijzigd:   1", "Verwijderd:  0", "~ " + key}, message);
}

int main() {
    RegistryValue binary{REG_BINARY, std::vector<BYTE>(32, 0x41)};
    auto changed = binary;
    changed.data[16] = 0x42;
    expect_modified(binary, changed, "binary change after byte 16");

    auto longer = binary;
    longer.data.push_back(0x41);
    expect_modified(binary, longer, "binary length change after byte 16");

    expect_modified({REG_SZ, {'1', 0, 0, 0}}, {REG_DWORD, {1, 0, 0, 0}},
                    "same display text with different registry types");
    expect_modified({REG_SZ, {'A', 0, 0, 0}}, {REG_EXPAND_SZ, {'A', 0, 0, 0}},
                    "identical bytes with different registry types");
    expect_modified({REG_DWORD, {1, 0, 0, 0}}, {REG_QWORD, {1, 0, 0, 0, 0, 0, 0, 0}},
                    "DWORD and QWORD with same numeric value");
    expect_modified({REG_NONE, {1}}, {REG_NONE, {2}},
                    "data for types with no value formatter");

    // Both values previously formatted as A|B, despite different element boundaries.
    expect_modified({REG_MULTI_SZ, {'A', 0, '|', 0, 'B', 0, 0, 0, 0, 0}},
                    {REG_MULTI_SZ, {'A', 0, 0, 0, 'B', 0, 0, 0, 0, 0}},
                    "multi-string element boundaries");
    expect_modified({REG_BINARY, {}}, {REG_BINARY, {0}}, "empty versus one zero byte");

    const auto unchanged = compare_registry_snapshots({{"value", binary}}, {{"value", binary}});
    expect(unchanged.items == std::vector<std::string>{
        "Toegevoegd:  0", "Gewijzigd:   0", "Verwijderd:  0"}, "identical values");
    const auto empty = compare_registry_snapshots(
        {{"value", {REG_BINARY, {}}}}, {{"value", {REG_BINARY, {}}}});
    expect(empty.items == unchanged.items, "identical empty values");

    const auto added_removed = compare_registry_snapshots(
        {{"old", binary}}, {{"new", binary}});
    expect(added_removed.items == std::vector<std::string>{
        "Toegevoegd:  1", "Gewijzigd:   0", "Verwijderd:  1", "+ new", "- old"},
        "added and removed values retain report format");

    if (failures) return 1;
    std::cout << "All registry comparison regression checks passed.\n";
    return 0;
}
