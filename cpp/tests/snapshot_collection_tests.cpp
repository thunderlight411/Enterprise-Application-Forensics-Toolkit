#include "analysis.h"
#include <iostream>
#include <sddl.h>

// Restore the original ACL even when a test throws; only the isolated fixture is changed.
struct DenyRead {
    HKEY key;
    std::vector<BYTE> original;
    bool applied = false;
    explicit DenyRead(HKEY handle) : key(handle) {
        DWORD size = 0;
        if (RegGetKeySecurity(key, DACL_SECURITY_INFORMATION, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER)
            throw std::runtime_error("Cannot query fixture ACL size");
        original.resize(size);
        if (RegGetKeySecurity(key, DACL_SECURITY_INFORMATION, original.data(), &size) != ERROR_SUCCESS)
            throw std::runtime_error("Cannot save fixture ACL");
        PSECURITY_DESCRIPTOR denied = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(D;;KR;;;WD)",
                SDDL_REVISION_1, &denied, nullptr)) throw std::runtime_error("Cannot create test ACL");
        const LONG status = RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, denied);
        LocalFree(denied);
        if (status != ERROR_SUCCESS) throw std::runtime_error("Cannot set fixture ACL");
        applied = true;
    }
    ~DenyRead() {
        if (applied) RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, original.data());
    }
};

static int failures = 0;
static void expect(bool condition, const char* message) {
    if (!condition) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}

struct Fixtures {
    fs::path directory;
    std::wstring key_path;
    HKEY key = nullptr;
    Fixtures() {
        const auto suffix = std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
        directory = fs::temp_directory_path() / (L"EAFT-tests-" + suffix);
        key_path = L"Software\\EAFT-tests-" + suffix;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, key_path.c_str(), 0, nullptr,
                REG_OPTION_VOLATILE, KEY_ALL_ACCESS, nullptr, &key, nullptr) != ERROR_SUCCESS)
            throw std::runtime_error("Cannot create isolated registry fixture");
    }
    ~Fixtures() {
        if (key) RegCloseKey(key);
        RegDeleteTreeW(HKEY_CURRENT_USER, key_path.c_str());
        std::error_code ec;
        fs::remove_all(directory, ec);
    }
};

static void check_incomplete(const ChangeSummary& result, const char* phase) {
    expect(result.complete == false, "incomplete comparison is marked false");
    expect(result.items.size() == 2, "one warning plus the original read error");
    expect(result.items.back().find(phase) != std::string::npos, "error identifies snapshot phase");
    for (const auto& item : result.items) {
        expect(item.find("Verwijderd:") == std::string::npos, "no false removal count");
        expect(item.find("Toegevoegd:") == std::string::npos, "no false addition count");
        expect(item.find("- ") != 0 && item.find("+ ") != 0, "no unverified change paths");
    }
}

int main() {
    try {
        Fixtures fixture;
        fs::create_directories(fixture.directory / "child");
        { std::ofstream file(fixture.directory / "child" / "example.txt"); file << "hello"; }
        const auto files = take_filesystem_snapshot(fixture.directory);
        expect(files.complete() && files.values.size() == 1, "complete directory scan");
        expect(files.values.at((fs::path("child") / "example.txt").u8string()).first == 5, "file metadata retained");
        const auto missing = take_filesystem_snapshot(fixture.directory / "missing");
        expect(!missing.complete() && missing.values.empty(), "missing directory is not an empty successful scan");
        expect(missing.errors.front().find("missing") != std::string::npos, "error includes failed path");
        const auto not_directory = take_filesystem_snapshot(fixture.directory / "child" / "example.txt");
        expect(!not_directory.complete(), "file used as root reports an error");
        check_incomplete(compare_filesystem_snapshot_results(files, missing), "Na-snapshot");
        check_incomplete(compare_filesystem_snapshot_results(missing, files), "Voor-snapshot");
        expect(compare_filesystem_snapshot_results(files, files).complete == true, "complete files still compare");

        std::vector<BYTE> large(128 * 1024);
        for (std::size_t i = 0; i < large.size(); ++i) large[i] = static_cast<BYTE>(i % 251);
        expect(RegSetValueExW(fixture.key, L"large-value", 0, REG_BINARY, large.data(),
            static_cast<DWORD>(large.size())) == ERROR_SUCCESS, "write large fixture");
        const BYTE small[] = {7, 8, 9};
        expect(RegSetValueExW(fixture.key, L"small-value", 0, REG_BINARY, small, sizeof(small)) == ERROR_SUCCESS,
            "write small fixture");
        expect(RegSetValueExW(fixture.key, L"", 0, REG_BINARY, nullptr, 0) == ERROR_SUCCESS,
            "write empty default value");
        RegistrySnapshot registry;
        std::vector<wchar_t> names(2);
        std::vector<BYTE> data(4);
        reg_enumerate_impl(HKEY_CURRENT_USER, fixture.key_path, registry, names, data, "HKCU");
        const std::string prefix = "HKCU\\" + reg_wcs_to_utf8(fixture.key_path.c_str()) + "\\";
        expect(registry.complete() && registry.values.size() == 3, "resizing retries index without skipping values");
        expect(registry.values.at(prefix + "large-value") == RegistryValue{REG_BINARY, large},
            "all 128 KiB preserved with type");
        expect(registry.values.at(prefix).data.empty(), "empty default value preserved");
        expect(registry.values.at(prefix + "small-value").data == std::vector<BYTE>{7, 8, 9},
            "reused buffer stores only actual bytes");

        RegistrySnapshot unavailable;
        reg_enumerate_impl(HKEY_CURRENT_USER, fixture.key_path + L"\\missing", unavailable, names, data, "HKCU");
        expect(!unavailable.complete() && unavailable.errors.size() == 1, "registry open failure recorded");
        expect(unavailable.errors.front().find("HKCU\\") == 0, "diagnostic has correct hive");
        expect(unavailable.errors.front().find("RegOpenKeyExW") != std::string::npos, "diagnostic identifies operation");
        check_incomplete(compare_registry_snapshot_results(registry, unavailable), "Na-snapshot");
        check_incomplete(compare_registry_snapshot_results(unavailable, registry), "Voor-snapshot");
        expect(compare_registry_snapshot_results(registry, registry).complete == true, "complete registry still compares");

        {
            DenyRead denied(fixture.key);
            RegistrySnapshot blocked;
            reg_enumerate_impl(HKEY_CURRENT_USER, fixture.key_path, blocked, names, data, "HKCU");
            expect(!blocked.complete() && blocked.values.empty(), "access-denied registry scan is incomplete");
            expect(blocked.errors.size() == 1 && blocked.errors.front().find("Windows error 5") != std::string::npos,
                "access-denied error code retained");
            check_incomplete(compare_registry_snapshot_results(registry, blocked), "Na-snapshot");
        }

        AnalysisReport report;
        report.changes["files"] = compare_filesystem_snapshot_results(files, files);
        report.changes["registry"] = compare_registry_snapshot_results(registry, unavailable);
        const auto json = to_json(report);
        expect(json.find("\"complete\": false") != std::string::npos, "JSON exposes incomplete comparison");
        expect(json.find("\"complete\": true") != std::string::npos, "independent complete comparison retained");
        expect(json.find("RegOpenKeyExW") != std::string::npos, "JSON preserves diagnostics");
    } catch (const std::exception& ex) {
        std::cerr << "Unexpected exception: " << ex.what() << '\n';
        return 1;
    }
    if (failures) return 1;
    std::cout << "Snapshot collection regression checks passed.\n";
    return 0;
}
