#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commdlg.h>
#include <shobjidl.h>
#include <d3d11.h>
#include <dxgi.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "analysis.h"

#include <chrono>
#include <future>
#include <string>

// ---------------------------------------------------------------------------
// DirectX 11 globals
// ---------------------------------------------------------------------------
static ID3D11Device*           g_pd3dDevice          = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext    = nullptr;
static IDXGISwapChain*         g_pSwapChain           = nullptr;
static UINT                    g_ResizeWidth          = 0;
static UINT                    g_ResizeHeight         = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------
static std::string wstr_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, result.data(), size, nullptr, nullptr);
    return result;
}

static std::wstring utf8_to_wstr(const char* str) {
    if (!str || str[0] == '\0') return {};
    const int size = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    std::wstring result(size - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str, -1, result.data(), size);
    return result;
}

// ---------------------------------------------------------------------------
// File dialogs
// ---------------------------------------------------------------------------
static bool browse_open(char* buf, int buf_size, const wchar_t* filter, const wchar_t* title) {
    OPENFILENAMEW ofn  = {};
    wchar_t path[MAX_PATH] = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = filter;
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = title;
    ofn.Flags       = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return false;
    strncpy_s(buf, buf_size, wstr_to_utf8(path).c_str(), _TRUNCATE);
    return true;
}

static bool browse_folder(char* buf, int buf_size, const wchar_t* title) {
    IFileDialog* pfd = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&pfd))))
        return false;
    DWORD opts = 0;
    pfd->GetOptions(&opts);
    pfd->SetOptions(opts | FOS_PICKFOLDERS | FOS_PATHMUSTEXIST);
    pfd->SetTitle(title);
    bool ok = false;
    if (SUCCEEDED(pfd->Show(nullptr))) {
        IShellItem* psi = nullptr;
        if (SUCCEEDED(pfd->GetResult(&psi))) {
            PWSTR path = nullptr;
            if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                strncpy_s(buf, buf_size, wstr_to_utf8(path).c_str(), _TRUNCATE);
                CoTaskMemFree(path);
                ok = true;
            }
            psi->Release();
        }
    }
    pfd->Release();
    return ok;
}

static bool browse_save(char* buf, int buf_size, const wchar_t* filter, const wchar_t* title) {
    OPENFILENAMEW ofn  = {};
    wchar_t path[MAX_PATH] = {};
    wcsncpy_s(path, utf8_to_wstr(buf).c_str(), _TRUNCATE);
    ofn.lStructSize    = sizeof(ofn);
    ofn.lpstrFilter    = filter;
    ofn.lpstrFile      = path;
    ofn.nMaxFile       = MAX_PATH;
    ofn.lpstrTitle     = title;
    ofn.lpstrDefExt    = L"json";
    ofn.Flags          = OFN_NOCHANGEDIR | OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameW(&ofn)) return false;
    strncpy_s(buf, buf_size, wstr_to_utf8(path).c_str(), _TRUNCATE);
    return true;
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------
struct AppState {
    char installer_path[512]  = "";
    char procmon_path[512]    = "";
    char procdump_path[512]   = "";
    char snapshot_dir[512]    = "";
    char output_path[512]     = "report.json";

    enum class Status { Idle, Running, Done, Error };
    Status      status = Status::Idle;
    std::string error_message;

    std::future<AnalysisReport> pending;
    AnalysisReport report;

    // Filesystem + registry snapshot state
    enum class SnapPhase { None, TakingBefore, TakingAfter };
    SnapPhase             snap_phase       = SnapPhase::None;
    std::future<Snapshot> snap_future;
    Snapshot              before_snap;
    bool                  has_before       = false;
    std::size_t           before_file_count = 0;
    std::size_t           before_reg_count  = 0;
    ChangeSummary         snap_result;
    ChangeSummary         reg_snap_result;
    bool                  has_snap_result   = false;
};

// ---------------------------------------------------------------------------
// Results renderer
// ---------------------------------------------------------------------------
static void render_report(const AnalysisReport& r) {
    ImGui::Text("Installer: %s", r.installer.empty() ? "(geen)" : r.installer.c_str());
    ImGui::Spacing();

    if (ImGui::CollapsingHeader("Wijzigingen", ImGuiTreeNodeFlags_DefaultOpen)) {
        for (const auto& [name, summary] : r.changes) {
            const std::string node_label = name + "  —  " + summary.description;
            if (ImGui::TreeNode(node_label.c_str())) {
                for (const auto& item : summary.items)
                    ImGui::BulletText("%s", item.c_str());
                ImGui::TreePop();
            }
        }
    }

    if (ImGui::CollapsingHeader("Dependencies")) {
        for (const auto& dep : r.dependencies)
            ImGui::BulletText("%s", dep.c_str());
    }

    if (ImGui::CollapsingHeader("Vereiste rechten")) {
        for (const auto& right : r.required_rights)
            ImGui::BulletText("%s", right.c_str());
    }

    if (ImGui::CollapsingHeader("Intune / MSIX aanbeveling", ImGuiTreeNodeFlags_DefaultOpen))
        ImGui::TextWrapped("%s", r.intune_msix_recommendation.c_str());
}

// ---------------------------------------------------------------------------
// Main UI
// ---------------------------------------------------------------------------
static void render_ui(AppState& s) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::Begin("##root", nullptr,
        ImGuiWindowFlags_NoTitleBar  | ImGuiWindowFlags_NoResize  |
        ImGuiWindowFlags_NoMove      | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImGui::PopStyleVar(2);

    // Title
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.40f, 0.80f, 1.00f, 1.00f));
    ImGui::SetWindowFontScale(1.25f);
    ImGui::Text("Enterprise Application Forensics Toolkit");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::PopStyleColor();
    ImGui::Separator();
    ImGui::Spacing();

    // Input table
    constexpr float LABEL_W  = 110.0f;
    constexpr float BUTTON_W = 90.0f;
    const     float INPUT_W  = ImGui::GetContentRegionAvail().x - LABEL_W - BUTTON_W
                               - ImGui::GetStyle().ItemSpacing.x * 2.0f;

    enum class BrowseMode { File, Save, Folder };
    auto input_row = [&](const char* label, char* buf, int buf_size,
                         const wchar_t* filter, const wchar_t* title,
                         BrowseMode mode = BrowseMode::File) {
        ImGui::PushItemWidth(INPUT_W);
        std::string input_id = std::string("##") + label;
        ImGui::InputText(input_id.c_str(), buf, buf_size);
        ImGui::PopItemWidth();
        ImGui::SameLine();
        std::string btn_id = std::string("Bladeren##") + label;
        if (ImGui::Button(btn_id.c_str(), ImVec2(BUTTON_W, 0))) {
            if (mode == BrowseMode::Folder)
                browse_folder(buf, buf_size, title);
            else if (mode == BrowseMode::Save)
                browse_save(buf, buf_size, filter, title);
            else
                browse_open(buf, buf_size, filter, title);
        }
        ImGui::SameLine();
        ImGui::SetNextItemWidth(LABEL_W);
        ImGui::TextUnformatted(label);
    };

    input_row("Installer",   s.installer_path, sizeof(s.installer_path),
        L"Installers\0*.exe;*.msi;*.msix;*.msp;*.mst\0Alle bestanden\0*.*\0",
        L"Selecteer installer");
    input_row("ProcMon CSV", s.procmon_path, sizeof(s.procmon_path),
        L"CSV\0*.csv\0Alle bestanden\0*.*\0",
        L"Selecteer ProcMon CSV");
    input_row("ProcDump",    s.procdump_path, sizeof(s.procdump_path),
        L"Dumps\0*.dmp;*.mdmp\0Alle bestanden\0*.*\0",
        L"Selecteer ProcDump bestand");

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextUnformatted("Bestandsvergelijking (voor/na installatie):");
    ImGui::Spacing();
    input_row("Doelmap", s.snapshot_dir, sizeof(s.snapshot_dir),
        nullptr, L"Selecteer doelmap voor snapshot", BrowseMode::Folder);

    ImGui::Spacing();
    {
        const bool snap_busy = s.snap_phase != AppState::SnapPhase::None;
        const bool has_dir   = s.snapshot_dir[0] != '\0';

        ImGui::BeginDisabled(snap_busy || !has_dir);
        if (ImGui::Button("Neem voor-snapshot", ImVec2(170, 26))) {
            s.has_before      = false;
            s.has_snap_result = false;
            s.snap_phase      = AppState::SnapPhase::TakingBefore;
            const fs::path dir(utf8_to_wstr(s.snapshot_dir));
            s.snap_future = std::async(std::launch::async,
                [dir]() { return take_full_snapshot(dir); });
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        if (!s.has_before)
            ImGui::TextColored({0.6f, 0.6f, 0.6f, 1.0f},
                snap_busy && s.snap_phase == AppState::SnapPhase::TakingBefore
                    ? "Bezig met scannen..." : "Nog niet genomen");
        else
            ImGui::TextColored({0.2f, 1.0f, 0.4f, 1.0f},
                "Klaar  (%zu bestanden, %zu registerwaarden)",
                s.before_file_count, s.before_reg_count);
    }

    ImGui::Spacing();
    {
        const bool snap_busy = s.snap_phase != AppState::SnapPhase::None;

        ImGui::BeginDisabled(snap_busy || !s.has_before);
        if (ImGui::Button("Neem na-snapshot + vergelijk", ImVec2(220, 26))) {
            s.snap_phase = AppState::SnapPhase::TakingAfter;
            const fs::path dir(utf8_to_wstr(s.snapshot_dir));
            s.snap_future = std::async(std::launch::async,
                [dir]() { return take_full_snapshot(dir); });
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        if (snap_busy && s.snap_phase == AppState::SnapPhase::TakingAfter)
            ImGui::TextColored({1.0f, 0.8f, 0.0f, 1.0f}, "Bezig met scannen...");
        else if (s.has_snap_result)
            ImGui::TextColored({0.2f, 1.0f, 0.4f, 1.0f}, "Vergelijking klaar");
    }

    // Poll snapshot future
    if (s.snap_phase != AppState::SnapPhase::None && s.snap_future.valid()) {
        if (s.snap_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            Snapshot result = s.snap_future.get();
            if (s.snap_phase == AppState::SnapPhase::TakingBefore) {
                s.before_snap      = std::move(result);
                s.before_file_count = s.before_snap.files.size();
                s.before_reg_count  = s.before_snap.registry.size();
                s.has_before        = true;
            } else {
                const std::string label =
                    fs::path(utf8_to_wstr(s.snapshot_dir)).filename().string();
                s.snap_result     = compare_filesystem_snapshots(
                    s.before_snap.files, result.files, label);
                s.reg_snap_result = compare_registry_snapshots(
                    s.before_snap.registry, result.registry, "HKLM");
                s.has_snap_result = true;
                s.report.changes["Bestandswijzigingen"] = s.snap_result;
                s.report.changes["Registerwijzigingen"] = s.reg_snap_result;
                if (s.status == AppState::Status::Idle ||
                    s.status == AppState::Status::Error)
                    s.status = AppState::Status::Done;
            }
            s.snap_phase = AppState::SnapPhase::None;
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    input_row("Uitvoer JSON", s.output_path, sizeof(s.output_path),
        L"JSON\0*.json\0Alle bestanden\0*.*\0",
        L"Sla rapport op als", BrowseMode::Save);

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Run button
    const bool has_input = s.installer_path[0] || s.procmon_path[0] || s.procdump_path[0];
    ImGui::BeginDisabled(s.status == AppState::Status::Running || !has_input);
    if (ImGui::Button("Analyse uitvoeren", ImVec2(170, 30))) {
        s.status = AppState::Status::Running;
        s.error_message.clear();

        Options opts;
        if (s.installer_path[0])  opts.installer = fs::path(utf8_to_wstr(s.installer_path));
        if (s.procmon_path[0])    opts.procmon   = fs::path(utf8_to_wstr(s.procmon_path));
        if (s.procdump_path[0])   opts.procdump  = fs::path(utf8_to_wstr(s.procdump_path));
        opts.output = fs::path(utf8_to_wstr(s.output_path));

        s.pending = std::async(std::launch::async, [opts]() {
            const ForensicsToolkitCpp toolkit(opts);
            AnalysisReport rep = toolkit.run_analysis();
            std::ofstream out(opts.output);
            if (out) out << to_json(rep);
            return rep;
        });
    }
    ImGui::EndDisabled();

    // Poll background task
    if (s.status == AppState::Status::Running && s.pending.valid()) {
        if (s.pending.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            try {
                s.report = s.pending.get();
                if (s.has_snap_result) {
                    s.report.changes["Bestandswijzigingen"] = s.snap_result;
                    s.report.changes["Registerwijzigingen"] = s.reg_snap_result;
                }
                s.status = AppState::Status::Done;
            } catch (const std::exception& ex) {
                s.error_message = ex.what();
                s.status = AppState::Status::Error;
            }
        }
    }

    // Status
    ImGui::SameLine();
    switch (s.status) {
        case AppState::Status::Idle:
            ImGui::TextColored({0.6f, 0.6f, 0.6f, 1.0f}, "Gereed");
            break;
        case AppState::Status::Running:
            ImGui::TextColored({1.0f, 0.8f, 0.0f, 1.0f}, "Analyse bezig...");
            break;
        case AppState::Status::Done:
            ImGui::TextColored({0.2f, 1.0f, 0.4f, 1.0f}, "Opgeslagen: %s", s.output_path);
            break;
        case AppState::Status::Error:
            ImGui::TextColored({1.0f, 0.3f, 0.3f, 1.0f}, "Fout: %s", s.error_message.c_str());
            break;
    }

    // Results
    if (s.status == AppState::Status::Done) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        if (ImGui::CollapsingHeader("Resultaten", ImGuiTreeNodeFlags_DefaultOpen))
            render_report(s.report);
    }

    ImGui::End();
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
        case WM_SIZE:
            if (wParam != SIZE_MINIMIZED) {
                g_ResizeWidth  = LOWORD(lParam);
                g_ResizeHeight = HIWORD(lParam);
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    WNDCLASSEXW wc   = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = L"EAFToolkit";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowW(wc.lpszClassName,
        L"Enterprise Application Forensics Toolkit",
        WS_OVERLAPPEDWINDOW, 100, 100, 1050, 780,
        nullptr, nullptr, hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename  = nullptr;

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowPadding    = {14.0f, 14.0f};
    style.FramePadding     = {6.0f, 4.0f};
    style.ItemSpacing      = {8.0f, 6.0f};
    style.FrameRounding    = 4.0f;
    style.GrabRounding     = 4.0f;
    style.Colors[ImGuiCol_WindowBg]  = {0.10f, 0.10f, 0.12f, 1.0f};
    style.Colors[ImGuiCol_FrameBg]   = {0.18f, 0.18f, 0.22f, 1.0f};
    style.Colors[ImGuiCol_Button]    = {0.22f, 0.45f, 0.70f, 1.0f};
    style.Colors[ImGuiCol_ButtonHovered] = {0.28f, 0.55f, 0.85f, 1.0f};
    style.Colors[ImGuiCol_ButtonActive]  = {0.18f, 0.38f, 0.60f, 1.0f};

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    AppState state;
    constexpr ImVec4 CLEAR = {0.10f, 0.10f, 0.12f, 1.0f};

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        if (g_ResizeWidth && g_ResizeHeight) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        render_ui(state);

        ImGui::Render();
        const float cc[4] = {CLEAR.x, CLEAR.y, CLEAR.z, CLEAR.w};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, cc);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, hInstance);
    CoUninitialize();
    return 0;
}

// ---------------------------------------------------------------------------
// DirectX 11 helpers
// ---------------------------------------------------------------------------
static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd          = {};
    sd.BufferCount                   = 2;
    sd.BufferDesc.Format             = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate        = {60, 1};
    sd.Flags                         = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage                   = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                  = hWnd;
    sd.SampleDesc.Count              = 1;
    sd.Windowed                      = TRUE;
    sd.SwapEffect                    = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL level;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        levels, 2, D3D11_SDK_VERSION, &sd,
        &g_pSwapChain, &g_pd3dDevice, &level, &g_pd3dDeviceContext);
    if (hr == DXGI_ERROR_UNSUPPORTED)
        hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0,
            levels, 2, D3D11_SDK_VERSION, &sd,
            &g_pSwapChain, &g_pd3dDevice, &level, &g_pd3dDeviceContext);
    if (FAILED(hr)) return false;

    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release();        g_pSwapChain        = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release();  g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)        { g_pd3dDevice->Release();         g_pd3dDevice        = nullptr; }
}

static void CreateRenderTarget() {
    ID3D11Texture2D* pBack = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBack));
    g_pd3dDevice->CreateRenderTargetView(pBack, nullptr, &g_mainRenderTargetView);
    pBack->Release();
}

static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}
