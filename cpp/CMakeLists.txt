cmake_minimum_required(VERSION 3.16)
project(enterprise_application_forensics_toolkit_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Dear ImGui — fetched from GitHub, built manually so we control which
# backends (Win32 + DX11) are compiled in.
# ---------------------------------------------------------------------------
include(FetchContent)
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.91.1
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(imgui)
if(NOT imgui_POPULATED)
    FetchContent_Populate(imgui)
endif()

add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)
target_include_directories(imgui PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)
target_link_libraries(imgui PUBLIC d3d11 dxgi)
if(MSVC)
    target_compile_options(imgui PRIVATE /W0)
endif()

# ---------------------------------------------------------------------------
# CLI executable
# ---------------------------------------------------------------------------
add_executable(eaftoolkit src/main.cpp)
target_include_directories(eaftoolkit PRIVATE src)
if(MSVC)
    target_compile_options(eaftoolkit PRIVATE /W4)
else()
    target_compile_options(eaftoolkit PRIVATE -Wall -Wextra -pedantic)
endif()

# ---------------------------------------------------------------------------
# GUI executable  (WIN32 = no console window, entry point is WinMain)
# ---------------------------------------------------------------------------
add_executable(eaftoolkit-gui WIN32 src/gui.cpp resources/resources.rc)
target_include_directories(eaftoolkit-gui PRIVATE src)
target_link_libraries(eaftoolkit-gui PRIVATE imgui comdlg32)
if(MSVC)
    target_compile_options(eaftoolkit-gui PRIVATE /W4)
else()
    target_compile_options(eaftoolkit-gui PRIVATE -Wall -Wextra -pedantic)
endif()
