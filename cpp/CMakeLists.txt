cmake_minimum_required(VERSION 3.16)

project(enterprise_application_forensics_toolkit_cpp LANGUAGES CXX)

add_executable(eaftoolkit src/main.cpp)
target_compile_features(eaftoolkit PRIVATE cxx_std_17)

if(MSVC)
  target_compile_options(eaftoolkit PRIVATE /W4)
else()
  target_compile_options(eaftoolkit PRIVATE -Wall -Wextra -pedantic)
endif()
