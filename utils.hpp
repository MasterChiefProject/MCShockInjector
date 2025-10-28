#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <Windows.h>
#include <unordered_map>
#include "defs.h"
namespace utils {
    bool read_file(const std::string& path, std::vector<uint8_t>& out_buffer);
    bool write_file(const std::string& path, const std::vector<uint8_t>& buffer);
    HMODULE loadlibrary_ex_a_remote(HANDLE process, const std::string& dll_path);
    uint32_t align_up(uint32_t value, uint32_t alignment);
    uint32_t align_down(uint32_t value, uint32_t alignment);
    uintptr_t get_remote_export(HANDLE process, const std::string& module_name, const std::string& function_name);
    std::string to_hex_string(uint64_t value, bool prefix = true);
    std::vector<size_t> find_pattern_all(const uint8_t* data, size_t size, const char* patstr);
    size_t find_pattern_first(const uint8_t* data, size_t size, const char* patstr);
    static std::unordered_map<USHORT, std::string> build_type_index_map_best_effort();
    std::vector<handle_info_ex> get_process_handles_allinfo(DWORD pid, bool with_type_names);
}
