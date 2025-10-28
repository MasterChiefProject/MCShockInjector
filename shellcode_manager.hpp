#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>
class shellcode_manager {
public:
    enum class region_type {
        rwx,
        rx,
        rw,
        rwx_alloc
    };
    shellcode_manager(HANDLE process);
    ~shellcode_manager();  // NEW: Destructor to free memory if applicable
    bool find_region(size_t size, region_type preferred_type);
    bool write_shellcode(const void* shellcode_data, size_t size);
    bool execute(const std::wstring& module_name, const std::string& function_name);
    uintptr_t get_shellcode_address() const;
private:
    HANDLE process_handle;
    uintptr_t shellcode_address = 0;
    uintptr_t trampoline_address = 0;  // NEW: Track trampoline address
    region_type selected_type = region_type::rwx_alloc;  // Single type for both allocations/caves
    bool search_rwx_cave(size_t size);
    bool search_rx_cave(size_t size);
    bool search_rw_cave(size_t size);
    bool allocate_rwx(size_t size);
    bool is_region_suitable(const MEMORY_BASIC_INFORMATION& mbi, DWORD protection, size_t size);
};