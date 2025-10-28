#include "shellcode_manager.hpp"
#include <Psapi.h>
#include <iostream>
#include "utils.hpp"
#include "memory.h"
shellcode_manager::shellcode_manager(HANDLE process)
    : process_handle(process) {
}

uintptr_t shellcode_manager::get_shellcode_address() const {
    return shellcode_address;
}

bool shellcode_manager::find_region(size_t size, region_type preferred_type) {
    selected_type = preferred_type;

    switch (preferred_type) {
    case region_type::rwx: return search_rwx_cave(size);
    case region_type::rx:  return search_rx_cave(size);
    case region_type::rw:  return search_rw_cave(size);
    case region_type::rwx_alloc: return allocate_rwx(size);
    default: return false;
    }
}

bool shellcode_manager::write_shellcode(const void* shellcode_data, size_t size) {
    if (!shellcode_address)
        return false;

    DWORD old_protect = 0;

    if (selected_type == region_type::rx || selected_type == region_type::rw) {
        // Temporarily make it RWX
        memory::virtual_protect_ex(process_handle, (LPVOID)shellcode_address, size, PAGE_EXECUTE_READWRITE, &old_protect);
    }

    SIZE_T written = 0;
    if (!memory::write_process_memory(process_handle, (LPVOID)shellcode_address, shellcode_data, size, &written) || written != size)
        return false;

    if (selected_type == region_type::rx || selected_type == region_type::rw) {
        // Restore original protection
        //VirtualProtectEx(process_handle, (LPVOID)shellcode_address, size, old_protect, &old_protect);
    }

    return true;
}

// shellcode_manager.cpp (updated execute and destructor)
bool shellcode_manager::execute(const std::wstring& module_name, const std::string& function_name) {
    if (!shellcode_address) {
        std::cerr << "[-] Shellcode address not set.\n";
        return false;
    }
    std::string module_name_str(module_name.begin(), module_name.end());
    uintptr_t remote_func = utils::get_remote_export(process_handle, module_name_str, function_name);
    if (!remote_func) {
        std::cerr << "[-] Failed to resolve " << module_name_str << "!" << function_name << "\n";
        return false;
    }
    std::cout << "[+] Resolved function " << function_name << " from " << module_name_str
        << " at 0x" << std::hex << remote_func << "\n";
    BYTE original_bytes[16] = {};
    SIZE_T read = 0;
    if (!memory::read_process_memory(process_handle, reinterpret_cast<LPCVOID>(remote_func),
        original_bytes, sizeof(original_bytes), &read) || read != sizeof(original_bytes)) {
        std::cerr << "[-] Failed to read original bytes from function.\n";
        return false;
    }
    std::cout << "[+] Backed up original 16 bytes from function.\n";
    // Trampoline with an embedded sentinel byte at the end: ... ret, 0x00
    BYTE trampoline[] = {
        0x57, // push rdi
        0x48, 0xBF, // mov rdi, <remote_func>
        0,0,0,0,0,0,0,0,
        0x48, 0xB8, // mov rax, <orig[0..7]>
        0,0,0,0,0,0,0,0,
        0x48, 0x89, 0x07, // mov [rdi], rax
        0x48, 0xB8, // mov rax, <orig[8..15]>
        0,0,0,0,0,0,0,0,
        0x48, 0x89, 0x47, 0x08, // mov [rdi+8], rax
        0x5F, // pop rdi
        0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
        0x48, 0xB8, // mov rax, <shellcode_address>
        0,0,0,0,0,0,0,0,
        0xFF, 0xD0, // call rax
        0xC6, 0x05, 0x05, 0x00, 0x00, 0x00, // mov byte ptr [rip+0x5], 0x01
        0x01,
        0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
        0xC3, // ret
        0x00 // flag byte (target of the RIP+0x5 store)
    };
    constexpr size_t DONE_BYTE_OFFSET = sizeof(trampoline) - 1;
    // Patch trampoline immediates
    *reinterpret_cast<uint64_t*>(&trampoline[3]) = remote_func;
    *reinterpret_cast<uint64_t*>(&trampoline[13]) = *reinterpret_cast<const uint64_t*>(&original_bytes[0]);
    *reinterpret_cast<uint64_t*>(&trampoline[26]) = *reinterpret_cast<const uint64_t*>(&original_bytes[8]);
    *reinterpret_cast<uint64_t*>(&trampoline[45]) = shellcode_address;
    std::cout << "[+] Trampoline created to restore function and jump to shellcode.\n";
    // Backup shellcode_address
    uintptr_t original_shellcode_addr = shellcode_address;
    std::cout << "[*] Finding memory for trampoline using previously selected region type...\n";
    if (!find_region(sizeof(trampoline), selected_type)) {
        std::cerr << "[-] Failed to find memory for trampoline.\n";
        return false;
    }
    trampoline_address = shellcode_address;  // NEW: Track trampoline address (type is same as selected_type)
    std::cout << "[+] Found trampoline memory at 0x" << std::hex << trampoline_address << "\n";
    const uintptr_t done_addr = trampoline_address + DONE_BYTE_OFFSET;
    shellcode_address = original_shellcode_addr; // Restore original
    SIZE_T written = 0;
    if (!memory::write_process_memory(process_handle, reinterpret_cast<void*>(trampoline_address),
        trampoline, sizeof(trampoline), &written) || written != sizeof(trampoline))
    {
        std::cerr << "[-] Failed to write trampoline shellcode.\n";
        return false;
    }
    std::cout << "[+] Wrote trampoline (" << std::dec << written << " bytes) to 0x"
        << std::hex << trampoline_address << "\n";
    //14-byte absolute indirect jmp detour: FF 25 00 00 00 00 ; dq <target>
    BYTE detour[14] = { 0xFF, 0x25, 0, 0, 0, 0 };
    *reinterpret_cast<uint64_t*>(&detour[6]) = trampoline_address;
    DWORD old_protect = 0;
    if (!memory::virtual_protect_ex(process_handle, reinterpret_cast<void*>(remote_func),
        sizeof(detour), PAGE_EXECUTE_READWRITE, &old_protect))
    {
        std::cerr << "[-] Failed to change protection for detour patch.\n";
        return false;
    }
    if (!memory::write_process_memory(process_handle, reinterpret_cast<void*>(remote_func),
        detour, sizeof(detour), &written))
    {
        std::cerr << "[-] Failed to write detour.\n";
        return false;
    }
    std::cout << "[+] Wrote detour to target function, detour target: 0x"
        << std::hex << (trampoline_address) << "\n";
    std::cout << "[*] Waiting for shellcode completion...\n";
    BYTE done = 0;
    bool ok = false;
    for (uint32_t i = 0; i < 5000; ++i) {
        if (!memory::read_process_memory(process_handle, reinterpret_cast<LPCVOID>(done_addr), &done, 1, &read))
            break;
        if (done == 1) { ok = true; break; }
        Sleep(1);
    }
    if (!ok) {
        std::cerr << "[-] Timeout waiting for shellcode completion.\n";
        return false;
    }
    std::cout << "[+] Shellcode executed successfully.\n";
    return true;
}

bool shellcode_manager::is_region_suitable(const MEMORY_BASIC_INFORMATION& mbi, DWORD protection, size_t size) {
    return mbi.State == MEM_COMMIT &&
        mbi.Type == MEM_PRIVATE &&
        mbi.Protect == protection &&
        mbi.RegionSize >= size;
}

bool is_zeroed_region(HANDLE process, uintptr_t address, size_t size) {
    std::vector<uint8_t> buffer(size);
    SIZE_T read = 0;

    if (!memory::read_process_memory(process, (LPCVOID)address, buffer.data(), size, &read) || read != size)
        return false;

    for (uint8_t b : buffer) {
        if (b != 0)
            return false;
    }

    return true;
}

bool shellcode_manager::search_rwx_cave(size_t size) {
    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi = {};

    while (memory::virtual_query_ex(process_handle, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (is_region_suitable(mbi, PAGE_EXECUTE_READWRITE, size)) {
            uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            if (is_zeroed_region(process_handle, base, size)) {
                shellcode_address = base;
                return true;
            }
        }

        address += mbi.RegionSize;
    }

    return false;
}

bool shellcode_manager::search_rx_cave(size_t size) {
    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi = {};

    while (memory::virtual_query_ex(process_handle, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (is_region_suitable(mbi, PAGE_EXECUTE_READ, size)) {
            uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            if (is_zeroed_region(process_handle, base, size)) {
                shellcode_address = base;
                return true;
            }
        }

        address += mbi.RegionSize;
    }

    return false;
}


bool shellcode_manager::search_rw_cave(size_t size) {
    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi = {};

    while (memory::virtual_query_ex(process_handle, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (is_region_suitable(mbi, PAGE_READWRITE, size)) {
            uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            if (is_zeroed_region(process_handle, base, size)) {
                shellcode_address = base;
                return true;
            }
        }

        address += mbi.RegionSize;
    }

    return false;
}


bool shellcode_manager::allocate_rwx(size_t size) {
    shellcode_address = reinterpret_cast<uintptr_t>(
        memory::virtual_alloc_ex(process_handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    return shellcode_address != 0;
}

shellcode_manager::~shellcode_manager() {
    if (shellcode_address != 0 && selected_type == region_type::rwx_alloc) {
        // Free the allocated shellcode memory (size=0 with MEM_RELEASE to free the entire region)
        memory::virtual_free_ex(process_handle, (LPVOID)shellcode_address, 0, MEM_RELEASE);
    }
    if (trampoline_address != 0 && selected_type == region_type::rwx_alloc) {
        // Free the allocated trampoline memory similarly (same type as shellcode)
        memory::virtual_free_ex(process_handle, (LPVOID)trampoline_address, 0, MEM_RELEASE);
    }
    // For caves (non-allocated), do nothing - memory is not ours to free
}