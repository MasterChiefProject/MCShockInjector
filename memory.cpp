#include "memory.h"
#include <Windows.h>
//#include "comms_functions.hpp"
//#include "channel.hpp"
//AAAAA
#include <Psapi.h>
namespace memory {

    BOOL read_process_memory(HANDLE h, LPCVOID address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
        if (h == nullptr) {
            /*// Use global ipc for comms read
            const uint32_t shmem_off = 1024;  // Adjust as needed
            uint32_t transferred = 0;
            int status = 0;
            bool ok = comms::request_read(g_ipc, (uint64_t)address, (uint32_t)size, shmem_off, transferred, status);
            if (ok && status == 0) {
                if (transferred > 0) {
                    memcpy(buffer, (uint8_t*)g_ipc.base + shmem_off, transferred);
                }
                if (bytes_read) *bytes_read = transferred;
                return TRUE;
            }
            else {
                if (bytes_read) *bytes_read = 0;
                return FALSE;
            }*/
        }
        else {
            // Standard ReadProcessMemory
            SIZE_T local_bytes_read;
            BOOL success = ReadProcessMemory(h, address, buffer, size, &local_bytes_read);
            if (bytes_read) *bytes_read = local_bytes_read;
            return success;
        }
    }
    BOOL write_process_memory(HANDLE h_process, LPVOID address, LPCVOID buffer, SIZE_T size, SIZE_T* bytes_written) {
        if (h_process == nullptr) {
            // Use IPC comms for write
            /*const uint32_t shmem_off = 1024;  // Example offset after mailbox; adjust to avoid overlap (e.g., sizeof(Mailbox) + padding)
            if (size > kMapSize - shmem_off) {
                if (bytes_written) *bytes_written = 0;
                return FALSE;  // Size too large for shared mem
            }
            memcpy((uint8_t*)g_ipc.base + shmem_off, buffer, size);
            uint32_t transferred = 0;
            int status = 0;
            bool ok = comms::request_write(g_ipc, (uint64_t)address, (uint32_t)size, shmem_off, transferred, status);
            if (ok && status == 0) {
                if (bytes_written) *bytes_written = transferred;
                return TRUE;
            }
            else {
                if (bytes_written) *bytes_written = 0;
                return FALSE;
            */
        }
        else {
            SIZE_T local_bytes_written;
            BOOL success = WriteProcessMemory(h_process, address, buffer, size, &local_bytes_written);
            if (bytes_written) *bytes_written = local_bytes_written;
            return success;
        }
    }

    BOOL virtual_protect_ex(HANDLE h_process, LPVOID lp_address, SIZE_T dw_size, DWORD fl_new_protect, PDWORD lpfl_old_protect) {
        if (h_process == nullptr) {
            /*uint32_t old_protect = 0;
            int status = 0;
            bool ok = comms::request_virtual_protect(g_ipc, (uint64_t)lp_address, (uint32_t)dw_size, fl_new_protect, old_protect, status);
            if (ok && status == 0) {
                if (lpfl_old_protect) *lpfl_old_protect = old_protect;
                return TRUE;
            }
            else {
                return FALSE;
            }*/
        }
        else {
            return VirtualProtectEx(h_process, lp_address, dw_size, fl_new_protect, lpfl_old_protect);
        }
    }

    SIZE_T virtual_query_ex(HANDLE h_process, LPCVOID lp_address, PMEMORY_BASIC_INFORMATION lp_buffer, SIZE_T dw_length) {
        if (h_process == nullptr) {
            /*const uint32_t shmem_off = 1024;  // Example offset; adjust to avoid overlap
            const uint32_t shmem_cap = sizeof(MEMORY_BASIC_INFORMATION);
            if (dw_length < shmem_cap) {
                return 0;  // Insufficient buffer size
            }
            MEMORY_BASIC_INFORMATION mbi{};
            uint32_t returned_size = 0;
            int status = 0;
            bool ok = comms::request_virtual_query(g_ipc, (uint64_t)lp_address, shmem_off, shmem_cap, mbi, returned_size, status);
            if (ok && status == 0) {
                memcpy(lp_buffer, &mbi, returned_size);
                return returned_size;
            }
            else {
                return 0;
            }*/
        }
        else {
            return VirtualQueryEx(h_process, lp_address, lp_buffer, dw_length);
        }
    }

    DWORD get_module_base_name_a(HANDLE h_process, HMODULE h_module, LPSTR lp_base_name, DWORD n_size) {
        if (h_process == NULL) {
            /*const uint32_t shmem_off = 1024;  // Example offset; adjust to avoid overlap
            const uint32_t shmem_cap = n_size;  // Use provided buffer size
            std::string name;
            int status = 0;
            bool ok = comms::request_get_module_base_name(g_ipc, (uint64_t)h_module, shmem_off, shmem_cap, name, status);
            if (ok && status == 0) {
                DWORD len = (DWORD)name.length();
                if (len >= n_size) len = n_size - 1;  // Truncate if needed
                if (len > 0) {
                    memcpy(lp_base_name, name.c_str(), len);
                }
                lp_base_name[len] = '\0';  // NUL-terminate
                return len;
            }
            else {
                return 0;
            }*/
        }
        else {
            return GetModuleBaseNameA(h_process, h_module, lp_base_name, n_size);
        }
    }

    BOOL enum_process_modules_ex(HANDLE h_process, HMODULE* lph_module, DWORD cb, LPDWORD lpcb_needed, DWORD dw_filter_flag) {
        if (h_process == NULL) {
            /*const uint32_t shmem_off = 1024;  // Example offset; adjust to avoid overlap
            const uint32_t shmem_cap = cb;
            uint32_t needed_bytes = 0;
            int status = 0;
            bool ok = comms::request_enum_process_modules(g_ipc, shmem_off, shmem_cap, dw_filter_flag, needed_bytes, status);
            if (lpcb_needed) *lpcb_needed = needed_bytes;
            if (ok && status == 0) {
                // Copy modules from shared mem to user buffer
                if (needed_bytes <= cb) {
                    memcpy(lph_module, (uint8_t*)g_ipc.base + shmem_off, needed_bytes);
                }
                return TRUE;
            }
            else {
                return FALSE;
            }*/
        }
        else {
            return EnumProcessModulesEx(h_process, lph_module, cb, lpcb_needed, dw_filter_flag);
        }
    }
    LPVOID virtual_alloc_ex(HANDLE h_process, LPVOID lp_address, SIZE_T dw_size, DWORD fl_allocation_type, DWORD fl_protect) {
        if (h_process == NULL) {
            /*uint64_t allocated_addr = 0;
            int status = 0;
            bool ok = comms::request_virtual_alloc(g_ipc, (uint64_t)lp_address, (uint32_t)dw_size, fl_allocation_type, fl_protect, allocated_addr, status);
            if (ok && status == 0) {
                return (LPVOID)allocated_addr;
            }
            else {
                return NULL;
            }*/
        }
        else {
            return VirtualAllocEx(h_process, lp_address, dw_size, fl_allocation_type, fl_protect);
        }
    }

    BOOL virtual_free_ex(HANDLE h_process, LPVOID lp_address, SIZE_T dw_size, DWORD dw_free_type) {
        if (h_process == NULL) {
            /*int status = 0;
            bool ok = comms::request_virtual_free(g_ipc, (uint64_t)lp_address, (uint32_t)dw_size, dw_free_type, status);
            if (ok && status == 0) {
                return TRUE;
            }
            else {
                return FALSE;
            }*/
        }
        else {
            return VirtualFreeEx(h_process, lp_address, dw_size, dw_free_type);
        }
    }

}  // namespace memory