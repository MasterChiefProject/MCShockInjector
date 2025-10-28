#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>
//AAAAAA
namespace memory {

	HANDLE open_process(DWORD process_id, DWORD desired_access);

	BOOL read_process_memory(HANDLE h_process, LPCVOID address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read = nullptr);

	BOOL write_process_memory(HANDLE h_process, LPVOID address, LPCVOID buffer, SIZE_T size, SIZE_T* bytes_written = nullptr);

	BOOL virtual_protect_ex(HANDLE h_process, LPVOID lp_address, SIZE_T dw_size, DWORD fl_new_protect, PDWORD lpfl_old_protect);

	SIZE_T virtual_query_ex(HANDLE h_process, LPCVOID lp_address, PMEMORY_BASIC_INFORMATION lp_buffer, SIZE_T dw_length);

	DWORD get_module_base_name_a(HANDLE h_process, HMODULE h_module, LPSTR lp_base_name, DWORD n_size);

	BOOL enum_process_modules_ex(HANDLE h_process, HMODULE* lph_module, DWORD cb, LPDWORD lpcb_needed, DWORD dw_filter_flag);

	LPVOID virtual_alloc_ex(HANDLE h_process, LPVOID lp_address, SIZE_T dw_size, DWORD fl_allocation_type, DWORD fl_protect);
	
	BOOL virtual_free_ex(HANDLE h_process, LPVOID lp_address, SIZE_T dw_size, DWORD dw_free_type);
}  // namespace memory

#endif  // MEMORY_H