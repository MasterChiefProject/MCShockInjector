#pragma once
#pragma once
#include <cstdint>
#include <string>
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <sstream>
// -------- ntstatus & helpers --------
typedef long ntstatus;
#ifndef nt_success
#define nt_success(s) ((s) >= 0)
#endif
#ifndef status_info_length_mismatch
#define status_info_length_mismatch ((ntstatus)0xC0000004L)
#endif

// -------- info class stand-ins (no SDK dependency) --------
typedef int system_information_class;
typedef int object_information_class;

#ifndef system_extended_handle_information
#define system_extended_handle_information ((system_information_class)64)
#endif
#ifndef object_types_information
#define object_types_information ((object_information_class)3)
#endif

// kill SDK macro collisions
#ifdef object_types_information
#undef object_types_information
#endif
#ifdef pobject_types_information
#undef pobject_types_information
#endif
#ifdef object_type_information
#undef object_type_information
#endif
#ifdef pobject_type_information
#undef pobject_type_information
#endif

// -------- minimal UNICODE_STRING --------
typedef struct _unicode_string {
    uint16_t length;
    uint16_t maximum_length;
    wchar_t* buffer;
} unicode_string, * punicode_string;

// -------- system handle info ex --------
typedef struct _system_handle_table_entry_info_ex {
    void* object;
    uintptr_t  unique_process_id;
    uintptr_t  handle_value;
    uint32_t   granted_access;
    uint16_t   creator_back_trace_index;
    uint16_t   object_type_index;
    uint32_t   handle_attributes;
    uint32_t   reserved;
} system_handle_table_entry_info_ex, * psystem_handle_table_entry_info_ex;

typedef struct _system_handle_information_ex {
    uintptr_t  number_of_handles;
    uintptr_t  reserved;
    system_handle_table_entry_info_ex handles[1];
} system_handle_information_ex, * psystem_handle_information_ex;

// -------- object types info (header + minimal entry) --------
typedef struct _object_types_information {
    uint32_t number_of_types;
} object_types_information, * pobject_types_information;

typedef struct _object_type_information_min {
    unicode_string type_name;
    uint32_t       total_number_of_handles;
    uint32_t       total_number_of_objects;
} object_type_information_min, * pobject_type_information_min;
typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;
typedef BOOL(WINAPI* SetProcessValidCallTargets_t)(HANDLE, PVOID, SIZE_T, ULONG, PVOID);
// Constants
#define NTDLL ("ntdll.dll")
#define NTSETINFORMATIONVIRTUALMEMORY ("NtSetInformationVirtualMemory")
#define CFG_CALL_TARGET_VALID (0x00000001)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
typedef enum _ESTATUS
{
    ESTATUS_INVALID = -1,
    ESTATUS_SUCCESS = 0,
    ESTATUS_GETFUNCTIONADDRESSFROMDLL_GETMODULEHANDLEA_FAILED = 0x100,
    ESTATUS_GETFUNCTIONADDRESSFROMDLL_GETPROCADDRESS_FAILED,
    ESTATUS_GETMEMORYALLOCATIONBASEANDREGIONSIZE_VIRTUALQUERY_FAILED,
    ESTATUS_ADDCFGEXCEPTIONUNDOCUMENTEDAPI_NTSETINFORMATIONVIRTUALMEMORY_FAILED
} ESTATUS, * PESTATUS;

#define ESTATUS_FAILED(eStatus) (ESTATUS_SUCCESS != eStatus)

// Structures
typedef struct _MEMORY_RANGE_ENTRY
{
    PVOID VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;
typedef struct _VM_INFORMATION
{
    DWORD dwNumberOfOffsets;
    PVOID dwMustBeZero;
    PDWORD pdwOutput;
    PCFG_CALL_TARGET_INFO ptOffsets;
} VM_INFORMATION, * PVM_INFORMATION;

// Function Pointer Type
typedef NTSTATUS(NTAPI* _NtSetInformationVirtualMemory)(
    HANDLE hProcess,
    VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    ULONG_PTR NumberOfEntries,
    PMEMORY_RANGE_ENTRY VirtualAddresses,
    PVOID VmInformation,
    ULONG VmInformationLength
    );
// -------- function pointer typedefs (we will GetProcAddress) --------
typedef ntstatus(__stdcall* pfn_nt_query_system_information)(
    system_information_class system_information_class,
    void* system_information,
    uint32_t                 system_information_length,
    uint32_t* return_length
    );

typedef ntstatus(__stdcall* pfn_nt_query_object)(
    void* handle,
    object_information_class object_information_class,
    void* object_information,
    uint32_t                 object_information_length,
    uint32_t* return_length
    );

// -------- small helpers --------
static inline size_t align_up_size(size_t v, size_t a) { return (v + (a - 1)) & ~(a - 1); }

// -------- public struct we return --------
struct handle_info_ex {
    uint64_t    handle;
    uint32_t    owner_pid;
    uint32_t    access;
    uint32_t    attributes;
    uint16_t    object_type_index;
    uint16_t    creator_back_trace_idx;
    uint64_t    object_ptr;
    std::string type_name; // optional; may be empty
};
typedef NTSTATUS(NTAPI* NtSetInformationVirtualMemory_t)(HANDLE, VIRTUAL_MEMORY_INFORMATION_CLASS, ULONG_PTR, PMEMORY_RANGE_ENTRY, PVOID, ULONG);

typedef struct _MemoryRegion {
    PVOID base;
    SIZE_T size;
    DWORD protect;
} MemoryRegion;
typedef NTSTATUS(NTAPI* NtSetInformationVirtualMemory_t)(HANDLE, VIRTUAL_MEMORY_INFORMATION_CLASS, ULONG_PTR, PMEMORY_RANGE_ENTRY, PVOID, ULONG);
