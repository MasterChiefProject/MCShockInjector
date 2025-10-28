#include "utils.hpp"
#include "defs.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <Psapi.h>
#include <vector>
#include <iostream>
#include <Windows.h>
#include "memory.h"
#include <cctype>
#include "shellcode_manager.hpp"
#include <winternl.h>   // NtQuerySystemInformation, SYSTEM_HANDLE_INFORMATION_EX, ...
#include <ntstatus.h>   // NT_SUCCESS
#include <cstdint>
#include <unordered_map>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Psapi.lib")
namespace utils {

    bool read_file(const std::string& path, std::vector<uint8_t>& out_buffer) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file)
            return false;

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        out_buffer.resize(static_cast<size_t>(size));
        return file.read(reinterpret_cast<char*>(out_buffer.data()), size).good();
    }

    bool write_file(const std::string& path, const std::vector<uint8_t>& buffer) {
        std::ofstream file(path, std::ios::binary);
        if (!file)
            return false;

        return file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size()).good();
    }

    uint32_t align_up(uint32_t value, uint32_t alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    static inline SIZE_T __align_up_sz(SIZE_T v, SIZE_T a) {
        return (v + (a - 1)) & ~(a - 1);
    }

    uint32_t align_down(uint32_t value, uint32_t alignment) {
        return value & ~(alignment - 1);
    }

    std::string to_hex_string(uint64_t value, bool prefix) {
        std::stringstream ss;
        if (prefix) ss << "0x";
        ss << std::hex << std::uppercase << value;
        return ss.str();
    }

    UINT_PTR resolve_relative_address(PVOID instruction_address, SIZE_T relative_address_offset, SIZE_T instruction_length)
    {
        return (ULONG_PTR)((ULONG_PTR)instruction_address
            + (*(int*)((ULONG_PTR)instruction_address + relative_address_offset))
            + instruction_length);
    }

    static std::vector<int> parse_pattern(const char* s) {
        auto hex = [](char c) -> int {
            if ('0' <= c && c <= '9') return c - '0';
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if ('A' <= c && c <= 'F') return 10 + (c - 'A');
            return -1;
            };
        std::vector<int> pat;
        for (size_t i = 0; s[i] != '\0';) {
            while (s[i] != '\0' && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
            if (s[i] == '\0') break;
            if (s[i] == '?') {
                ++i;
                if (s[i] == '?') ++i;
                pat.push_back(-1);
            }
            else {
                if (s[i + 1] == '\0') break;
                int hi = hex(s[i]);
                int lo = hex(s[i + 1]);
                if (hi < 0 || lo < 0) {

                    while (s[i] != '\0' && !std::isspace(static_cast<unsigned char>(s[i]))) ++i;
                    continue;
                }
                pat.push_back((hi << 4) | lo);
                i += 2;
            }

            while (s[i] != '\0' && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        }
        return pat;
    }

    static std::vector<size_t> find_pattern_all_impl(const uint8_t* data, size_t size,
        const std::vector<int>& pat) {
        std::vector<size_t> hits;
        if (!data || size == 0 || pat.empty() || pat.size() > size) return hits;
        const size_t m = pat.size();
        for (size_t i = 0; i + m <= size; ++i) {
            size_t j = 0;
            for (; j < m; ++j) {
                if (pat[j] != -1 && data[i + j] != static_cast<uint8_t>(pat[j])) break;
            }
            if (j == m) hits.push_back(i);
        }
        return hits;
    }

    static size_t find_pattern_first_impl(const uint8_t* data, size_t size,
        const std::vector<int>& pat) {
        if (!data || size == 0 || pat.empty() || pat.size() > size) return size;
        const size_t m = pat.size();
        for (size_t i = 0; i + m <= size; ++i) {
            size_t j = 0;
            for (; j < m; ++j) {
                if (pat[j] != -1 && data[i + j] != static_cast<uint8_t>(pat[j])) break;
            }
            if (j == m) return i;
        }
        return size;
    }

    std::vector<size_t> find_pattern_all(const uint8_t* data, size_t size, const char* patstr) {
        return find_pattern_all_impl(data, size, parse_pattern(patstr));
    }

    size_t find_pattern_first(const uint8_t* data, size_t size, const char* patstr) {
        return find_pattern_first_impl(data, size, parse_pattern(patstr));
    }

    // best-effort: build map from type index -> type name (no duplication)
    static std::unordered_map<USHORT, std::string> build_type_index_map() {
        std::unordered_map<USHORT, std::string> map;

        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return map;

        auto nt_query_object = reinterpret_cast<pfn_nt_query_object>(
            GetProcAddress(ntdll, "NtQueryObject"));
        if (!nt_query_object) return map;

        uint32_t len = 0;
        std::vector<unsigned char> buf(len);
        static constexpr object_information_class k_obj_types_info =
            (object_information_class)3;

        nt_query_object(nullptr, k_obj_types_info, nullptr, 0, &len);
        if (!nt_success(nt_query_object(nullptr, k_obj_types_info, buf.data(), len, &len)))
            return map;


        // parse buffer
        auto hdr = reinterpret_cast<const object_types_information*>(buf.data());
        const unsigned char* p = reinterpret_cast<const unsigned char*>(hdr) + sizeof(object_types_information);
        const unsigned char* end = buf.data() + buf.size();

        std::vector<std::wstring> names;
        names.reserve(hdr->number_of_types);

        for (uint32_t i = 0; i < hdr->number_of_types; ++i) {
            if (p + sizeof(object_type_information_min) > end) break;
            auto ti = reinterpret_cast<const object_type_information_min*>(p);

            std::wstring wname;
            if (ti->type_name.buffer && ti->type_name.length) {
                size_t chars = ti->type_name.length / sizeof(wchar_t);
                if ((unsigned char*)ti->type_name.buffer >= buf.data() &&
                    ((unsigned char*)ti->type_name.buffer + ti->type_name.length) <= end) {
                    wname.assign(ti->type_name.buffer, ti->type_name.buffer + chars);
                }
            }
            names.push_back(std::move(wname));

            size_t step = align_up_size(sizeof(object_type_information_min), sizeof(void*))
                + align_up_size(ti->type_name.maximum_length, sizeof(void*));
            const unsigned char* next = p + step;
            if (next <= p || next > end) break;
            p = next;
        }

        // best-effort index mapping (1-based)
        for (USHORT idx = 1; idx <= names.size(); ++idx) {
            const auto& w = names[idx - 1];
            if (!w.empty()) map[idx] = std::string(w.begin(), w.end());
        }
        return map;
    }

    // enumerate all handles for a pid (no handle duplication)
    std::vector<handle_info_ex> get_process_handles_allinfo(DWORD pid, bool with_type_names) {
        std::vector<handle_info_ex> out;

        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return out;

        auto nt_query_system_information = reinterpret_cast<pfn_nt_query_system_information>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (!nt_query_system_information) return out;

        uint32_t buf_size = 1u << 16;
        std::vector<unsigned char> buffer;
        uint32_t ret_len = 0;
        ntstatus st = 0;

        for (;;) {
            buffer.resize(buf_size);
            st = nt_query_system_information(
                system_extended_handle_information,
                buffer.data(),
                buf_size,
                &ret_len
            );
            if (st == status_info_length_mismatch) {
                buf_size = (ret_len > buf_size) ? (ret_len + (1u << 14)) : (buf_size << 1);
                continue;
            }
            break;
        }
        if (!nt_success(st)) return out;

        const auto info = reinterpret_cast<const system_handle_information_ex*>(buffer.data());
        const size_t n = static_cast<size_t>(info->number_of_handles);

        std::unordered_map<USHORT, std::string> type_map;
        if (with_type_names) type_map = build_type_index_map();

        out.reserve(n / 8);
        for (size_t i = 0; i < n; ++i) {
            const auto& e = info->handles[i];
            if (static_cast<DWORD>(e.unique_process_id) != pid) continue;

            handle_info_ex hi{};
            hi.handle = static_cast<uint64_t>(e.handle_value);
            hi.owner_pid = static_cast<uint32_t>(e.unique_process_id);
            hi.access = e.granted_access;
            hi.attributes = e.handle_attributes;
            hi.object_type_index = e.object_type_index;
            hi.creator_back_trace_idx = e.creator_back_trace_index;
            hi.object_ptr = reinterpret_cast<uint64_t>(e.object);

            if (with_type_names && !type_map.empty()) {
                auto it = type_map.find(hi.object_type_index);
                if (it != type_map.end()) hi.type_name = it->second;
            }

            out.push_back(std::move(hi));
        }
        return out;
    }


    uintptr_t get_remote_export(HANDLE process, const std::string& module_name, const std::string& function_name) {
        HMODULE modules[1024];
        DWORD needed = 0;

        if (!memory::enum_process_modules_ex(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
            std::cout << "[get_remote_export] Failed: EnumProcessModulesEx\n";
            return 0;
        }

        int module_count = needed / sizeof(HMODULE);

        char name_buf[MAX_PATH] = {};
        uintptr_t remote_base = 0;

        for (int i = 0; i < module_count; ++i) {
            if (!memory::get_module_base_name_a(process, modules[i], name_buf, sizeof(name_buf)))
                continue;

            if (_stricmp(name_buf, module_name.c_str()) == 0) {
                remote_base = reinterpret_cast<uintptr_t>(modules[i]);
                break;
            }
        }

        if (!remote_base) {
            std::cout << "[get_remote_export] Failed: Could not find module " << module_name << "\n";
            return 0;
        }

        IMAGE_DOS_HEADER dos = {};
        if (!memory::read_process_memory(process, (LPCVOID)remote_base, &dos, sizeof(dos), nullptr) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
            std::cout << "[get_remote_export] Failed: Invalid DOS header\n";
            return 0;
        }

        IMAGE_NT_HEADERS nt = {};
        if (!memory::read_process_memory(process, (LPCVOID)(remote_base + dos.e_lfanew), &nt, sizeof(nt), nullptr) || nt.Signature != IMAGE_NT_SIGNATURE) {
            std::cout << "[get_remote_export] Failed: Invalid NT header\n";
            return 0;
        }

        DWORD export_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD export_size = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (!export_rva || !export_size) {
            std::cout << "[get_remote_export] Failed: No export directory\n";
            return 0;
        }

        uintptr_t export_base = remote_base + export_rva;

        IMAGE_EXPORT_DIRECTORY export_dir = {};
        if (!memory::read_process_memory(process, (LPCVOID)export_base, &export_dir, sizeof(export_dir), nullptr)) {
            std::cout << "[get_remote_export] Failed: Unable to read export directory\n";
            return 0;
        }

        std::vector<DWORD> name_rvas(export_dir.NumberOfNames);
        if (!memory::read_process_memory(process, (LPCVOID)(remote_base + export_dir.AddressOfNames), name_rvas.data(), name_rvas.size() * sizeof(DWORD), nullptr)) {
            std::cout << "[get_remote_export] Failed: Unable to read export names\n";
            return 0;
        }

        std::vector<WORD> ordinals(export_dir.NumberOfNames);
        if (!memory::read_process_memory(process, (LPCVOID)(remote_base + export_dir.AddressOfNameOrdinals), ordinals.data(), ordinals.size() * sizeof(WORD), nullptr)) {
            std::cout << "[get_remote_export] Failed: Unable to read ordinals\n";
            return 0;
        }

        std::vector<DWORD> function_rvas(export_dir.NumberOfFunctions);
        if (!memory::read_process_memory(process, (LPCVOID)(remote_base + export_dir.AddressOfFunctions), function_rvas.data(), function_rvas.size() * sizeof(DWORD), nullptr)) {
            std::cout << "[get_remote_export] Failed: Unable to read function addresses\n";
            return 0;
        }

        for (DWORD i = 0; i < export_dir.NumberOfNames; ++i) {
            char func_name[256] = {};
            if (!memory::read_process_memory(process, (LPCVOID)(remote_base + name_rvas[i]), func_name, sizeof(func_name) - 1, nullptr))
                continue;

            if (function_name == func_name) {
                WORD ordinal = ordinals[i];
                if (ordinal >= function_rvas.size()) {
                    std::cout << "[get_remote_export] Failed: Invalid ordinal index\n";
                    return 0;
                }

                DWORD func_rva = function_rvas[ordinal];
                uintptr_t resolved = remote_base + func_rva;

                // Check for forwarder string
                if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                    char forwarder_str[256] = {};
                    if (!memory::read_process_memory(process, (LPCVOID)resolved, forwarder_str, sizeof(forwarder_str) - 1, nullptr)) {
                        std::cout << "[get_remote_export] Failed: Could not read forwarder string\n";
                        return 0;
                    }

                    std::string forwarder(forwarder_str);
                    size_t dot_pos = forwarder.find('.');
                    if (dot_pos == std::string::npos) {
                        std::cout << "[get_remote_export] Failed: Malformed forwarder string: \"" << forwarder << "\"\n";
                        return 0;
                    }

                    std::string fwd_module = forwarder.substr(0, dot_pos) + ".dll";
                    std::string fwd_func = forwarder.substr(dot_pos + 1);
                    std::cout << "[get_remote_export] Forwarded: " << function_name << " -> " << fwd_module << "!" << fwd_func << "\n";
                    return get_remote_export(process, fwd_module, fwd_func);
                }

                return resolved;
            }
        }

        std::cout << "[get_remote_export] Failed: Function not found: " << function_name << "\n";
        return 0;
    }

    std::vector<std::pair<std::string, uintptr_t>> get_remote_modules(HANDLE process) {
        std::vector<std::pair<std::string, uintptr_t>> modules_list;
        HMODULE modules[1024];
        DWORD needed = 0;
        if (!memory::enum_process_modules_ex(process, modules, sizeof(modules), &needed, LIST_MODULES_ALL)) {
            std::cout << "[+] get_remote_modules Failed: EnumProcessModulesEx\n";
            return modules_list;
        }
        int module_count = needed / sizeof(HMODULE);
        char name_buf[MAX_PATH] = {};
        for (int i = 0; i < module_count; ++i) {
            if (!memory::get_module_base_name_a(process, modules[i], name_buf, sizeof(name_buf))) {
                continue;
            }
            std::string module_name = name_buf;
            uintptr_t module_base = reinterpret_cast<uintptr_t>(modules[i]);
            modules_list.emplace_back(module_name, module_base);
        }
        return modules_list;
    }

    HMODULE loadlibrary_ex_a_remote(HANDLE process, const std::string& dll_path)
    {
        shellcode_manager scm(process);

        BYTE shellcode[] = {
            0x48, 0x83, 0xEC, 0x28,               // sub rsp, 0x28         ; align the johnson (pmo)

            0x48, 0xB9, 0,0,0,0,0,0,0,0,          // mov rcx, <dll_path>   ; arg1
            0x48, 0x31, 0xD2,                    // xor rdx, rdx          ; arg2 = NULL
            0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,  // mov r8d, 1             ; arg3 = flags (0x1) (calling with this flag so it does not get executed or anything, causes problems when hollowing, change to 0 if u dont want this)

            0x48, 0xB8, 0,0,0,0,0,0,0,0,          // mov rax, <LoadLibraryExA>
            0xFF, 0xD0,                          // call rax

            0x48, 0x89, 0x05, 0x05, 0x00, 0x00, 0x00,  // mov [rip+0x5], rax
            0x48, 0x83, 0xC4, 0x28,                     // add rsp, 0x28         ; restore stack (pmo)
            0xC3,                                   // ret

            0,0,0,0,0,0,0,0
        };

        const size_t shellcode_size = sizeof(shellcode);
        const size_t dll_len = dll_path.length() + 1;

        // Allocate space for shellcode + DLL path (shellcode will reference it)
        size_t total_size = shellcode_size + dll_len;
        if (!scm.find_region(total_size, shellcode_manager::region_type::rwx_alloc))
        {
            std::cerr << "[-] Could not find memory for shellcode.\n";
            return nullptr;
        }

        uintptr_t shellcode_addr = scm.get_shellcode_address();
        uintptr_t dll_str_remote = shellcode_addr + shellcode_size;


        *reinterpret_cast<uint64_t*>(&shellcode[6]) = dll_str_remote;

        //uintptr_t remote_func = utils::get_remote_export(process, "Kernel32.dll", "LoadLibraryExA");
        uintptr_t remote_func = utils::get_remote_export(process, "Kernel32.dll", "LoadLibraryA");
        BYTE buffer[100];
        SIZE_T bytes_read = 0;
        if (memory::read_process_memory(process, (LPCVOID)remote_func, buffer, sizeof(buffer), &bytes_read)) {
            std::cout << "Read " << bytes_read << " bytes from 0x" << std::hex << remote_func << ": ";
            for (SIZE_T i = 0; i < bytes_read; ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
            }
            std::cout << std::endl;
        }
        else {
            std::cerr << "Failed to read memory from remote process. Error: " << GetLastError() << std::endl;
        }
        if (!remote_func)
        {
            std::cerr << "[-] Failed to resolve LoadLibraryExA.\n";
            return nullptr;
        }

        *reinterpret_cast<uint64_t*>(&shellcode[25]) = remote_func;

        // Write shellcode and DLL path
        if (!scm.write_shellcode(shellcode, sizeof(shellcode)))
        {
            std::cerr << "[-] Failed to write shellcode.\n";
            return nullptr;
        }

        SIZE_T written = 0;
        if (!memory::write_process_memory(process, (LPVOID)dll_str_remote, dll_path.c_str(), dll_len, &written) || written != dll_len)
        {
            std::cerr << "[-] Failed to write DLL path.\n";
            return nullptr;
        }

        std::cout << "[+] Shellcode and DLL path written.\n";
        scm.execute(L"ntdll.dll", "NtWaitForSingleObject");

        HMODULE remote_module = nullptr;
        SIZE_T read = 0;
        uintptr_t hmodule_addr = shellcode_addr + sizeof(shellcode) - sizeof(HMODULE);

        if (!memory::read_process_memory(process, (LPCVOID)hmodule_addr, &remote_module, sizeof(remote_module), &read) || read != sizeof(remote_module))
        {
            std::cerr << "[-] Failed to read remote HMODULE.\n";
            return nullptr;
        }
        scm.~shellcode_manager();
        return remote_module;
    }

}