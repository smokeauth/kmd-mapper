#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <fstream>
#include <vector>
#include <psapi.h>
#include <chrono>

#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

pNtCreateThreadEx NtCreateThreadEx = nullptr;
pNtSetInformationThread NtSetInformationThread = nullptr;

#define ThreadHideFromDebugger 17
#define ThreadQuerySetWin32StartAddress 9

constexpr ULONG code_read_memory = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE8C2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG code_write_memory = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE3C7, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG code_allocate_memory = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE4C0, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG code_get_base = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE8C3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG code_protect_memory = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE9C2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG code_create_thread = CTL_CODE(FILE_DEVICE_UNKNOWN, 0xE2A8, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

#pragma pack(push, 1)
typedef struct _struct_read {
    INT32 process_identifier;
    ULONGLONG address;
    ULONGLONG buffer;
    ULONGLONG size;
} struct_read, * pstruct_read;

typedef struct _struct_write {
    INT32 process_identifier;
    ULONGLONG address;
    ULONGLONG buffer;
    ULONGLONG size;
} struct_write, * pstruct_write;

typedef struct _struct_base {
    INT32 process_identifier;
    ULONGLONG* address;
} struct_base, * pstruct_base;

typedef struct _struct_alloc {
    INT32 process_identifier;
    ULONGLONG address;
    ULONGLONG size;
    ULONG protection;
    ULONGLONG* output_address;
} struct_alloc, * pstruct_alloc;

typedef struct _struct_protect {
    INT32 process_identifier;
    ULONGLONG address;
    ULONGLONG size;
    ULONG new_protection;
    ULONG old_protection;
} struct_protect, * pstruct_protect;

typedef struct _struct_thread {
    INT32 process_identifier;
    ULONGLONG start_address;
    ULONGLONG parameter;
    ULONGLONG thread_handle;
    ULONG thread_id;
    BOOLEAN suspended;
} struct_thread, * pstruct_thread;
#pragma pack(pop)

#define DRIVER_DEVICE L"\\\\.\\kmode-injector"

std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    struct tm* tm_info = localtime(&time);
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d_%H:%M:%S", tm_info);
    return std::string(buffer);
};

bool init_nt() {
    try {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
        NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
        return NtCreateThreadEx && NtSetInformationThread;
    }
    catch (...) {
        return false;
    };
};

namespace pe {
    PBYTE rva_to_file(PBYTE base, DWORD rva, PIMAGE_NT_HEADERS nt) {
        try {
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                    DWORD offset = rva - sec[i].VirtualAddress;
                    return base + sec[i].PointerToRawData + offset;
                }
            }
            return nullptr;
        }
        catch (...) {
            return nullptr;
        };
    };
};

namespace injector {
    class driver_interface {
    private:
        HANDLE device_handle;

    public:
        driver_interface() : device_handle(INVALID_HANDLE_VALUE) {};
        ~driver_interface() { if (device_handle != INVALID_HANDLE_VALUE) CloseHandle(device_handle); };

        bool connect() {
            try {
                device_handle = CreateFileW(DRIVER_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (device_handle == INVALID_HANDLE_VALUE) return false;
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool allocate(INT32 pid, ULONGLONG& address, SIZE_T size) {
            try {
                struct_alloc data = { 0 };
                data.process_identifier = pid;
                data.address = 0;
                data.size = size;
                data.protection = PAGE_EXECUTE_READWRITE;
                data.output_address = &address;

                DWORD returned = 0;
                if (!DeviceIoControl(device_handle, code_allocate_memory, &data, sizeof(data), &data, sizeof(data), &returned, NULL)) {
                    return false;
                }
                address = data.address;
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool write(INT32 pid, ULONGLONG address, LPVOID buffer, SIZE_T size) {
            try {
                const SIZE_T CHUNK = 0x1000;
                PBYTE ptr = (PBYTE)buffer;
                ULONGLONG addr = address;
                SIZE_T remain = size;

                while (remain > 0) {
                    SIZE_T chunk_size = (remain > CHUNK) ? CHUNK : remain;
                    struct_write data = { 0 };
                    DWORD ret = 0;

                    data.process_identifier = pid;
                    data.address = addr;
                    data.buffer = (ULONGLONG)ptr;
                    data.size = chunk_size;

                    if (!DeviceIoControl(device_handle, code_write_memory, &data, sizeof(data), &data, sizeof(data), &ret, NULL)) {
                        return false;
                    }

                    ptr += chunk_size;
                    addr += chunk_size;
                    remain -= chunk_size;
                }
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool get_base(INT32 pid, ULONGLONG& base) {
            try {
                struct_base data = { 0 };
                data.process_identifier = pid;
                data.address = &base;

                DWORD returned = 0;
                if (!DeviceIoControl(device_handle, code_get_base, &data, sizeof(data), &data, sizeof(data), &returned, NULL)) {
                    return false;
                }
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool protect_memory(INT32 pid, ULONGLONG address, SIZE_T size, ULONG new_protection, ULONG& old_protection) {
            try {
                struct_protect data = { 0 };
                data.process_identifier = pid;
                data.address = address;
                data.size = size;
                data.new_protection = new_protection;

                DWORD returned = 0;
                if (!DeviceIoControl(device_handle, code_protect_memory, &data, sizeof(data), &data, sizeof(data), &returned, NULL)) {
                    return false;
                }
                old_protection = data.old_protection;
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool create_kernel_thread(INT32 pid, ULONGLONG start_address, ULONGLONG parameter) {
            try {
                struct_thread data = { 0 };
                data.process_identifier = pid;
                data.start_address = start_address;
                data.parameter = parameter;
                data.suspended = FALSE;

                std::string timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_ioctl: sending_create_thread\n";
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_ioctl: pid=" << pid << L" addr=0x" << std::hex << start_address << std::dec << L"\n";

                DWORD returned = 0;
                if (!DeviceIoControl(device_handle, code_create_thread, &data, sizeof(data), &data, sizeof(data), &returned, NULL)) {
                    timestamp = get_current_timestamp();
                    DWORD error = GetLastError();
                    std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_ioctl: device_io_control_failed\n";
                    std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_ioctl: error_code=" << error << L"\n";
                    return false;
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_ioctl: returned_bytes=" << returned << L"\n";
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_ioctl: thread_handle=0x" << std::hex << data.thread_handle << std::dec << L"\n";
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_ioctl: thread_id=" << data.thread_id << L"\n";

                return true;
            }
            catch (...) {
                std::string timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_ioctl: exception_caught\n";
                return false;
            };
        };
    };
};

namespace mapper {
    class pe_mapper {
    private:
        injector::driver_interface& driver;
        INT32 target_pid;
        HANDLE target_process;

    public:
        pe_mapper(injector::driver_interface& drv, INT32 pid, HANDLE proc)
            : driver(drv), target_pid(pid), target_process(proc) {
        };

        bool fix_relocations(PBYTE dll_data, SIZE_T dll_size, ULONGLONG base, PIMAGE_NT_HEADERS nt) {
            try {
                ULONGLONG delta = base - nt->OptionalHeader.ImageBase;
                if (delta == 0) return true;

                DWORD reloc_va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
                DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                if (!reloc_va || !reloc_size) return true;

                PBYTE reloc_section = pe::rva_to_file(dll_data, reloc_va, nt);
                if (!reloc_section) return false;

                int total = 0;
                PBYTE reloc_current = reloc_section;
                PBYTE reloc_end = reloc_section + reloc_size;

                while (reloc_current < reloc_end) {
                    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)reloc_current;
                    if (!reloc->VirtualAddress || !reloc->SizeOfBlock) break;

                    PUINT16 entries = (PUINT16)(reloc + 1);
                    int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

                    for (int i = 0; i < count; i++) {
                        UINT16 entry = entries[i];
                        int type = entry >> 12;
                        int offset = entry & 0xFFF;

                        if (type == 0) continue;

                        ULONGLONG addr = base + reloc->VirtualAddress + offset;

                        if (type == IMAGE_REL_BASED_DIR64) {
                            ULONGLONG val = *(PULONGLONG)(dll_data + reloc->VirtualAddress + offset);
                            val += delta;
                            if (!driver.write(target_pid, addr, &val, 8)) return false;
                            total++;
                        }
                        else if (type == IMAGE_REL_BASED_HIGHLOW) {
                            ULONG val = *(PULONG)(dll_data + reloc->VirtualAddress + offset);
                            val += (ULONG)delta;
                            if (!driver.write(target_pid, addr, &val, 4)) return false;
                            total++;
                        }
                    }
                    reloc_current += reloc->SizeOfBlock;
                }
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool fix_imports(PBYTE dll_data, SIZE_T dll_size, ULONGLONG base, PIMAGE_NT_HEADERS nt) {
            try {
                DWORD import_va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                DWORD import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

                if (!import_va || !import_size) return true;

                PBYTE import_section = pe::rva_to_file(dll_data, import_va, nt);
                if (!import_section) return false;

                PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)import_section;
                int modules = 0;

                while (import_desc->Name != 0) {
                    PBYTE name_ptr = pe::rva_to_file(dll_data, import_desc->Name, nt);
                    if (!name_ptr) { import_desc++; continue; }

                    char* module_name = (char*)name_ptr;

                    HMODULE module = LoadLibraryA(module_name);
                    if (!module) { import_desc++; continue; }

                    modules++;

                    PBYTE iat_ptr = pe::rva_to_file(dll_data, import_desc->FirstThunk, nt);
                    PBYTE orig_ptr = pe::rva_to_file(dll_data, import_desc->OriginalFirstThunk, nt);

                    if (!iat_ptr || !orig_ptr) { import_desc++; continue; }

                    PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)iat_ptr;
                    PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)orig_ptr;
                    int funcs = 0;

                    while (orig->u1.AddressOfData != 0) {
                        FARPROC func_addr = NULL;

                        if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                            func_addr = GetProcAddress(module, (LPCSTR)(DWORD_PTR)(orig->u1.Ordinal & 0xFFFF));
                        }
                        else {
                            PBYTE name_data_ptr = pe::rva_to_file(dll_data, (DWORD)orig->u1.AddressOfData, nt);
                            if (name_data_ptr) {
                                PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)name_data_ptr;
                                func_addr = GetProcAddress(module, import_by_name->Name);
                            }
                        }

                        if (func_addr) {
                            ULONGLONG iat_addr = base + import_desc->FirstThunk + (funcs * sizeof(ULONGLONG));
                            ULONGLONG func_ptr = (ULONGLONG)func_addr;
                            if (!driver.write(target_pid, iat_addr, &func_ptr, 8)) return false;
                            funcs++;
                        }

                        orig++;
                    }
                    import_desc++;
                }
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool create_shellcode(ULONGLONG dll_base, ULONGLONG entry_point, ULONGLONG& stub_addr) {
            try {
                if (!driver.allocate(target_pid, stub_addr, 0x1000)) return false;

                std::vector<unsigned char> shellcode;

                shellcode.push_back(0x48);
                shellcode.push_back(0x83);
                shellcode.push_back(0xEC);
                shellcode.push_back(0x28);

                shellcode.push_back(0xBA);
                shellcode.push_back(0x01);
                shellcode.push_back(0x00);
                shellcode.push_back(0x00);
                shellcode.push_back(0x00);

                shellcode.push_back(0x4D);
                shellcode.push_back(0x31);
                shellcode.push_back(0xC0);

                shellcode.push_back(0x48);
                shellcode.push_back(0xB8);
                int offset = shellcode.size();
                for (int i = 0; i < 8; i++) shellcode.push_back(0x00);

                shellcode.push_back(0xFF);
                shellcode.push_back(0xD0);

                shellcode.push_back(0x48);
                shellcode.push_back(0x83);
                shellcode.push_back(0xC4);
                shellcode.push_back(0x28);

                shellcode.push_back(0xC3);

                ULONGLONG* addr_ptr = (ULONGLONG*)(shellcode.data() + offset);
                *addr_ptr = entry_point;

                if (!driver.write(target_pid, stub_addr, shellcode.data(), shellcode.size())) return false;
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool execute_shellcode_user(ULONGLONG stub_addr, ULONGLONG param) {
            try {
                if (!init_nt()) return false;

                HANDLE thread = NULL;
                NTSTATUS status = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, target_process, (PVOID)stub_addr, (PVOID)param, 0, 0, 0, 0, NULL);

                if (status < 0) return false;

                Sleep(500);

                ULONG hide = 1;
                NtSetInformationThread(thread, ThreadHideFromDebugger, &hide, sizeof(hide));

                SetThreadPriority(thread, THREAD_PRIORITY_LOWEST);

                WaitForSingleObject(thread, 10000);
                CloseHandle(thread);
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool execute_shellcode_kernel(ULONGLONG stub_addr, ULONGLONG param) {
            try {
                std::string timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_execution: attempting\n";

                if (!driver.create_kernel_thread(target_pid, stub_addr, param)) {
                    timestamp = get_current_timestamp();
                    std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_execution: failed\n";
                    return false;
                }

                Sleep(1000);

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_execution: success\n";
                return true;
            }
            catch (...) {
                return false;
            };
        };

        bool map_dll(PBYTE dll_data, SIZE_T dll_size, bool use_kernel) {
            try {
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_data;
                if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

                PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dll_data + dos->e_lfanew);
                if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

                std::string timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] process_information: pid=" << target_pid << L"\n";

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] dll_allocation: starting\n";

                ULONGLONG base = 0;
                if (!driver.allocate(target_pid, base, nt->OptionalHeader.SizeOfImage)) {
                    timestamp = get_current_timestamp();
                    std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] dll_allocation: failed\n";
                    return false;
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] dll_allocation: success\n";
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] base_address: 0x" << std::hex << base << std::dec << L"\n";

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] headers_write: starting\n";

                if (!driver.write(target_pid, base, dll_data, nt->OptionalHeader.SizeOfHeaders)) {
                    timestamp = get_current_timestamp();
                    std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] headers_write: failed\n";
                    return false;
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] headers_write: success\n";

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] sections_write: starting\n";

                PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
                for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                    if (sec[i].SizeOfRawData > 0) {
                        if (!driver.write(target_pid, base + sec[i].VirtualAddress, dll_data + sec[i].PointerToRawData, sec[i].SizeOfRawData)) {
                            timestamp = get_current_timestamp();
                            std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] section_write: failed\n";
                            return false;
                        }
                    }
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] sections_write: success\n";

                timestamp = get_current_timestamp();
                std::string section_info = "dll_sections: ";
                for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                    section_info += std::string((char*)sec[i].Name) + ",";
                }
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] " << std::string(section_info.begin(), section_info.end()).c_str() << L"\n";

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] fix_relocations: starting\n";

                if (!fix_relocations(dll_data, dll_size, base, nt)) {
                    timestamp = get_current_timestamp();
                    std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] fix_relocations: failed\n";
                    return false;
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] fix_relocations: success\n";

                timestamp = get_current_timestamp();
                DWORD import_va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                if (import_va) {
                    PBYTE import_section = pe::rva_to_file(dll_data, import_va, nt);
                    if (import_section) {
                        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)import_section;
                        std::string imports_info = "dll_imports: ";
                        while (import_desc->Name != 0) {
                            PBYTE name_ptr = pe::rva_to_file(dll_data, import_desc->Name, nt);
                            if (name_ptr) {
                                imports_info += std::string((char*)name_ptr) + ",";
                            }
                            import_desc++;
                        }
                        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] " << std::string(imports_info.begin(), imports_info.end()).c_str() << L"\n";
                    }
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] fix_imports: starting\n";

                if (!fix_imports(dll_data, dll_size, base, nt)) {
                    timestamp = get_current_timestamp();
                    std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] fix_imports: failed\n";
                    return false;
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] fix_imports: success\n";

                ULONGLONG entry = base + nt->OptionalHeader.AddressOfEntryPoint;

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] create_shellcode: starting\n";

                ULONGLONG stub_addr = 0;
                if (!create_shellcode(base, entry, stub_addr)) {
                    timestamp = get_current_timestamp();
                    std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] create_shellcode: failed\n";
                    return false;
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] attempting_execution: addr=0x" << std::hex << stub_addr << std::dec << L"\n";

                if (use_kernel) {
                    if (!execute_shellcode_kernel(stub_addr, base)) {
                        timestamp = get_current_timestamp();
                        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] kernel_execution: failed\n";
                        return false;
                    }
                }
                else {
                    if (!execute_shellcode_user(stub_addr, base)) {
                        timestamp = get_current_timestamp();
                        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] user_execution: failed\n";
                        return false;
                    }
                }

                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] execution_status: success\n";

                return true;
            }
            catch (...) {
                std::string timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] map_dll_exception: caught\n";
                return false;
            };
        };
    };
};

int wmain(int argc, wchar_t* argv[]) {
    try {
        if (argc < 2) {
            std::wcout << L"Usage: injector.exe <dll> [proc] [--kernel]\n";
            std::cin.get();
            return 1;
        }

        injector::driver_interface driver;
        if (!driver.connect()) {
            std::string timestamp = get_current_timestamp();
            std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] driver_connection: failed\n";
            std::cin.get();
            return 1;
        }

        std::string timestamp = get_current_timestamp();
        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] driver_connection: success\n";

        std::wstring dll_path = argv[1];
        std::wstring proc_name = (argc >= 3) ? argv[2] : L"notepad.exe";

        bool use_kernel_execution = false;
        if (argc >= 4) {
            std::wstring arg3 = argv[3];
            if (arg3 == L"--kernel") {
                use_kernel_execution = true;
                timestamp = get_current_timestamp();
                std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] execution_mode: kernel\n";
            }
        }

        timestamp = get_current_timestamp();
        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] looking_for_process: " << proc_name.c_str() << L"\n";

        INT32 pid = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(snapshot, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, proc_name.c_str()) == 0) { pid = pe.th32ProcessID; break; }
                } while (Process32NextW(snapshot, &pe));
            }
            CloseHandle(snapshot);
        }

        if (!pid) {
            timestamp = get_current_timestamp();
            std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] process_status: not_found\n";
            std::cin.get();
            return 1;
        }

        timestamp = get_current_timestamp();
        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] process_status: found\n";

        HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!proc) {
            timestamp = get_current_timestamp();
            std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] process_open: failed\n";
            std::cin.get();
            return 1;
        }

        timestamp = get_current_timestamp();
        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] process_open: success\n";

        std::ifstream file(dll_path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            timestamp = get_current_timestamp();
            std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] dll_status: not_found\n";
            CloseHandle(proc);
            std::cin.get();
            return 1;
        }

        timestamp = get_current_timestamp();
        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] dll_status: found\n";

        SIZE_T size = file.tellg();
        file.seekg(0);
        PBYTE data = (PBYTE)malloc(size);
        file.read((char*)data, size);
        file.close();

        timestamp = get_current_timestamp();
        std::wcout << L"[" << std::string(timestamp.begin(), timestamp.end()).c_str() << L"] dll_information: size=" << size << L"\n";

        mapper::pe_mapper mapper(driver, pid, proc);
        bool result = mapper.map_dll(data, size, use_kernel_execution);

        free(data);
        CloseHandle(proc);

        std::cin.get();
        return result ? 0 : 1;
    }
    catch (...) {
        std::cin.get();
        return 1;
    };
}
