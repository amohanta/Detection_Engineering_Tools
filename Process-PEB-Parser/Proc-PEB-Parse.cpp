#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Structures

bool enableDebugPriv()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
        CloseHandle(hToken);
        return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }
    return true;
}



typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    ULONG_PTR Buffer;
} UNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    // More fields can be added if needed
} PEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PEB* PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

// Function pointer for NtQueryInformationProcess
typedef NTSTATUS(WINAPI* PNTQUERYINFORMATIONPROCESS)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

int main(int argc, char* argv[]) {
    enableDebugPriv();
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process with PID %d. Error: %lu\n", pid, GetLastError());
        return 1;
    }

    // Get NtQueryInformationProcess
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) {
        printf("[-] Failed to get handle to ntdll.dll\n");
        CloseHandle(hProcess);
        return 1;
    }

    PNTQUERYINFORMATIONPROCESS NtQueryInformationProcess =
        (PNTQUERYINFORMATIONPROCESS)GetProcAddress(hNtDll, "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[-] Failed to get NtQueryInformationProcess address\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Get the PEB address
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
    if (status != 0) {
        printf("[-] NtQueryInformationProcess failed. NTSTATUS: 0x%08X\n", status);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] PEB Address: %p\n", pbi.PebBaseAddress);

    // Read the PEB
    PEB peb = { 0 };
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        printf("[-] Failed to read PEB. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] BeingDebugged: %d\n", peb.BeingDebugged);
    printf("[+] ProcessParameters: %p\n", peb.ProcessParameters);

    // Read the ProcessParameters
    RTL_USER_PROCESS_PARAMETERS procParams = { 0 };
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), &bytesRead)) {
        printf("[-] Failed to read RTL_USER_PROCESS_PARAMETERS. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Read and print CommandLine string
    WCHAR commandLine[1024] = { 0 };
    if (procParams.CommandLine.Length > 0 && procParams.CommandLine.Length < sizeof(commandLine)) {
        if (!ReadProcessMemory(hProcess, (LPCVOID)procParams.CommandLine.Buffer, commandLine, procParams.CommandLine.Length, &bytesRead)) {
            printf("[-] Failed to read CommandLine string. Error: %lu\n", GetLastError());
        }
        else {
            wprintf(L"[+] CommandLine: %.*s\n", procParams.CommandLine.Length / 2, commandLine);
        }
    }

    // Read and print ImagePathName
    WCHAR imagePath[1024] = { 0 };
    if (procParams.ImagePathName.Length > 0 && procParams.ImagePathName.Length < sizeof(imagePath)) {
        if (!ReadProcessMemory(hProcess, (LPCVOID)procParams.ImagePathName.Buffer, imagePath, procParams.ImagePathName.Length, &bytesRead)) {
            printf("[-] Failed to read ImagePathName. Error: %lu\n", GetLastError());
        }
        else {
            wprintf(L"[+] ImagePathName: %.*s\n", procParams.ImagePathName.Length / 2, imagePath);
        }
    }

    CloseHandle(hProcess);
    return 0;
}
