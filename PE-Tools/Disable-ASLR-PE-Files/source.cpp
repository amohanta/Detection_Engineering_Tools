#include <windows.h>
#include <stdio.h>

#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040

bool UnsetDynamicBaseFlag(const char* filePath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = NULL;
    LPVOID lpBase = NULL;
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    WORD* dllChar = NULL;

    hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %s\n", filePath);
        return false;
    }

    hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) {
        printf("[-] Failed to create file mapping.\n");
        goto cleanup;
    }

    lpBase = MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!lpBase) {
        printf("[-] Failed to map view of file.\n");
        goto cleanup;
    }

    dosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature.\n");
        goto cleanup;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature.\n");
        goto cleanup;
    }

    dllChar = &ntHeaders->OptionalHeader.DllCharacteristics;
    if (*dllChar & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        printf("[+] DYNAMIC_BASE flag is set. Unsetting it...\n");
        *dllChar &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        printf("[+] Successfully unset DYNAMIC_BASE.\n");
    }
    else {
        printf("[*] DYNAMIC_BASE flag is already unset.\n");
    }

cleanup:
    if (lpBase) UnmapViewOfFile(lpBase);
    if (hMapping) CloseHandle(hMapping);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return true;
}

int main(int argc, char* argv[]) {

    printf("  Tool Name: PEASLRDisabler\n");
    printf("  Description: Disables ASLR (DYNAMIC_BASE) in PE files\n");
    printf("  Author: abhijit mohanta\n");
    if (argc != 2) {
        printf("Usage: %s <path_to_pe_file>\n", argv[0]);
        return 1;
    }

    if (UnsetDynamicBaseFlag(argv[1])) {
        printf("[+] PE file updated successfully.\n");
    }
    else {
        printf("[-] Failed to update PE file.\n");
    }

    return 0;
}
