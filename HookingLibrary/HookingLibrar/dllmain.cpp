//IMPORTANT: Compile in Release mode (else the hooking code will not work) and disable optimization (else the trampoline function will not work)
#include <windows.h>
#include <libloaderapi.h>
#include <psapi.h>

#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/*****************************************************************************/
/********************************PROTOTYPES***********************************/
/*****************************************************************************/
//Load library functions:
HMODULE WINAPI DummyLoadLibraryA(LPCSTR lpLibFileName);
HMODULE WINAPI MyLoadLibraryA(LPCSTR lpLibFileName);
HMODULE WINAPI DummyLoadLibraryW(LPCWSTR lpLibFileName);
HMODULE WINAPI MyLoadLibraryW(LPCWSTR lpLibFileName);
HMODULE WINAPI DummyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
HMODULE WINAPI MyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

//Create process functions:
BOOL WINAPI DummyCreateProcessW( LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
BOOL WINAPI MyCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

//Other functions that are used by the program:
void LogToDbgView(const char* format, ...);
void LogToDbgView_W(const char* format, ...);
#ifdef WIN64
BOOL PatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, __int64 bytesToSkip);
#else
BOOL PatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip);
#endif
#ifdef WIN64
BOOL UnpatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip);
#else
BOOL UnpatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip);
#endif
bool LoadInsideProcess(DWORD dwChromeProcessId);
void ListDllsInsideThisProcess();
bool InjectDllInThisProcess_x86(DWORD dwProcessId);
void ConvertToUpper(char* s);
void ConvertToUpper_W(wchar_t* s);
bool LibraryShouldNotBeLoaded_W(wchar_t* wszPath);
bool LibraryShouldNotBeLoaded(char* szPath);

/*****************************************************************************/
/*****************************GLOBAL VARIABLES********************************/
/*****************************************************************************/
HINSTANCE ghInst=NULL;

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ghInst = hModule;
        ListDllsInsideThisProcess();
#ifdef WIN64 //For x64 use a different number of bytes to skip since it requires more space
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 16);
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 16);
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 16);
        PatchFunction((char*)"kernel32.dll", (char*)"CreateProcessW", (BYTE*)MyCreateProcessW, (BYTE*)DummyCreateProcessW, 16);
#else
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 5);
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 5);
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 5);
        PatchFunction((char*)"kernel32.dll", (char*)"CreateProcessW", (BYTE*)MyCreateProcessW, (BYTE*)DummyCreateProcessW, 5);
#endif
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
#ifdef WIN64 //For x64 use a different number of bytes to skip since it requires more space
        UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 16);
        UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 16);
        UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 16);
        UnpatchFunction((char*)"kernel32.dll", (char*)"CreateProcessW", (BYTE*)MyCreateProcessW, (BYTE*)DummyCreateProcessW, 16);
#else
        UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 5);
        UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 5);
        UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 5);
        UnpatchFunction((char*)"kernel32.dll", (char*)"CreateProcessW", (BYTE*)MyCreateProcessW, (BYTE*)DummyCreateProcessW, 5);
#endif
        break;
    }
    return TRUE;
}

/*****************************************************************************/
#ifdef WIN64
BOOL PatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, __int64 bytesToSkip)
#else
BOOL PatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip)
#endif
{
    int i;
    DWORD dwOldProtect;
    HMODULE hModule = GetModuleHandleA(szDllPath);
    if (!hModule) hModule = LoadLibraryA(szDllPath);
    if (!hModule) return FALSE;
    BYTE* pPatchThisAddress = (BYTE*)GetProcAddress(hModule, szFunctionName);
    BYTE* pbTargetCode = (BYTE*)pPatchThisAddress;
    BYTE* pbReplaced = pRedirectToThisFunction;
    BYTE* pbTrampoline = trampolineFunctionPtr;
#ifdef WIN64
    VirtualProtect((void*)trampolineFunctionPtr, 14 + bytesToSkip, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#else
    VirtualProtect((void*)trampolineFunctionPtr, 5 + bytesToSkip, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#endif
    for (i = 0; i < bytesToSkip; i++) *pbTrampoline++ = *pbTargetCode++;
    pbTargetCode = (BYTE*)pPatchThisAddress;
#ifdef WIN64
    * pbTrampoline++ = 0xff; // jmp [rip+addr]
    *pbTrampoline++ = 0x25; // jmp [rip+addr]
    *((DWORD*)pbTrampoline) = 0; // addr=0
    pbTrampoline += sizeof(DWORD);
    *((ULONG_PTR*)pbTrampoline) = (ULONG_PTR)(pbTargetCode + bytesToSkip);
    VirtualProtect((void*)pPatchThisAddress, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    *pbTargetCode++ = 0xff; // jmp [rip+addr]
    *pbTargetCode++ = 0x25; // jmp [rip+addr]
    *((DWORD*)pbTargetCode) = 0; // addr=0
    pbTargetCode += sizeof(DWORD);
    *((ULONG_PTR*)pbTargetCode) = (ULONG_PTR)pbReplaced;
#else
    * pbTrampoline++ = 0xE9; // jump rel32
    *((signed int*)(pbTrampoline)) = (pbTargetCode + bytesToSkip) - (pbTrampoline + 4);
    VirtualProtect((void*)trampolineFunctionPtr, 5 + bytesToSkip, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    VirtualProtect((void*)pPatchThisAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    *pbTargetCode++ = 0xE9; // jump rel32
    *((signed int*)(pbTargetCode)) = pbReplaced - (pbTargetCode + 4);
    VirtualProtect((void*)pPatchThisAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#endif
    FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
    return TRUE;
}

/*****************************************************************************/
#ifdef WIN64
BOOL UnpatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip)
#else
BOOL UnpatchFunction(char* szDllPath, char* szFunctionName, BYTE* pRedirectToThisFunction, BYTE* trampolineFunctionPtr, int bytesToSkip)
#endif
{
    int i;
    DWORD dwOldProtect;
    HMODULE hModule = GetModuleHandleA(szDllPath);
    if (!hModule) hModule = LoadLibraryA(szDllPath);
    if (!hModule) return FALSE;
    BYTE* pPatchThisAddress = (BYTE*)GetProcAddress(hModule, szFunctionName);
    BYTE* pbTargetCode = (BYTE*)pPatchThisAddress;
    BYTE* pbReplaced = (BYTE*)pRedirectToThisFunction;
    BYTE* pbTrampoline = trampolineFunctionPtr;
#ifdef WIN64
    VirtualProtect((void*)pPatchThisAddress, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#else
    VirtualProtect((void*)pPatchThisAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
#endif
    for (i = 0; i < bytesToSkip; i++) *pbTargetCode++ = *pbTrampoline++;
    FlushInstructionCache(GetCurrentProcess(), NULL, NULL);
    return TRUE;
}

/*****************************************************************************/
HMODULE WINAPI DummyLoadLibraryA(LPCSTR lpLibFileName)
{
    //This is just a dummy body since I need the function to have some bytes in the implementation... the logic does not matter since it is never executed
    void* var1 = (void*)1;
    void* var2 = (void*)2;
    void* var3 = (void*)3;
    void* var4 = (void*)4;
    void* var5 = (void*)5;
    void* var6 = (void*)6;
    void* var7 = (void*)7;
    void* var8 = (void*)8;
    void* var9 = (void*)9;
    void* var10 = (void*)10;
    void* var11 = (void*)11;
    void* var12 = (void*)12;
    void* var13 = (void*)13;
    void* var14 = (void*)14;
    void* var15 = (void*)15;
    var1 = (char*)var2;
    var2 = (char*)var3;
    var3 = (char*)var4;
    var4 = (char*)var5;
    var5 = (char*)var6;
    var6 = (char*)var7;
    var7 = (char*)var8;
    var8 = (char*)var9;
    var9 = (char*)var10;
    var10 = (char*)var11;
    var11 = (char*)var12;
    var12 = (char*)var13;
    var13 = (char*)var14;
    var14 = (char*)var15;
    var15 = (char*)var15;
    unsigned char s[1024];
    strcpy_s((char*)s, sizeof(s), "Something to copy");
    return (HMODULE)1;
    int x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;
    x1 = 1; x1++;
    x2 = 2; x2++;
    x3 = 3; x3++;
    x4 = 4; x4++;
    x5 = 5; x5++;
    x6 = 6; x6++;
    x7 = 7; x7++;
    x8 = 8; x8++;
    x9 = 9; x9++;
    x10 = 10; x10++;
    x11 = 11; x11++;
    x12 = 12; x12++;
    char szString[512];
    strcpy_s(szString, sizeof(szString), "this is just dummy");
    if (_stricmp(szString, "something else") == 0) x12 = 7;
    else {
        char szString2[512];
        strcpy_s(szString2, sizeof(szString2), "this is just dummy else");
        if (_stricmp(szString2, "another thing") == 0) {
            x4 = 897;
        }
    }
    return 0;
}

/*****************************************************************************/
HMODULE WINAPI DummyLoadLibraryW(LPCWSTR lpLibFileName)
{
    //This is just a dummy body since I need the function to have some bytes in the implementation... the logic does not matter since it is never executed
    void* var1 = (void*)1;
    void* var2 = (void*)2;
    void* var3 = (void*)3;
    void* var4 = (void*)4;
    void* var5 = (void*)5;
    void* var6 = (void*)6;
    void* var7 = (void*)7;
    void* var8 = (void*)8;
    void* var9 = (void*)9;
    void* var10 = (void*)10;
    void* var11 = (void*)11;
    void* var12 = (void*)12;
    void* var13 = (void*)13;
    void* var14 = (void*)14;
    void* var15 = (void*)15;
    var1 = (char*)var2;
    var2 = (char*)var3;
    var3 = (char*)var4;
    var4 = (char*)var5;
    var5 = (char*)var6;
    var6 = (char*)var7;
    var7 = (char*)var8;
    var8 = (char*)var9;
    var9 = (char*)var10;
    var10 = (char*)var11;
    var11 = (char*)var12;
    var12 = (char*)var13;
    var13 = (char*)var14;
    var14 = (char*)var15;
    var15 = (char*)var15;
    unsigned char s[1024];
    strcpy_s((char*)s, sizeof(s), "Something to copy");
    return (HMODULE)1;
    int x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;
    x1 = 1; x1++;
    x2 = 2; x2++;
    x3 = 3; x3++;
    x4 = 4; x4++;
    x5 = 5; x5++;
    x6 = 6; x6++;
    x7 = 7; x7++;
    x8 = 8; x8++;
    x9 = 9; x9++;
    x10 = 10; x10++;
    x11 = 11; x11++;
    x12 = 12; x12++;
    char szString[512];
    strcpy_s(szString, sizeof(szString), "this is just dummy");
    if (_stricmp(szString, "something else") == 0) x12 = 7;
    else {
        char szString2[512];
        strcpy_s(szString2, sizeof(szString2), "this is just dummy else");
        if (_stricmp(szString2, "another thing") == 0) {
            x4 = 897;
        }
    }
    return 0;
}

/*****************************************************************************/
HMODULE WINAPI DummyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    //This is just a dummy body since I need the function to have some bytes in the implementation... the logic does not matter since it is never executed
    void* var1 = (void*)1;
    void* var2 = (void*)2;
    void* var3 = (void*)3;
    void* var4 = (void*)4;
    void* var5 = (void*)5;
    void* var6 = (void*)6;
    void* var7 = (void*)7;
    void* var8 = (void*)8;
    void* var9 = (void*)9;
    void* var10 = (void*)10;
    void* var11 = (void*)11;
    void* var12 = (void*)12;
    void* var13 = (void*)13;
    void* var14 = (void*)14;
    void* var15 = (void*)15;
    var1 = (char*)var2;
    var2 = (char*)var3;
    var3 = (char*)var4;
    var4 = (char*)var5;
    var5 = (char*)var6;
    var6 = (char*)var7;
    var7 = (char*)var8;
    var8 = (char*)var9;
    var9 = (char*)var10;
    var10 = (char*)var11;
    var11 = (char*)var12;
    var12 = (char*)var13;
    var13 = (char*)var14;
    var14 = (char*)var15;
    var15 = (char*)var15;
    unsigned char s[1024];
    strcpy_s((char*)s, sizeof(s), "Something to copy");
    return (HMODULE)1;
    int x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;
    x1 = 1; x1++;
    x2 = 2; x2++;
    x3 = 3; x3++;
    x4 = 4; x4++;
    x5 = 5; x5++;
    x6 = 6; x6++;
    x7 = 7; x7++;
    x8 = 8; x8++;
    x9 = 9; x9++;
    x10 = 10; x10++;
    x11 = 11; x11++;
    x12 = 12; x12++;
    char szString[512];
    strcpy_s(szString, sizeof(szString), "this is just dummy");
    if (_stricmp(szString, "something else") == 0) x12 = 7;
    else {
        char szString2[512];
        strcpy_s(szString2, sizeof(szString2), "this is just dummy else");
        if (_stricmp(szString2, "another thing") == 0) {
            x4 = 897;
        }
    }
    return 0;
}

/*****************************************************************************/
void LogToDbgView(const char* format, ...)
{
    char szFormattedError[8196];
    const char* szPreffix = "Hooking: ";
    va_list arguments;
    va_start(arguments, format);
    vsprintf_s(szFormattedError, format, arguments);
    va_end(arguments);
    memmove(((char*)szFormattedError) + strlen(szPreffix), szFormattedError, strlen(szFormattedError) + 1);
    memcpy(szFormattedError, szPreffix, strlen(szPreffix));
    OutputDebugStringA(szFormattedError);
}

/*****************************************************************************/
void LogToDbgView_W(const wchar_t* format, ...)
{
    wchar_t szFormattedError[8196];
    const wchar_t* szPreffix = L"Hooking: ";
    va_list arguments;
    va_start(arguments, format);
    vswprintf_s(szFormattedError, format, arguments);
    va_end(arguments);
    memmove(((char*)szFormattedError) + (wcslen(szPreffix)*2), szFormattedError, (wcslen(szFormattedError)*2) + 2);
    memcpy(szFormattedError, szPreffix, wcslen(szPreffix)*2);
    OutputDebugStringW(szFormattedError);
}

/*****************************************************************************/
HMODULE WINAPI MyLoadLibraryA(LPCSTR lpLibFileName)
{
    LogToDbgView("======================>LoadLibraryA (%s).....", lpLibFileName);
#ifdef WIN64
    UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 16);
#else
    UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 5);
#endif
    if (LibraryShouldNotBeLoaded((char*)lpLibFileName)) {
        char szToReport[1024 * 4];
        sprintf_s(szToReport, sizeof(szToReport) / sizeof(char), "Preventing this library from getting loaded:\n%s", lpLibFileName);
#ifdef WIN64
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 16);
#else
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 5);
#endif
        MessageBoxA(NULL, szToReport, "Antimalware", MB_OK | MB_SYSTEMMODAL | MB_ICONEXCLAMATION);
        return NULL;
    }
    HMODULE hToRet = LoadLibraryA(lpLibFileName);
#ifdef WIN64
    PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 16);
#else
    PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryA", (BYTE*)MyLoadLibraryA, (BYTE*)DummyLoadLibraryA, 5);
#endif
    return hToRet;
}

/*****************************************************************************/
HMODULE WINAPI MyLoadLibraryW(LPCWSTR lpLibFileName)
{
    LogToDbgView_W(L"======================>LoadLibraryW(%s).....",lpLibFileName);
#ifdef WIN64
    UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 16);
#else
    UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 5);
#endif
    if (LibraryShouldNotBeLoaded_W((wchar_t*)lpLibFileName)) {
        wchar_t wszToReport[1024 * 4];
        swprintf_s(wszToReport, sizeof(wszToReport) / sizeof(wchar_t), L"Preventing this library from getting loaded:\n%s", lpLibFileName);
#ifdef WIN64
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 16);
#else
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 5);
#endif
        MessageBoxW(NULL, wszToReport, L"Antimalware", MB_OK | MB_SYSTEMMODAL | MB_ICONEXCLAMATION);
        return NULL;
    }
    HMODULE hToRet = LoadLibraryW(lpLibFileName);
#ifdef WIN64
    PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 16);
#else
    PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryW", (BYTE*)MyLoadLibraryW, (BYTE*)DummyLoadLibraryW, 5);
#endif
    return hToRet;
}

/*****************************************************************************/
HMODULE WINAPI MyLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    LogToDbgView_W(L"======================>LoadLibraryExW(%s).....", lpLibFileName);
#ifdef WIN64
    UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 16);
#else
    UnpatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 5);
#endif
    if (LibraryShouldNotBeLoaded_W((wchar_t*)lpLibFileName)) {
        wchar_t wszToReport[1024 * 4];
        swprintf_s(wszToReport, sizeof(wszToReport) / sizeof(wchar_t), L"Preventing this library from getting loaded:\n%s", lpLibFileName);
#ifdef WIN64
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 16);
#else
        PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 5);
#endif
        MessageBoxW(NULL, wszToReport, L"Antimalware", MB_OK | MB_SYSTEMMODAL | MB_ICONEXCLAMATION);
        return NULL;
    }
    HMODULE hToRet = LoadLibraryExW(lpLibFileName, hFile, dwFlags);
#ifdef WIN64
    PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 16);
#else
    PatchFunction((char*)"kernel32.dll", (char*)"LoadLibraryExW", (BYTE*)MyLoadLibraryExW, (BYTE*)DummyLoadLibraryExW, 5);
#endif
    return hToRet;
}

/*****************************************************************************/
BOOL WINAPI DummyCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    //This is just a dummy body since I need the function to have some bytes in the implementation... the logic does not matter since it is never executed
    void* var1 = (void*)1;
    void* var2 = (void*)2;
    void* var3 = (void*)3;
    void* var4 = (void*)4;
    void* var5 = (void*)5;
    void* var6 = (void*)6;
    void* var7 = (void*)7;
    void* var8 = (void*)8;
    void* var9 = (void*)9;
    void* var10 = (void*)10;
    void* var11 = (void*)11;
    void* var12 = (void*)12;
    void* var13 = (void*)13;
    void* var14 = (void*)14;
    void* var15 = (void*)15;
    var1 = (char*)var2;
    var2 = (char*)var3;
    var3 = (char*)var4;
    var4 = (char*)var5;
    var5 = (char*)var6;
    var6 = (char*)var7;
    var7 = (char*)var8;
    var8 = (char*)var9;
    var9 = (char*)var10;
    var10 = (char*)var11;
    var11 = (char*)var12;
    var12 = (char*)var13;
    var13 = (char*)var14;
    var14 = (char*)var15;
    var15 = (char*)var15;
    unsigned char s[1024];
    strcpy_s((char*)s, sizeof(s), "Something to copy");
    return 1;
    int x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;
    x1 = 1; x1++;
    x2 = 2; x2++;
    x3 = 3; x3++;
    x4 = 4; x4++;
    x5 = 5; x5++;
    x6 = 6; x6++;
    x7 = 7; x7++;
    x8 = 8; x8++;
    x9 = 9; x9++;
    x10 = 10; x10++;
    x11 = 11; x11++;
    x12 = 12; x12++;
    char szString[512];
    strcpy_s(szString, sizeof(szString), "this is just dummy");
    if (_stricmp(szString, "something else") == 0) x12 = 7;
    else {
        char szString2[512];
        strcpy_s(szString2, sizeof(szString2), "this is just dummy else");
        if (_stricmp(szString2, "another thing") == 0) {
            x4 = 897;
        }
    }
    return 0;
}

/*****************************************************************************/
BOOL WINAPI MyCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    LogToDbgView_W(L"======================>CreateProcessW(%s).....", lpCommandLine);
#ifdef WIN64
    UnpatchFunction((char*)"kernel32.dll", (char*)"CreateProcessW", (BYTE*)MyCreateProcessW, (BYTE*)DummyCreateProcessW, 16);
#else
    UnpatchFunction((char*)"kernel32.dll", (char*)"CreateProcessW", (BYTE*)MyCreateProcessW, (BYTE*)DummyCreateProcessW, 5);
#endif
    bool bCreationFlagsHadSuspended = false;
    if ((dwCreationFlags & CREATE_SUSPENDED) == CREATE_SUSPENDED) bCreationFlagsHadSuspended = true;
    dwCreationFlags = dwCreationFlags | CREATE_SUSPENDED;
    BOOL bToRet = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
#ifdef WIN64
    PatchFunction((char*)"kernel32.dll", (char*)"CreateProcessW", (BYTE*)MyCreateProcessW, (BYTE*)DummyCreateProcessW, 16);
#else
    PatchFunction((char*)"kernel32.dll", (char*)"CreateProcessW", (BYTE*)MyCreateProcessW, (BYTE*)DummyCreateProcessW, 5);
#endif
    if (bToRet) {
        HANDLE hMapObject = NULL;
        LPVOID lpvMem = NULL;
        if (LoadInsideProcess(lpProcessInformation->dwProcessId)) {
            LogToDbgView_W(L"======================>Process %u was created. Injecting was OK...", lpProcessInformation->dwProcessId);
        }
        else {
            LogToDbgView_W(L"======================>Process %u was created. Error while injecting...", lpProcessInformation->dwProcessId);
        }
        if (bCreationFlagsHadSuspended == false) {
            DWORD dwTickStart = GetTickCount();
            ResumeThread(lpProcessInformation->hThread);
        }
        if (lpvMem) UnmapViewOfFile(lpvMem);
        if (hMapObject) CloseHandle(hMapObject);
    }
    return bToRet;
}

/*****************************************************************************/
bool LoadInsideProcess(DWORD dwProcessId)
{
    char szLibPath[1024];
    void* pLibRemote;
    DWORD hLibModule;
    BOOL bRes;
    HANDLE hThread;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (!hProcess) return false;
    BOOL bProcessWas32Bits = false;
    BOOL bIsWow64Result = IsWow64Process(hProcess, &bProcessWas32Bits);
    if (!(bIsWow64Result && bProcessWas32Bits == false)) {
        //It is an X86 process... 
        CloseHandle(hProcess);
        return InjectDllInThisProcess_x86(dwProcessId);
    }
    HMODULE hKernel32 = GetModuleHandleA("Kernel32");
    GetModuleFileNameA(ghInst, szLibPath, sizeof(szLibPath));
    pLibRemote = VirtualAllocEx(hProcess, NULL, sizeof(szLibPath),
        MEM_COMMIT, PAGE_READWRITE);
    bRes = WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath,
        sizeof(szLibPath), NULL);
    hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress((HINSTANCE)hKernel32, "LoadLibraryA"),
        pLibRemote, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &hLibModule);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pLibRemote, sizeof(szLibPath), MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}

/*****************************************************************************/
void ListDllsInsideThisProcess()
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    if (hProcess == NULL) {
        LogToDbgView_W(L"======================>While listing libraries, could not open the process (%u)",GetLastError());
        return;
    }
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        LogToDbgView_W(L"======================>At this time there are %u libraries ", cbNeeded / sizeof(HMODULE));
        // Go through each module
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i) {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                LogToDbgView_W(L"======================>Library: %s", szModName);
            }
        }
    }
    else {
        LogToDbgView_W(L"======================>Error %u enumerating modules",GetLastError());
    }
    CloseHandle(hProcess);
}

/*****************************************************************************/
void ConvertToUpper(char* s)
{
    while (*s) {
        if (*s >= 'a' && *s <= 'z')
            *s -= 'a' - 'A';
        s++;
    }
}

/*****************************************************************************/
void ConvertToUpper_W(wchar_t* s)
{
    while (*s) {
        if (*s >= L'a' && *s <= L'z')
            *s -= L'a' - L'A';
        s++;
    }
}

/*****************************************************************************/
bool InjectDllInThisProcess_x86(DWORD dwProcessId)
{ // In this case I must inject the 32 bits version of this library inside the process id that is passed by parameter. To do this, I must use a 32 bits program
    char szCommandLine[1024 * 4];
    char szLibPath_32[1024];
    char sz32BitsProgramToLaunch[1024];
    HMODULE hKernel32 = GetModuleHandleA("Kernel32");
    GetModuleFileNameA(ghInst, szLibPath_32, sizeof(szLibPath_32));
    if (strrchr(szLibPath_32, '.')) *strrchr(szLibPath_32, '.') = 0;
    else return false;
    strcat_s(szLibPath_32, sizeof(szLibPath_32), "_x86.dll");
    strcpy_s(sz32BitsProgramToLaunch, sizeof(sz32BitsProgramToLaunch), szLibPath_32);
    if (strrchr(sz32BitsProgramToLaunch, '\\') != NULL) *(strrchr(sz32BitsProgramToLaunch, '\\') + 1) = 0;
    else if (strrchr(sz32BitsProgramToLaunch, '/') != NULL) *(strrchr(sz32BitsProgramToLaunch, '/') + 1) = 0;
    else return false;
    strcat_s(sz32BitsProgramToLaunch, sizeof(sz32BitsProgramToLaunch), "Launch32Bits.exe");
    sprintf_s(szCommandLine, sizeof(szCommandLine), "\"%s\" %u \"%s\"",sz32BitsProgramToLaunch,dwProcessId, szLibPath_32);
    LogToDbgView("======================>Launching %s", szCommandLine); //TODO: borrar
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_FORCEOFFFEEDBACK;
    BOOL bProcessRet = CreateProcessA(NULL, szCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    if (bProcessRet == 0) {
        return false;
    }
    if (pi.hProcess == 0) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    return true;
}

/*****************************************************************************/
bool LibraryShouldNotBeLoaded_W(wchar_t* wszPath)
{
    wchar_t wszUppered[1024 * 4];
    wcscpy_s(wszUppered, sizeof(wszUppered) / sizeof(wchar_t), wszPath);
    ConvertToUpper_W(wszUppered);
    if (wcsstr(wszUppered, L"MALWARE")) return true;
    return false;
}

/*****************************************************************************/
bool LibraryShouldNotBeLoaded(char *szPath)
{
    char szUppered[1024 * 4];
    strcpy_s(szUppered, sizeof(szUppered) / sizeof(char), szPath);
    ConvertToUpper(szUppered);
    if (strstr(szUppered, "MALWARE")) return true;
    return false;
}
