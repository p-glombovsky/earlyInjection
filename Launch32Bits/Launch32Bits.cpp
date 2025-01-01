//This little program just injects a given library inside a given 32 bits process. Why? Because from the x64 library
//I cannot execute this code since it must really be done from a 32 bits process. 32 bits processes can only inject 32 bits libraries, 64 bits processes can only inject x64 libraries
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>

extern int __argc;
extern char** __argv;

bool InjectLibraryInsideProcess(DWORD dwPID, char* szDllPath);

/*****************************************************************************/
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{//Usage: <Program> <ProcessId> <dll path>
	if (__argc < 3) return E_INVALIDARG;
	DWORD dwProcessId = strtoul(__argv[1], NULL, 10); //Convert the first argument 
	char *sz32BitsDllToInject = __argv[2];
	if( InjectLibraryInsideProcess(dwProcessId, sz32BitsDllToInject)) return EXIT_SUCCESS;
	return E_FAIL;
}

/*****************************************************************************/
bool InjectLibraryInsideProcess(DWORD dwPID, char* szDllPath)
{
	char szLibPath[1024];
	void* pLibRemote;
	DWORD hLibModule;
	BOOL bRes;
	HANDLE hThread;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hProcess) return false;
	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	strcpy_s(szLibPath, sizeof(szLibPath), szDllPath);

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
