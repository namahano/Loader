#include <Windows.h>
#include <stdio.h>

#define MAX_SHELLCODE_SIZE 1024 * 1024 * 100
#define KEY 0x55

#ifdef _DEBUG
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0)
			printf("\n\t");

		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}
	printf("\n};\n\n\n");
}
#endif

void XOR(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PBYTE pbBuffer) {

	for (int i = 0; i < sPayloadSize; i++) {
		pbBuffer[i] = pPayload[i] ^ KEY;
	}
}

int wmain(int argc, wchar_t* argv[]) {

	HANDLE        hInputFile     = INVALID_HANDLE_VALUE;
	HANDLE        hOutputFile    = INVALID_HANDLE_VALUE;
	PBYTE         pbPayload      = NULL;
	PBYTE         pbEncrypted    = NULL;

	LARGE_INTEGER liFileSize     = { 0 };
	DWORD         dwPayloadSize  = 0;
	DWORD         dwBytesRead    = 0;
	DWORD         dwBytesWritten = 0;

	LPCWSTR       lpwInputPath   = NULL;
	LPCWSTR       lpwOutputPath  = NULL;
	
	int nExitCode                = EXIT_FAILURE;

	if (argc < 3) {
		printf("Usage: XOREncoder.exe <INPUT SHELLCODE FILE> <OUTPUT SHELLCODE FILE>\n");
		return EXIT_FAILURE;
	}

	lpwInputPath  = argv[1];
	lpwOutputPath = argv[2];

	hInputFile = CreateFileW(lpwInputPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW (input) failed: %lu\n", GetLastError());
		goto cleanup;
	}

	printf("[+] Opened input file: %ls\n", lpwInputPath);

	hOutputFile = CreateFileW(lpwOutputPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW (output) failed: %lu\n", GetLastError());
		goto cleanup;
	}

	printf("[+] Opened output file: %ls\n", lpwOutputPath);

	if (!GetFileSizeEx(hInputFile, &liFileSize)) {
		printf("[-] GetFileSizeEx failed: %lu\n", GetLastError());
		goto cleanup;
	}

	if (liFileSize.QuadPart > MAX_SHELLCODE_SIZE || liFileSize.QuadPart == 0) {
		printf("[-] Invalid file size: %lld\n", liFileSize.QuadPart);
		goto cleanup;
	}
	dwPayloadSize = (DWORD)liFileSize.QuadPart;
	printf("[+] File size: %lu bytes\n", dwPayloadSize);

	pbPayload = HeapAlloc(GetProcessHeap(), 0, dwPayloadSize);
	if (pbPayload == NULL) {
		printf("[-] HeapAlloc (payload) failed\n");
		goto cleanup;
	}

	if (!ReadFile(hInputFile, pbPayload, dwPayloadSize, &dwBytesRead, NULL)) {
		printf("[-] ReadFile failed: %lu\n", GetLastError());
		goto cleanup;
	}

	printf("[+] Read %lu bytes\n", dwBytesRead);

	pbEncrypted = HeapAlloc(GetProcessHeap(), 0, dwPayloadSize);
	if (pbEncrypted == NULL) {
		printf("[-] HeapAlloc (encrypted) failed\n");
		goto cleanup;
	}

	XOR(pbPayload, dwPayloadSize, pbEncrypted);
	printf("[+] XOR encryption complete\n");
	
	if (!WriteFile(hOutputFile, pbEncrypted, dwPayloadSize, &dwBytesWritten, NULL)) {
		printf("[-] WriteFile failed: %lu\n", GetLastError());
		goto cleanup;
	}
	if (dwBytesWritten != dwPayloadSize) {
		printf("[-] Partial write: %lu of %lu\n", dwBytesWritten, dwPayloadSize);
		goto cleanup;
	}
	printf("[+] Wrote %lu bytes\n", dwBytesWritten);

#ifdef _DEBUG
	PrintHexData(L"shellcode", pbEncrypted, dwPayloadSize);
#endif

	nExitCode = EXIT_SUCCESS;

cleanup:
	if (hInputFile != INVALID_HANDLE_VALUE) CloseHandle(hInputFile);
	if (hOutputFile != INVALID_HANDLE_VALUE) CloseHandle(hOutputFile);
	if (pbPayload != NULL) HeapFree(GetProcessHeap(), 0, pbPayload);
	if (pbEncrypted != NULL) HeapFree(GetProcessHeap(), 0, pbEncrypted);
	if (nExitCode == EXIT_SUCCESS) {
		printf("[+] Encoding completed successfully\n");
	}
	else {
		printf("[-] Encoding failed (exit code: %d)\n", nExitCode);
	}
	return nExitCode;
}