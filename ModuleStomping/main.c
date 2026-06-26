#include <Windows.h>
#include <stdio.h>

BOOL LoadDllFile(IN LPCWSTR lpDllName, OUT PBYTE ppModuleBase, OUT PSIZE_T pMapSize) {

}


int main(void) {
    HMODULE pPE = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pPE + pImgDosHdr->e_lfanew);

    IMAGE_FILE_HEADER ImgFileHdr = pImgNtHdrs->FileHeader;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

        
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");

    

    if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE) {
        printf("DOS Magic : 0x%04X\n", pImgDosHdr->e_magic); // 5A4D
    }

    if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE) {        // 修正: != → ==
        printf("NT Sig    : 0x%08X\n", pImgNtHdrs->Signature); // 4550
    }

    
    IMAGE_NT_OPTIONAL_HDR_MAGIC;

}