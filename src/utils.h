#pragma once
#include <Windows.h>

struct PEFileData {
	HANDLE hFile;
	BYTE* base;
	HANDLE hMapping;
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS ntHeaderPtr;
	BOOL is32bit;
	int isValid;
};

PEFileData peIsValid(int argc, wchar_t* argv[]);
DWORD RVAToOffset(DWORD rva, PEFileData peData);