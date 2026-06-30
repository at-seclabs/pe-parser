#include <Windows.h>
#include <iostream>
#include "utils.h"

PEFileData peIsValid(int argc, wchar_t* argv[])
{
	std::cout << "\n=== PE Parser v1.0 ===" << std::endl;

	struct PEFileData fileData = { 0 };

	if (argc < 2)
	{
		std::cout << "File path needed, try again..." << std::endl;
		return fileData;
	}

	LPCWSTR path = argv[1];
	std::wcout << "File: " << path << std::endl;

	// ==================================================== Create File to get handle one the file =========================================

	HANDLE hFile = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::wcout << "[-] Failed to CreateFile handle, error: " << GetLastError() << std::endl;
		fileData.isValid = 1;
		return fileData;
	}

	// ==================================================== Create File mapping =========================================

	HANDLE hMapping = CreateFileMappingW(
		hFile,
		NULL,
		PAGE_READONLY,
		0,
		0,
		NULL
	);

	if (hMapping == NULL)
	{
		std::cout << "[-] Failed file mapping, error : " << GetLastError() << std::endl;
		fileData.isValid = 1;
		return fileData;
	}

	// ==================================================== Get MapView File =========================================

	LPVOID pMappedFile = MapViewOfFile(
		hMapping,
		FILE_MAP_READ,
		0,
		0,
		0
	);

	if (pMappedFile == NULL)
	{
		std::cout << "[-] Failed to get MapView, error : " << GetLastError() << std::endl;
		fileData.isValid = 1;
		return fileData;
	}

	// ==================================================== DOS Header MZ validation =========================================

	const uint16_t ImageDosSignature = 0x5A4D;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pMappedFile;

	if (pImageDosHeader->e_magic != ImageDosSignature) {
		std::wcout << "[+] Failed e_magic signature check" << std::endl;
		fileData.isValid = 1;
		return fileData;
	}

	// ==================================================== NT HEader Signature validation =========================================

	BYTE* base = (BYTE*)pImageDosHeader;

	BYTE* ntHeaderPtr = base + pImageDosHeader->e_lfanew;

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)ntHeaderPtr;

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		std::wcout << "[+] Failed MZ signature check" << std::endl;
		fileData.isValid = 1;
		return fileData;
	}

	if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		fileData.is32bit = true;
		std::cout << "Architecture x86" << std::endl;
	}

	if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		fileData.is32bit = false;
		std::cout << "Architecture x64" << std::endl;
	}

	fileData.hFile = hFile;
	fileData.base = base;
	fileData.hMapping = hMapping;
	fileData.pImageDosHeader = pImageDosHeader;
	fileData.ntHeaderPtr = (PIMAGE_NT_HEADERS)ntHeaderPtr;

	return fileData;
}

	// ==================================================== TVA To Offset =========================================

DWORD RVAToOffset(DWORD rva, PEFileData peData)
{
	WORD totalSections = peData.ntHeaderPtr->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(peData.ntHeaderPtr);

	for (int i = 0; i < totalSections; i++)
	{
		if (rva >= pSectionHeader->VirtualAddress && rva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize) {
			return (DWORD)(rva - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;
		}
		pSectionHeader++;
	}
	return -1;
};






