#include "utils.h"
#include <iostream>
#include <Windows.h>

int parseExports(PEFileData peData)
{
	std::cout << "\n== EXPORTS ==" << std::endl;

	DWORD rvaOfExports = 0;

	if (peData.is32bit == true)
	{
		rvaOfExports = ((PIMAGE_NT_HEADERS32)peData.ntHeaderPtr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else if (peData.is32bit == false) {
		rvaOfExports = ((PIMAGE_NT_HEADERS64)peData.ntHeaderPtr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}

	std::cout << "RVA export: " << rvaOfExports << std::endl;

	DWORD exportOffset = RVAToOffset(rvaOfExports, peData);
	
	std::cout << exportOffset << std::endl; 

	if (exportOffset < 0)
	{
		std::cout << "RVA value is less than 0 for the export offset, strange right? " << std::hex << "0x" << exportOffset << std::endl;
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)peData.base + exportOffset);
	
	DWORD* pAddressesofNames = (DWORD*)(peData.base + RVAToOffset(pExports->AddressOfNames, peData));

	for(int i = 0; i < pExports->NumberOfNames; i++)
	{
		std::cout << "exported: " << (char*)(peData.base + RVAToOffset(pAddressesofNames[i], peData)) << std::endl;
	}

	return 0;
};