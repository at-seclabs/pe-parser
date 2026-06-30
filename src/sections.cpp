#include <Windows.h>
#include <iostream>
#include "utils.h"

int parseSections(PEFileData peData)
{

	WORD totalSections = peData.ntHeaderPtr->FileHeader.NumberOfSections;
	std::cout << "\n=== SECTIONS (" << totalSections << ") ===" << std::endl;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(peData.ntHeaderPtr);
	
	char sectionName[9] = {};
	
	for (int i = 0; i < totalSections; i++)
	{
		memcpy(sectionName, pSectionHeader->Name, 8);
	
		std::string permission = "[---]";
		
		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			permission[3] = 'X';
		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
			permission[1] = 'R';
		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
			permission[2] = 'W';

		std::cout << sectionName << " VA: 0x" << std::hex << pSectionHeader->VirtualAddress << " Size: 0x" << pSectionHeader->SizeOfRawData << " " << permission << std::endl;

		pSectionHeader++;

	}

	return 0;
}
