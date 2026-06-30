#include <iostream>
#include <Windows.h>
#include "utils.h"

int parseImports(PEFileData peData)
{
	std::cout << "\n== IMPORTS == " << std::endl;
	DWORD rvaOfImports = 0;

	if (peData.is32bit == true)
	{
		rvaOfImports = ((PIMAGE_NT_HEADERS32)peData.ntHeaderPtr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	}
	else if (peData.is32bit == false) {
		rvaOfImports = ((PIMAGE_NT_HEADERS64)peData.ntHeaderPtr)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	}
	
	DWORD importOffset = RVAToOffset(rvaOfImports, peData);
	if (importOffset < 0)
	{
		std::cout << "RVA value is less than 0, strange right? " << std::hex << "0x" << importOffset << std::endl;
		return 0;
	}
	
	PIMAGE_IMPORT_DESCRIPTOR pImports = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)peData.base + importOffset);
	while (pImports->Name != NULL)
	{

		std::wcout << "\n-- Imported functions by: " << (char*)(peData.base + RVAToOffset(pImports->Name, peData)) << std::endl;

		if (pImports->OriginalFirstThunk == 0)
		{
			pImports++;
			continue;
		}

		if (peData.is32bit == true)
		{
			PIMAGE_THUNK_DATA32 pFirstFunction = (PIMAGE_THUNK_DATA32)((BYTE*)(peData.base + RVAToOffset(pImports->OriginalFirstThunk, peData)));

			while (pFirstFunction->u1.Ordinal != NULL)
			{
				PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)(BYTE*)(peData.base + RVAToOffset(pFirstFunction->u1.AddressOfData, peData));

				if (peData.is32bit == true)
				{
					if (pFirstFunction->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
					{
						std::wcout << functionName->Hint << std::endl;
					}
					else
					{
						std::wcout << (char*)functionName->Name << std::endl;
					}
				}
				else {
					if (pFirstFunction->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
					{
						std::wcout << functionName->Hint << std::endl;
					}
					else
					{
						std::wcout << (char*)functionName->Name << std::endl;
					}
				}

				pFirstFunction++;
			}
		}
		else {

			PIMAGE_THUNK_DATA64 pFirstFunction = (PIMAGE_THUNK_DATA64)((BYTE*)(peData.base + RVAToOffset(pImports->OriginalFirstThunk, peData)));

			while (pFirstFunction->u1.Ordinal != NULL)
			{
				PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)(BYTE*)(peData.base + RVAToOffset(pFirstFunction->u1.AddressOfData, peData));

				if (peData.is32bit == true)
				{
					if (pFirstFunction->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
					{
						std::wcout << IMAGE_ORDINAL32(pFirstFunction->u1.Ordinal) << std::endl;
					}
					else
					{
						std::wcout << (char*)functionName->Name << std::endl;
					}
				}
				else {
					if (pFirstFunction->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
					{
						std::wcout << IMAGE_ORDINAL64(pFirstFunction->u1.Ordinal) << std::endl;
					}
					else
					{
						std::wcout << (char*)functionName->Name << std::endl;
					}
				}

				pFirstFunction++;
			}
		}
		
		pImports++;
	}

	std::cout << "imports end" << std::endl;
	return 0;
}