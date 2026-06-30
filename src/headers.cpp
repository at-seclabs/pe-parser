#include <Windows.h>
#include <iostream>
#include "utils.h"

int parsOptionalHeader(PEFileData peData)
{
	std::cout << "\n== OPTIONAL HEADER ==" << std::endl;

	if (peData.is32bit) {
		IMAGE_OPTIONAL_HEADER32 optionalHeader = ((PIMAGE_NT_HEADERS32)peData.ntHeaderPtr)->OptionalHeader;
		std::cout << "Magic: 0x" << std::hex << optionalHeader.Magic << std::dec << std::endl;
		std::cout << "Entry point : 0x" << std::hex << optionalHeader.AddressOfEntryPoint << std::dec << std::endl;
		std::cout << "Image base : 0x" << std::hex << optionalHeader.ImageBase << std::dec << std::endl;
		std::cout << "Size of image : " << optionalHeader.SizeOfImage << std::endl;
	}
	else {
		IMAGE_OPTIONAL_HEADER64 optionalHeader = ((PIMAGE_NT_HEADERS64)peData.ntHeaderPtr)->OptionalHeader;
		std::cout << "Magic: 0x" << std::hex << optionalHeader.Magic << std::dec << std::endl;
		std::cout << "Entry point : 0x" << std::hex << optionalHeader.AddressOfEntryPoint << std::dec << std::endl;
		std::cout << "Image base : 0x" << std::hex << optionalHeader.ImageBase << std::dec << std::endl;
		std::cout << "Size of image : 0x" << std::hex << optionalHeader.SizeOfImage << std::dec << std::endl;
	}

	return 0;
}