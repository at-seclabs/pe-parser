#include <Windows.h>
#include <iostream>
#include "src/utils.h"
#include "src/headers.h"
#include "src/sections.h"
#include "src/imports.h"
#include "src/exports.h"

int wmain(int argc, wchar_t* argv[])
{
	PEFileData peData = peIsValid(argc, argv);
		
	if (peData.isValid != 0)
		return 1;
	
	int headers = parsOptionalHeader(peData);

	int sections = parseSections(peData);

	int imports = parseImports(peData);

	int exports = parseExports(peData);

	UnmapViewOfFile(peData.hMapping);
	
	CloseHandle(peData.hFile);

	return 0;
}