#include "IATHook.h"

namespace HookTools
{
	IATHook::IATHook(LPCSTR szModName, LPCSTR szFuncName, void* pFunc)
	{
		Init(szModName, szFuncName, pFunc);
	}

	IATHook::~IATHook()
	{
		UnHook();
	}

	void IATHook::Hook()
	{
		*pIATEntry = pNFunc;
	}

	void IATHook::UnHook()
	{
		*pIATEntry = pOFunc;
	}

	PDWORD IATHook::GetOriginalFunction()
	{
		return pOFunc;
	}

	void IATHook::Init(LPCSTR szModName, LPCSTR szFuncName, void* pFunc)
	{
		pNFunc = (PDWORD)pFunc;

		//EXE base in memory
		iModuleBase = (LPVOID)GetModuleHandle(NULL);
		//NT Headers struct
		pNtHeaders = ImageNtHeader(iModuleBase);
		//RVA of the IAT header
		UINT iIatRva = (UINT) pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
		//Get the header struct
		PIMAGE_SECTION_HEADER pIatSection = ImageRvaToSection(pNtHeaders, NULL, iIatRva);

		//The first ImpDesc
		pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)iModuleBase+(pIatSection->VirtualAddress));

		//Get the ImpDesc for the module we want
		for(; pImportDesc->Characteristics; pImportDesc++)
		{
			LPSTR szName = (LPSTR) iModuleBase+(pImportDesc->Name);
			if(stricmp(szModName, szName) == 0)
			{	//pImportDesc is now the correct ImpDesc, so exit the loop
				break;
			}
		}

		//Actual addresses
		PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((DWORD)iModuleBase+(pImportDesc->FirstThunk));
		//Names/Hints
		PIMAGE_THUNK_DATA pOThunkData = (PIMAGE_THUNK_DATA)((DWORD)iModuleBase+(pImportDesc->OriginalFirstThunk));

		//The thunks are null terminated, so loop until we hit the end or find our function name
		for(; pOThunkData->u1.AddressOfData; pOThunkData++, pThunkData++)
		{
			PIMAGE_IMPORT_BY_NAME pImpByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)iModuleBase+(pOThunkData->u1.AddressOfData));
			//Don't check the name if it's by ordinal instead
			if((WORD)(pImpByName->Name) == 0x8000)
				continue;
			LPSTR szFN = (LPSTR)pImpByName->Name;
			if(stricmp(szFuncName, szFN) == 0)
				break;
		}
			
		//We've got the address!
		pIATEntry = (PDWORD*)pThunkData;

		//Save the original function address
		pOFunc = *pIATEntry;
	}
}