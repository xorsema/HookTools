#pragma once
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")

namespace HookTools
{
	class IATHook
	{
	public:
		IATHook(){}
		IATHook(LPCSTR szModName, LPCSTR szFuncName, void* pFunc);
		~IATHook();
		void Init(LPCSTR szModName, LPCSTR szFuncName, void* pFunc);
		void Hook();
		void UnHook();
		PDWORD GetOriginalFunction();
	private:
		PDWORD pOFunc;
		PDWORD pNFunc;
		PDWORD* pIATEntry;
		PIMAGE_NT_HEADERS pNtHeaders;
		LPVOID iModuleBase;
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
		DWORD dwProt;
	};
}