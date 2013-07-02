#include <Windows.h>
#pragma comment(lib, "HookTools.lib")
#include "HookTools.h"

typedef int (WINAPI *MBW_PTR)(HWND, LPCTSTR, LPCTSTR, UINT);

HookTools::IATHook hook;
MBW_PTR pFunc;

int WINAPI myMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	return pFunc(hWnd, L"Function successfully hooked.", L"SUCCESS", MB_OK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hook.Init("user32.dll", "MessageBoxW", myMessageBox);
		pFunc = (MBW_PTR)hook.GetOriginalFunction();
		hook.Hook();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

