#include "HookTools.h"
#include "JMPHook.h"

namespace HookTools
{
	JMPHook::JMPHook(void* pOrig, void* pFunc)
	{
		Init(pOrig, pFunc);
	}

	JMPHook::JMPHook()
	{
	}

	JMPHook::~JMPHook()
	{
		UnHook();
	}

	void JMPHook::Init(void* pOrig, void* pFunc)
	{
		pOFunc = (UINT)pOrig;
		pNFunc = (UINT)pFunc;

		//Absolute jump to our function
		pNBytes[0] = 0x68; //push
		*(UINT*)&pNBytes[1] = (UINT)(pNFunc); //immediate DWORD
		pNBytes[5] = 0xC3; //ret

		//Get the original bytes
		VirtualProtect((LPVOID)pOFunc, 6, PAGE_EXECUTE_READWRITE, &dwProt);
		memcpy(pOBytes, (LPVOID)pOFunc, 6);
		VirtualProtect((LPVOID)pOFunc, 6, dwProt, &dwProt);
	}

	void JMPHook::Hook()
	{
		//Write our opcodes that call the new function
		VirtualProtect((LPVOID)pOFunc, 6, PAGE_EXECUTE_READWRITE, &dwProt);
		memcpy((LPVOID)pOFunc, pNBytes, 6);
		VirtualProtect((LPVOID)pOFunc, 6, dwProt, &dwProt);
	}

	void JMPHook::UnHook()
	{
		//Restore the original bytes
		VirtualProtect((LPVOID)pOFunc, 6, PAGE_EXECUTE_READWRITE, &dwProt);
		memcpy((LPVOID)pOFunc, pOBytes, 6);
		VirtualProtect((LPVOID)pOFunc, 6, dwProt, &dwProt);
	}
}