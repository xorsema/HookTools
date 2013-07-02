#pragma once
#include <Windows.h>

namespace HookTools
{
	class JMPHook
	{
	public:
		JMPHook(void* Original, void* New);
		JMPHook();
		~JMPHook();
		void Init(void* Original, void* New);
		void Hook();
		void UnHook();

	private:
		UINT pOFunc, pNFunc;
		BYTE pOBytes[6], pNBytes[6];
		DWORD dwProt;
	};
}