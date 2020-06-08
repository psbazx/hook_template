#include<Windows.h>

int inlinehook(DWORD addr, BYTE code[5], void(*func)());
int main()
{
	
	return 0;
}

int inlinehook(DWORD hookaddr, BYTE hookcode[5], void(*func)())
{
	DWORD jmpAddr = (DWORD)func - (hookaddr + 5);
	BYTE code[5];
	*(hookcode + 0) = 0xE9;
	*(DWORD*)(hookcode + 1) = jmpAddr;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	if (ReadProcessMemory(hProcess, (LPVOID)hookaddr, code, 5, NULL) == 0) {
		return false;
	}

	if (WriteProcessMemory(hProcess, (LPVOID)hookaddr, hookcode, 5, NULL) == 0) {
		return false;
	}

	return true;
}
