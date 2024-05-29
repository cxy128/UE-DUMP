#include <Windows.h>
#include <iostream>
#include <codecvt>
#include <string>
#include <set>
#include "util.h"
#include "dump.h"

static HANDLE GetProcessHandle() {

	//if (ProcessId) {
	//	return OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
	//}

	HWND hwnd = FindWindowA("UnrealWindow", nullptr);
	if (!hwnd) {
		return nullptr;
	}
	
	DWORD dwProcessId = 0;
	auto ThreadId = GetWindowThreadProcessId(hwnd, &dwProcessId);
	if (!dwProcessId) {
		return nullptr;
	}

	return OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);
}

int main() {

	if (!InitSystemRoutineAddress()) {
		__debugbreak();
		return 0;
	}

	HANDLE ProcessHandle = GetProcessHandle();
	if (!ProcessHandle) {
		__debugbreak();
		return 0;
	}

	//unsigned __int64 UObjectAddress = 0x21acb12e180;
	//DumpUObjectByAddress(ProcessHandle, UObjectAddress, 300);

	DumpUObjectByGUObjectArray(ProcessHandle);

	return 0;
}