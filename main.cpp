#include <Windows.h>
#include <iostream>
#include <codecvt>
#include <string>
#include <set>
#include "util.h"
#include "dump.h"

static HANDLE GetProcessHandle() {

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

	InitSystemRoutineAddress();

	HANDLE ProcessHandle = GetProcessHandle();

	//unsigned __int64 UObjectAddress = 0x1f68f55c580;
	//DumpUObjectByAddress(ProcessHandle, UObjectAddress, 300);

	DumpUObjectByGUObjectArray(ProcessHandle);

	return 0;
}