#include <Windows.h>
#include <iostream>
#include <codecvt>
#include <string>
#include "util.h"
#include "dump.h"

HANDLE ProcessHandle;

static bool GetProcessHandle(DWORD ProcessId) {

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
	if (!ProcessHandle) {
		return false;
	}

	return true;
}

int main() {

	if (!InitSystemRoutineAddress()) {
		__debugbreak();
		return 0;
	}

	if (!GetProcessHandle(0xffffffff)) {
		__debugbreak();
		return 0;
	}

	//unsigned __int64 UObjectAddress = 0x1EAAF686140;
	//DumpUObjectByAddress(ProcessHandle, UObjectAddress, 1000);

	DumpUObjectByGUObjectArray(ProcessHandle);

	return 0;
}