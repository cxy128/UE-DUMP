#include <Windows.h>
#include "util.h"

bool InitSystemRoutineAddress() {

	auto Handle = GetModuleHandleA("ntdll.dll");
	if (!Handle) {
		return false;
	}

	ZwQuerySystemInformation = (fnZwQuerySystemInformation)GetProcAddress(Handle, "ZwQuerySystemInformation");
	if (!ZwQuerySystemInformation) {
		return false;
	}

	ZwAllocateVirtualMemory = (fnZwAllocateVirtualMemory)GetProcAddress(Handle, "ZwAllocateVirtualMemory");
	if (!ZwAllocateVirtualMemory) {
		return false;
	}

	ZwReadVirtualMemory = (fnZwReadVirtualMemory)GetProcAddress(Handle, "NtReadVirtualMemory");
	if (!ZwReadVirtualMemory) {
		return false;
	}

	ZwFreeVirtualMemory = (fnZwFreeVirtualMemory)GetProcAddress(Handle, "ZwFreeVirtualMemory");
	if (!ZwFreeVirtualMemory) {
		return false;
	}

	ZwWriteVirtualMemory = (fnZwWriteVirtualMemory)GetProcAddress(Handle, "ZwWriteVirtualMemory");
	if (!ZwWriteVirtualMemory) {
		return false;
	}

	return true;
}

unsigned __int64 GetSystemModuleBaseAddress(const char* ModuleName) {

	NTSTATUS Status = 0;
	unsigned long BytesReturned = 0;

	Status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, NULL, 0, &BytesReturned);

	if (Status == STATUS_INFO_LENGTH_MISMATCH) {

		RTL_PROCESS_MODULES* ModuleBuffer = nullptr;
		unsigned __int64 RegionSize = BytesReturned;

		Status = ZwAllocateVirtualMemory(GetCurrentProcess(), (void**)&ModuleBuffer, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
		if (NT_ERROR(Status)) {
			return 0;
		}

		Status = ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemModuleInformation, ModuleBuffer, BytesReturned, &BytesReturned);
		if (NT_ERROR(Status)) {
			return 0;
		}

		for (unsigned __int32 i = 0; i < ModuleBuffer->NumberOfModules; i++) {

			if (strstr(ModuleBuffer->Modules[i].FullPathName, ModuleName) != nullptr) {

				return reinterpret_cast<unsigned __int64>(ModuleBuffer->Modules[i].ImageBase);
			}
		}
	}

	return 0;
}