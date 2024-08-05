#include <Windows.h>
#include <iostream>
#include "intrin.h"
#include "util.h"
#include "dump.h"

static bool GetName(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, std::string& strName) {

	NTSTATUS Status = STATUS_SUCCESS;

	FName NamePrivate = {};
	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(UObjectAddress + 0x18), &NamePrivate, sizeof(FName), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned __int64 GNameId = 0;
	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GName - 8), &GNameId, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	auto BlockIndex = NamePrivate.ComparisonIndex >> 0x10llu;
	auto Offset = NamePrivate.ComparisonIndex & 0xffffllu;
	if ((BlockIndex > (GNameId & 0xffffffff)) || (Offset > ((GNameId >> 32) & 0xffffffff))) {
		return false;
	}

	unsigned __int64 Block = 0;
	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GName + BlockIndex * 8llu), &Block, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned __int16 FNameEntryHeader = 0;
	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(Block + Offset * 2), &FNameEntryHeader, sizeof(unsigned __int16), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	auto Len = FNameEntryHeader >> 6;
	if (Len < 1 || Len > 0xff) {
		return false;
	}

	char Name[0x400] = "";
	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(Block + Offset * 2 + 2), Name, Len, nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	strName.assign(Name, Len);

	if (strName.find("null") != strName.npos || strName.find("None") != strName.npos || strName.empty()) {
		return false;
	}

	auto pos = strName.rfind('/');
	if (pos != std::string::npos) {
		strName = strName.substr(pos + 1);
	}

	return true;
}

static bool GetClassPrivateName(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, std::string& ClassName) {

	NTSTATUS Status = STATUS_SUCCESS;
	unsigned __int64 ClassPrivate = 0;

	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(UObjectAddress + 0x10), &ClassPrivate, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	return GetName(ProcessHandle, ClassPrivate, ClassName);
}

static bool GetOuterPrivateName(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, std::string& OuterObjectName) {

	NTSTATUS Status = STATUS_SUCCESS;
	unsigned __int64 OuterUObjectAddress = 0;

	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(UObjectAddress + 0x20), &OuterUObjectAddress, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	std::string ObjectName = {};
	if (!GetName(ProcessHandle, OuterUObjectAddress, ObjectName)) {
		return false;
	}

	OuterObjectName = ObjectName;

	for (;;) {

		Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(OuterUObjectAddress + 0x20), &OuterUObjectAddress, sizeof(unsigned __int64), nullptr);
		if (NT_ERROR(Status)) {
			break;
		}

		ObjectName.clear();
		if (!GetName(ProcessHandle, OuterUObjectAddress, ObjectName)) {
			break;
		}

		OuterObjectName = ObjectName + "." + OuterObjectName;
	}

	ObjectName.clear();
	if (!GetName(ProcessHandle, UObjectAddress, ObjectName)) {
		return true;
	}

	OuterObjectName = OuterObjectName + "." + ObjectName;

	return true;
}

void DumpUObjectByAddress(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, unsigned __int32 DumpLength) {

	for (unsigned __int32 i = 0; i < DumpLength; i++) {

		unsigned __int64 Address = 0;
		NTSTATUS Status = STATUS_SUCCESS;

		Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(UObjectAddress + i * 8ull), &Address, sizeof(unsigned __int64), nullptr);
		if (NT_ERROR(Status)) {
			continue;
		}

		std::string ClassName = {};
		if (!GetClassPrivateName(ProcessHandle, Address, ClassName)) {
			continue;
		}

		std::string OuterObjectName = {};
		if (!GetOuterPrivateName(ProcessHandle, Address, OuterObjectName)) {
			continue;
		}

		printf_s("address: %08llx\toffset: %08lx\tclass: %-26s\tObjectName %s\n", UObjectAddress + i * 8ull, i * 8, ClassName.c_str(), OuterObjectName.c_str());
	}
}

// GUObjectArray

static __int32 GetNumElements(HANDLE ProcessHandle) {

	static __int32 NumElements = 0;
	if (NumElements) {
		return NumElements;
	}

	auto Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GUObjectArray + 0x14), &NumElements, sizeof(__int32), nullptr);

	return NumElements;
}

static __int32 GetMaxElements(HANDLE ProcessHandle) {

	static __int32 MaxElements = 0;
	if (MaxElements) {
		return MaxElements;
	}

	ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GUObjectArray + 0x10), &MaxElements, sizeof(__int32), nullptr);
	return MaxElements;
}

static __int32 GetNumChunks(HANDLE ProcessHandle) {

	static __int32 NumChunks = 0;
	if (NumChunks) {
		return NumChunks;
	}

	ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GUObjectArray + 0x1C), &NumChunks, sizeof(__int32), nullptr);
	return NumChunks;
}

static bool IsValidIndex(HANDLE ProcessHandle, __int32 Index) {

	return (Index < GetNumElements(ProcessHandle) && Index >= 0) && (Index < GetMaxElements(ProcessHandle));
}

static unsigned __int64 GetObjectPtr(HANDLE ProcessHandle, __int32 Index) {

	if (!IsValidIndex(ProcessHandle, Index)) {
		return 0;
	}

	const __int32 ChunkIndex = Index / (64 * 1024);
	const __int32 WithinChunkIndex = Index % (64 * 1024);
	if (ChunkIndex > GetNumChunks(ProcessHandle)) {
		return 0;
	}

	unsigned __int64 ObjectArrayArray = 0;
	NTSTATUS Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GUObjectArray), &ObjectArrayArray, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return 0;
	}

	unsigned __int64 ObjectArray = 0;
	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(ObjectArrayArray + ChunkIndex * 8llu), &ObjectArray, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return 0;
	}

	unsigned __int64 Object = 0;
	Status = ZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(ObjectArray + WithinChunkIndex * 0x18llu), &Object, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return 0;
	}

	return Object;
}

void DumpUObjectByGUObjectArray(HANDLE ProcessHandle) {

	std::ofstream OutputFile("C:\\Users\\15669\\Desktop\\app\\UE-Object.txt", std::ofstream::out);

	for (__int32 i = 0; i < GetNumElements(ProcessHandle); i++) {

		unsigned __int64 UObjectAddress = GetObjectPtr(ProcessHandle, i);
		if (!UObjectAddress) {
			continue;
		}

		std::string ClassName = "";
		if (!GetClassPrivateName(ProcessHandle, UObjectAddress, ClassName)) {
			continue;
		}

		std::string OuterObjectName = "";
		if (!GetOuterPrivateName(ProcessHandle, UObjectAddress, OuterObjectName)) {
			continue;
		}

		char buf[PAGE_SIZE] = "";

		sprintf_s(buf, PAGE_SIZE, "[%08lu]\taddress: %08llx\tclass: %-30s\tObjectName: %s\n", i, UObjectAddress, ClassName.c_str(), OuterObjectName.c_str());

		OutputFile << buf;
	}

	OutputFile.close();
}

