#include <Windows.h>
#include <iostream>
#include "intrin.h"
#include "util.h"
#include "dump.h"

static bool GetName(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, std::string& strName) {

	NTSTATUS Status = STATUS_SUCCESS;

	FName CurrentFName = {};
	Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(UObjectAddress + 0x18), &CurrentFName, sizeof(FName), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	unsigned __int64 GNameId = 0;
	Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GName - 8), &GNameId, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	auto BlockIndex = CurrentFName.ComparisonIndex >> 0x10llu;
	auto Offset = CurrentFName.ComparisonIndex & 0xffffllu;
	//if ((BlockIndex > (GNameId & 0xffffffff)) || (Offset > ((GNameId >> 32) & 0xffffffff))) {
	//	return false;
	//}

	unsigned __int64 Block = 0;
	Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GName + BlockIndex * 8llu), &Block, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	FNameEntry NameEntry = {};
	Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(Block + Offset * 2), &NameEntry, sizeof(FNameEntry), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	if (NameEntry.Header.Len < 1 || NameEntry.Header.Len > 0xff) {
		return false;
	}

	strName.assign(NameEntry.name.AnsiName, NameEntry.Header.Len);

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

	Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(UObjectAddress + 0x10), &ClassPrivate, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	return GetName(ProcessHandle, ClassPrivate, ClassName);
}

static bool GetOuterPrivateName(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, std::string& OuterObjectName) {

	NTSTATUS Status = STATUS_SUCCESS;
	unsigned __int64 OuterUObjectAddress = 0;

	Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(UObjectAddress + 0x20), &OuterUObjectAddress, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return false;
	}

	std::string ObjectName = {};
	if (!GetName(ProcessHandle, OuterUObjectAddress, ObjectName)) {
		return false;
	}

	OuterObjectName = ObjectName;

	for (;;) {

		Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(OuterUObjectAddress + 0x20), &OuterUObjectAddress, sizeof(unsigned __int64), nullptr);
		if (NT_ERROR(Status)) {
			break;
		}

		ObjectName = "";
		if (!GetName(ProcessHandle, OuterUObjectAddress, ObjectName)) {
			break;
		}

		OuterObjectName = ObjectName + "." + OuterObjectName;
	}

	ObjectName = "";
	if (!GetName(ProcessHandle, UObjectAddress, ObjectName)) {
		return true;
	}

	OuterObjectName = OuterObjectName + "." + ObjectName;

	return true;
}

void DumpUObjectByAddress(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, unsigned __int32 DumpLength) {

	auto Peb = reinterpret_cast<PEB*>(__readgsqword(0x60));

	if (!ImageBaseAddress) {
		ImageBaseAddress = reinterpret_cast<unsigned __int64>(Peb->ImageBaseAddress);
	}

	for (unsigned __int32 i = 0; i < DumpLength; i++) {

		unsigned __int64 Address = 0;
		NTSTATUS Status = STATUS_SUCCESS;

		Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(UObjectAddress + i * 8ull), &Address, sizeof(unsigned __int64), nullptr);
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

	fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GUObjectArray + 0x14), &NumElements, sizeof(unsigned __int32), nullptr);

	return NumElements;
}

static __int32 GetMaxElements(HANDLE ProcessHandle) {

	static __int32 MaxElements = 0;
	if (MaxElements) {
		return MaxElements;
	}

	fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GUObjectArray + 0x10), &MaxElements, sizeof(unsigned __int32), nullptr);
	return MaxElements;
}

static __int32 GetNumChunks(HANDLE ProcessHandle) {

	static __int32 NumChunks = 0;
	if (NumChunks) {
		return NumChunks;
	}

	fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GUObjectArray + 0x1C), &NumChunks, sizeof(unsigned __int32), nullptr);
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
	NTSTATUS Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(GUObjectArray), &ObjectArrayArray, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return 0;
	}

	unsigned __int64 ObjectArray = 0;
	Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(ObjectArrayArray + ChunkIndex * 8llu), &ObjectArray, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return 0;
	}

	unsigned __int64 Object = 0;
	Status = fZwReadVirtualMemory(ProcessHandle, reinterpret_cast<unsigned __int64*>(ObjectArray + WithinChunkIndex * 0x18llu), &Object, sizeof(unsigned __int64), nullptr);
	if (NT_ERROR(Status)) {
		return 0;
	}

	return Object;
}

void DumpUObjectByGUObjectArray(HANDLE ProcessHandle) {

	auto Peb = reinterpret_cast<PEB*>(__readgsqword(0x60));

	if (!ImageBaseAddress) {
		ImageBaseAddress = reinterpret_cast<unsigned __int64>(Peb->ImageBaseAddress);
	}

	auto ImageFilePath = std::wstring(Peb->ProcessParameters->ImagePathName.Buffer, Peb->ProcessParameters->ImagePathName.Length);

	auto Position = ImageFilePath.find_last_of(L'\\') + 1;
	auto ImageFileName = ImageFilePath.substr(Position);

	Position = ImageFileName.find_last_of(L'.');
	ImageFileName = ImageFileName.substr(0, Position).append(L"-GObjects-Dump.txt").c_str();

	__debugbreak();

	std::wstring str{L"C:\\Users\\15669\\Desktop\\Wuthering Waves\\"};		// TODO Need to modify
	auto FileName = str.append(ImageFileName).c_str();

	auto FileHandle = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (FileHandle == nullptr || FileHandle == INVALID_HANDLE_VALUE) {
		return;
	}

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

		//std::string StaticClassName = "";

		//StaticClassName = ClassName;
		//StaticClassName += " ";
		//StaticClassName += OuterObjectName;

		//if (!OuterObjectName.compare("CoreUObject.Struct")) {

		//}

		char buf[256ull << 1] = "";
		sprintf_s(buf, 256ull << 1, "[%08lu]\taddress: %08llx\tclass: %-30s\tObjectName: %s\n", i, UObjectAddress, ClassName.c_str(), OuterObjectName.c_str());

		auto NumberOfBytesToWrite = 0ul;
		WriteFile(FileHandle, buf, strnlen_s(buf, 256), &NumberOfBytesToWrite, nullptr);

		//printf_s(buf);
	}

	FlushFileBuffers(FileHandle);

	CloseHandle(FileHandle);
}

