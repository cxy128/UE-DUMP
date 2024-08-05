#pragma once

#include <filesystem>
#include <fstream>
#include <iomanip>

enum {

	NAME_SIZE = 1024
};

struct FName {

	unsigned __int32 ComparisonIndex;
	unsigned __int32 Number;
};

struct FNameEntryHeader {

	union {

		unsigned __int32 bIsWide : 1;
		unsigned __int32 LowercaseProbeHash : 5;
		unsigned __int32 Len : 10;
	};

	unsigned __int32 value;
};

struct FNameEntry {

	FNameEntryHeader Header;

	union {

		char AnsiName[NAME_SIZE];
		wchar_t WideName[NAME_SIZE];
	};
};

inline unsigned __int64 ImageBaseAddress = 0x7FF7DE6B0000;

inline unsigned __int64 GNameOffset = 0xBD84D40;
inline unsigned __int64 GName = ImageBaseAddress + GNameOffset + 0x10;

inline unsigned __int64 GUObjectArrayOffset = 0xBD9DD88;
inline unsigned __int64 GUObjectArray = ImageBaseAddress + GUObjectArrayOffset + 0x10;

static bool GetName(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, std::string& strName);

static bool GetClassPrivateName(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, std::string& ClassName);

static bool GetOuterPrivateName(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, std::string& OuterObjectName);

void DumpUObjectByAddress(HANDLE ProcessHandle, unsigned __int64 UObjectAddress, unsigned __int32 DumpLength);

static __int32 GetNumElements(HANDLE ProcessHandle);

static __int32 GetMaxElements(HANDLE ProcessHandle);

static __int32 GetNumChunks(HANDLE ProcessHandle);

static bool IsValidIndex(HANDLE ProcessHandle, __int32 Index);

static unsigned __int64 GetObjectPtr(HANDLE ProcessHandle, __int32 Index);

void DumpUObjectByGUObjectArray(HANDLE ProcessHandle);