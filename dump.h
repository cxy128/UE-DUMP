#pragma once

enum {

	NAME_SIZE = 1024
};

struct FName {

	unsigned __int32 ComparisonIndex;
	unsigned __int32 Number;
};

struct FNameEntryHeader {

	unsigned __int16 bIsWide : 1;
	unsigned __int16 LowercaseProbeHash : 5;
	unsigned __int16 Len : 10;
};

struct FNameEntry {

	FNameEntryHeader Header;

	union {

		char	AnsiName[NAME_SIZE];
		wchar_t	WideName[NAME_SIZE];

	}name;
};

inline unsigned __int64 ImageBase = 0x7FF781CD0000;			// Need to modify

inline unsigned __int64 GNameOffset = 0x7440B40;			// Need to modify
inline unsigned __int64 GUObjectArrayOffset = 0x747D240;	// Need to modify

inline unsigned __int64 GName = ImageBase + GNameOffset + 0x10;
inline unsigned __int64 GUObjectArray = ImageBase + GUObjectArrayOffset + 0x10;  // 0x7FF7DA140000 + 0x747D240 + 0x10

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