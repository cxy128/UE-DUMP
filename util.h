#pragma once

#include "Windows.h"
#include "common.h"

//0x10 bytes (sizeof)
struct  UNICODE_STRING {

	USHORT Length;                                                          //0x0
	USHORT MaximumLength;                                                   //0x2
	WCHAR* Buffer;                                                          //0x8
};

//0x18 bytes (sizeof)
struct CURDIR {

	UNICODE_STRING DosPath;									                //0x0
	VOID* Handle;                                                           //0x10
};

//0x448 bytes (sizeof)
struct RTL_USER_PROCESS_PARAMETERS {

	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x18
	VOID* StandardInput;                                                    //0x20
	VOID* StandardOutput;                                                   //0x28
	VOID* StandardError;                                                    //0x30
	CURDIR CurrentDirectory;                                                //0x38
	UNICODE_STRING DllPath;                                                 //0x50
	UNICODE_STRING ImagePathName;										    //0x60
};

//0x58 bytes (sizeof)
struct PEB_LDR_DATA {
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	LIST_ENTRY InLoadOrderModuleList;                               //0x10
	LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	VOID* EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	VOID* ShutdownThreadId;                                                 //0x50
};

struct PEB {

	UCHAR InheritedAddressSpace;                                              //0x0
	UCHAR ReadImageFileExecOptions;                                           //0x1
	UCHAR BeingDebugged;                                                      //0x2

	union {

		UCHAR BitField;                                                       //0x3

		struct {

			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR IsProtectedProcessLight : 1;                                //0x3
			UCHAR IsLongPathAwareProcess : 1;                                 //0x3
		};
	};

	UCHAR Padding0[4];                                                        //0x4
	VOID* Mutant;                                                             //0x8
	VOID* ImageBaseAddress;                                                   //0x10
	PEB_LDR_DATA* Ldr;                                              //0x18
	RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
};

bool InitSystemRoutineAddress();

unsigned __int64 GetSystemModuleBaseAddress(const char* ModuleName);
