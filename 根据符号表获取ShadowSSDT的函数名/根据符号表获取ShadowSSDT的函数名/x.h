#pragma once
#undef UNICODE
#include <iostream>
#include <Windows.h>
#include <ImageHlp.h>

#pragma comment(lib,"DbgHelp.lib")
#pragma comment(lib,"ImageHlp.lib")

#define SystemModuleInformationClass        11
#define STATUS_INFO_LENGTH_MISMATCH         0xC0000004L

typedef struct
{
	PVOID section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	char ImageName[256];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct
{
	ULONG ModuleCount;
	SYSTEM_MODULE Module[0];
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS
(__stdcall *ZWQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength OPTIONAL
	);

using namespace std;