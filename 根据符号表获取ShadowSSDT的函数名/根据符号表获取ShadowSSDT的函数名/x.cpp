#include "x.h"
#include <fstream>

ULONG ImageBase;						//文件的默认基址
ULONG MemoryBase;						//文件在内存中的基址
ULONG W32pServiceTable;

HANDLE CurrentProcess;

typedef struct _SHADOWSSDT
{
	CHAR FuncName[100];
	ULONG Address;
}SHADOWSSDT, *PSHADOWSSDT;

SHADOWSSDT zty[1000];
ULONG Limit = 0;

ofstream out;

char * ReadWin32k()
{
	char FilePath[] = "C:\\Windows\\System32\\win32k.sys";			//文件的路径
	HANDLE FileHandle;						//文件的句柄
	ULONG FileSize;							//文件的大小
	CHAR *FileBuff;							//文件在硬盘的格式
	CHAR *FileMemory;						//文件在内存的格式

	FileHandle = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (FileHandle == NULL)
	{
		cout << GetLastError() << endl;
		return NULL;
	}
	FileSize = GetFileSize(FileHandle, NULL);

	if (FileSize == 0 || FileSize > 4 * 1024 * 1024)
		return NULL;

	FileBuff = new char[FileSize];

	if (!ReadFile(FileHandle, FileBuff, FileSize, &FileSize, NULL))
	{
		delete[]FileBuff;
		cout << GetLastError() << endl;
		return NULL;
	}

	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER*)FileBuff;
	if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS*)(FileBuff + DosHeader->e_lfanew);
		if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			ImageBase = NtHeader->OptionalHeader.ImageBase;
			FileMemory = new char[NtHeader->OptionalHeader.SizeOfImage];
			memcpy(FileMemory, FileBuff, NtHeader->OptionalHeader.SizeOfHeaders);
		}
		IMAGE_SECTION_HEADER * SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i, ++SectionHeader)
			memcpy(FileMemory + SectionHeader->VirtualAddress, FileBuff + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);
	}

	delete[]FileBuff;

	CloseHandle(FileHandle);
	return FileMemory;
}

BOOL InitLoadSymbols()
{
	char CurrentDir[MAX_PATH];
	char SymbolPath[MAX_PATH];

	ZeroMemory(CurrentDir, _MAX_PATH);
	ZeroMemory(SymbolPath, MAX_PATH);

	CurrentProcess = GetCurrentProcess();

	if (0 == GetCurrentDirectory(MAX_PATH, CurrentDir))
		return FALSE;

	sprintf(SymbolPath, "srv*%s\\symbols*http://msdl.microsoft.com/download/symbols", CurrentDir);

	return SymInitialize(CurrentProcess, SymbolPath, FALSE);
}

BOOL CALLBACK EnumSymRoutine(PSYMBOL_INFO psi, ULONG SymSize, PVOID Context)
{
	if (Limit == 0)							//第一次，只是为了获取W32pServiceTable的基址,这个地址上的内容就是用来初始化shadow ssdt的一系列东西
	{
		if (!strcmp(psi->Name, "W32pServiceTable"))
		{
			printf("%s-%x\n", psi->Name, psi->Address);
			W32pServiceTable = (ULONG)psi->Address;
		}
	}
	else
	{
		for (int i = 0; i < Limit; ++i)
		{
			if (zty[i].Address == psi->Address)
			{
				if (zty[i].FuncName[0] != 0)				//如果里面以前赋值过了，有可能一个函数有n个名字，这里按照windbg里面的取名逻辑（取Notification结尾的函数）
				{
					if (!strstr(zty[i].FuncName, "Notification"))
						strcpy(zty[i].FuncName, psi->Name);
					continue;
				}
					
				strcpy(zty[i].FuncName, psi->Name);
			}
		}
	}
	return TRUE;
}

BOOL EnumSymbols()
{
	char Win32k[] = "win32k.sys";
	char SymbolFile[MAX_PATH];

	ZeroMemory(SymbolFile, MAX_PATH);

	ZWQUERYSYSTEMINFORMATION  zwquerysysteminformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(LoadLibraryA("ntdll.dll"), "ZwQuerySystemInformation");
	ULONG SizeToAlloc;

	if (STATUS_INFO_LENGTH_MISMATCH != zwquerysysteminformation(SystemModuleInformationClass, NULL, 0, &SizeToAlloc))
	{
		cout << "获取需要大小失败！" << endl;
		return FALSE;
	}

	PSYSTEM_MODULE_INFORMATION ModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(SizeToAlloc);
	if (ModuleInfo == NULL)
	{
		cout << "分配内存失败！" << endl;
		return FALSE;
	}

	if (zwquerysysteminformation(SystemModuleInformationClass, ModuleInfo, SizeToAlloc, &SizeToAlloc) < 0)
	{
		cout << "获取系统模块失败！" << endl;
		return FALSE;
	}

	PSYSTEM_MODULE pModule = ModuleInfo->Module;
	for (UINT i = 0; i < ModuleInfo->ModuleCount; ++i)
	{
		if (strstr(pModule[i].ImageName, Win32k))
		{
			MemoryBase = (ULONG)pModule[i].ImageBase;
			break;
		}
	}
	if (MemoryBase == 0)
	{
		cout << Win32k << "没有被加载到系统中！" << endl;
		return FALSE;
	}
	printf("在内存中的基址是：%x\n", MemoryBase);
	/*以上利用ZwQuerySystemInformation获取win32k.sys在系统中的基址*/

	PLOADED_IMAGE pLoadImage = ImageLoad(Win32k, NULL);
	if (pLoadImage == NULL)
	{
		cout << "ImageLoad失败！" << endl;
		return FALSE;
	}
	/*加载Image到内存中，感觉这一步是多余的，如果win32k.sys没加载到内存中就加载到内存，否则返回在内存中的地址*/

	BOOL Result = SymGetSymbolFile(CurrentProcess, NULL, pLoadImage->ModuleName, sfPdb, SymbolFile, MAX_PATH, SymbolFile, MAX_PATH);
	if (!Result)
	{
		cout << "SymGetSymbolFile失败！" << endl;
		cout << GetLastError() << endl;
		return FALSE;
	}
	/*最开始设置了符号链接的位置，因此第二个可以设置为空，后面的参数是用来接收符号路径的字符串，会从你设定的路径获取符号路径（如果是下载的，也会在这一步下载）*/

	DWORD64 ImageBase64 = SymLoadModule64(CurrentProcess, pLoadImage->hFile, pLoadImage->ModuleName, NULL, (DWORD64)MemoryBase, pLoadImage->SizeOfImage);
	if (ImageBase64 == 0)
	{
		cout << "SymLoadModule失败！" << endl;
		return FALSE;
	}
	/*这个就很简单了，就是把当前系统中某个位置的文件的符号表载入进去*/

	Result = SymEnumSymbols(CurrentProcess, MemoryBase, NULL, EnumSymRoutine, NULL);
	if (!Result)
	{
		cout << "枚举失败！" << endl;
		return FALSE;
	}
	/*枚举符号表中所有的函数，回调函数是自己写的，系统会帮你填写参数*/

	return TRUE;
}

void ShowShadowSSDT(char *FileMemory)
{
	ULONG Offset = W32pServiceTable - MemoryBase;
	PULONG FunAddress = (PULONG)(FileMemory + Offset);

	for (int i = 0; FunAddress[i] > ImageBase; ++i)
	{
		zty[i].Address = FunAddress[i] - ImageBase + MemoryBase;
		++Limit;
	}
	if (Limit != 0)
	{
		BOOL Result = SymEnumSymbols(CurrentProcess, MemoryBase, NULL, EnumSymRoutine, NULL);
		if (!Result)
		{
			cout << "枚举失败！" << endl;
			return;
		}
	}
	SymUnloadModule64(CurrentProcess, MemoryBase);

	for (int i = 0; i < Limit; ++i)
	{
		printf("%d:%s -- %x\n", i, zty[i].FuncName, zty[i].Address);
		out << dec << i << ":" << zty[i].FuncName << " -- " << hex << zty[i].Address << endl;
	}
}

int main()
{
	out.open("zty.txt");
	char *FileMemory = ReadWin32k();				//这个函数是从硬盘中读取win32k.sys并且在内存中对齐排列
	printf("ImageBase is:%x\n", ImageBase);			//顺便获取下默认的对齐地址
	if (InitLoadSymbols())							//调用SymInitialize初始化Symbol的后续操作，重点就是传递当前进程句柄和符号路径
	{
		if (EnumSymbols())
			ShowShadowSSDT(FileMemory);
	}
	delete[]FileMemory;
	system("pause");
	return 0;
}