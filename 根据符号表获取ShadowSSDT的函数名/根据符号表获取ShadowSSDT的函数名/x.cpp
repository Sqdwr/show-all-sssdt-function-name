#include "x.h"
#include <fstream>

ULONG ImageBase;						//�ļ���Ĭ�ϻ�ַ
ULONG MemoryBase;						//�ļ����ڴ��еĻ�ַ
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
	char FilePath[] = "C:\\Windows\\System32\\win32k.sys";			//�ļ���·��
	HANDLE FileHandle;						//�ļ��ľ��
	ULONG FileSize;							//�ļ��Ĵ�С
	CHAR *FileBuff;							//�ļ���Ӳ�̵ĸ�ʽ
	CHAR *FileMemory;						//�ļ����ڴ�ĸ�ʽ

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
	if (Limit == 0)							//��һ�Σ�ֻ��Ϊ�˻�ȡW32pServiceTable�Ļ�ַ,�����ַ�ϵ����ݾ���������ʼ��shadow ssdt��һϵ�ж���
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
				if (zty[i].FuncName[0] != 0)				//���������ǰ��ֵ���ˣ��п���һ��������n�����֣����ﰴ��windbg�����ȡ���߼���ȡNotification��β�ĺ�����
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
		cout << "��ȡ��Ҫ��Сʧ�ܣ�" << endl;
		return FALSE;
	}

	PSYSTEM_MODULE_INFORMATION ModuleInfo = (PSYSTEM_MODULE_INFORMATION)malloc(SizeToAlloc);
	if (ModuleInfo == NULL)
	{
		cout << "�����ڴ�ʧ�ܣ�" << endl;
		return FALSE;
	}

	if (zwquerysysteminformation(SystemModuleInformationClass, ModuleInfo, SizeToAlloc, &SizeToAlloc) < 0)
	{
		cout << "��ȡϵͳģ��ʧ�ܣ�" << endl;
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
		cout << Win32k << "û�б����ص�ϵͳ�У�" << endl;
		return FALSE;
	}
	printf("���ڴ��еĻ�ַ�ǣ�%x\n", MemoryBase);
	/*��������ZwQuerySystemInformation��ȡwin32k.sys��ϵͳ�еĻ�ַ*/

	PLOADED_IMAGE pLoadImage = ImageLoad(Win32k, NULL);
	if (pLoadImage == NULL)
	{
		cout << "ImageLoadʧ�ܣ�" << endl;
		return FALSE;
	}
	/*����Image���ڴ��У��о���һ���Ƕ���ģ����win32k.sysû���ص��ڴ��оͼ��ص��ڴ棬���򷵻����ڴ��еĵ�ַ*/

	BOOL Result = SymGetSymbolFile(CurrentProcess, NULL, pLoadImage->ModuleName, sfPdb, SymbolFile, MAX_PATH, SymbolFile, MAX_PATH);
	if (!Result)
	{
		cout << "SymGetSymbolFileʧ�ܣ�" << endl;
		cout << GetLastError() << endl;
		return FALSE;
	}
	/*�ʼ�����˷������ӵ�λ�ã���˵ڶ�����������Ϊ�գ�����Ĳ������������շ���·�����ַ�����������趨��·����ȡ����·������������صģ�Ҳ������һ�����أ�*/

	DWORD64 ImageBase64 = SymLoadModule64(CurrentProcess, pLoadImage->hFile, pLoadImage->ModuleName, NULL, (DWORD64)MemoryBase, pLoadImage->SizeOfImage);
	if (ImageBase64 == 0)
	{
		cout << "SymLoadModuleʧ�ܣ�" << endl;
		return FALSE;
	}
	/*����ͺܼ��ˣ����ǰѵ�ǰϵͳ��ĳ��λ�õ��ļ��ķ��ű������ȥ*/

	Result = SymEnumSymbols(CurrentProcess, MemoryBase, NULL, EnumSymRoutine, NULL);
	if (!Result)
	{
		cout << "ö��ʧ�ܣ�" << endl;
		return FALSE;
	}
	/*ö�ٷ��ű������еĺ������ص��������Լ�д�ģ�ϵͳ�������д����*/

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
			cout << "ö��ʧ�ܣ�" << endl;
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
	char *FileMemory = ReadWin32k();				//��������Ǵ�Ӳ���ж�ȡwin32k.sys�������ڴ��ж�������
	printf("ImageBase is:%x\n", ImageBase);			//˳���ȡ��Ĭ�ϵĶ����ַ
	if (InitLoadSymbols())							//����SymInitialize��ʼ��Symbol�ĺ����������ص���Ǵ��ݵ�ǰ���̾���ͷ���·��
	{
		if (EnumSymbols())
			ShowShadowSSDT(FileMemory);
	}
	delete[]FileMemory;
	system("pause");
	return 0;
}