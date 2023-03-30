#include <Windows.h>
#include <stdio.h>


typedef HMODULE(WINAPI* LOAD_LIBRARY_W)(LPCWSTR);

int main()
{
	LoadLibraryW(L"ntdll.dll");

	char *krnl32 = "KERNEL32.dll";
	int	krnl32Len = 12;

	char *loadLibraryWstr = "LoadLibraryW";
	int loadLibraryWstrLen = 12;

	char *getModuleHandleWstr = "GetModuleHandleW";
	int getModuleHandleWstrLen = 16;

	char *getProcAddressStr = "GetProcAddress";
	int getProcAddressStrLen = 14;

	DWORD_PTR pLoadLibraryWaddr;
	DWORD_PTR pGetModuleHandleWaddr;
	DWORD_PTR pGetProcAddressAddr;

	LPVOID imageBase = GetModuleHandleA(NULL); // image base, start of the loaded code (?)
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase; // dos headers
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew); // ntHeaders are in e_lfanew

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // IAT
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase); // img descriptor

	LPCSTR currentLibraryName = NULL;
	PIMAGE_IMPORT_BY_NAME functionNameStruct = NULL;

	while (importDescriptor->Name != NULL) // run until library name is not null, meaning we have libraries
	{

		currentLibraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase; // get name of library

		// check if it's kernel32.dll
		int libraryFound = 1;

		for (int i = 0; i < krnl32Len; i++)
		{
			if (krnl32[i] != currentLibraryName[i])
			{
				libraryFound = 0;
				break;
			}
		}

		if (libraryFound == 0)
		{
			importDescriptor++;
			continue;
		}

		printf("%s", currentLibraryName);
		// this part of the code is only executed if KERNEL32.dll is found.
		
		// TODO: find function: GetModuleHandle, LoadLibraryW, GetProcAddress.

		PIMAGE_THUNK_DATA originalFirstThunk = NULL;
		PIMAGE_THUNK_DATA firstThunk = NULL;

		// thunk where the functions are located  (?)
		originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk); // the INT (Names)
		firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk); // the IAT (Addresses)

		while (originalFirstThunk->u1.AddressOfData != NULL) // run until function name is not null, meaning we have functions
		{

			functionNameStruct = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData); // name of function
			LPCSTR currentFunctionName = functionNameStruct->Name;

			printf("%s\n", currentFunctionName);

			int functionFound = 1;

			// find LoadLibraryW
			for (int i = 0; i < loadLibraryWstrLen; i++)
			{
				if (loadLibraryWstr[i] != currentFunctionName[i])
				{
					functionFound = 0;
					break;
				}
			}

			if (functionFound)
			{
				pLoadLibraryWaddr = firstThunk->u1.Function;
				printf("found llw %x\n", pLoadLibraryWaddr);
			}

			functionFound = 1;

			// find GetModuleHandleW
			for (int i = 0; i < getModuleHandleWstrLen; i++)
			{
				if (getModuleHandleWstr[i] != currentFunctionName[i])
				{
					functionFound = 0;
					break;
				}
			}

			if (functionFound)
			{
				pGetModuleHandleWaddr = firstThunk->u1.Function;
				printf("found gmh %x\n", pGetModuleHandleWaddr);
			}

			functionFound = 1;

			// find GetProcAddress
			for (int i = 0; i < getProcAddressStrLen; i++)
			{
				if (getProcAddressStr[i] != currentFunctionName[i])
				{
					functionFound = 0;
					break;
				}
			}

			if (functionFound)
			{
				pGetProcAddressAddr = firstThunk->u1.Function;
				printf("found gpa %x\n", pGetProcAddressAddr);
			}

			// increase to go over the next functions.
			originalFirstThunk++;
			firstThunk++;
		}

		break; // break cuz we found the functions.
	}

	

	return 0;
}