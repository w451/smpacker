#include <iostream>
#include <fstream>
#include <string>
#include <argh.h>
#include <windows.h>
#include <intrin.h>

using namespace std;

#define OFFSET_ALIGN(value, fa) (value + fa - 1) & ~(fa - 1)

class PEFile {
public:
	typedef struct FileSection_ {
		char name[8];
		BYTE* data;
		DWORD size;
		DWORD flags;
	} FileSection, PFileSection;

	BYTE* data;
	DWORD currentSize;

	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS64 nt_header;

	PIMAGE_SECTION_HEADER section_headers;
	WORD num_sections;

	void expand(DWORD offset) {
		if (offset >= currentSize) {
			DWORD newSize = OFFSET_ALIGN(offset, nt_header->OptionalHeader.FileAlignment);
			BYTE* newdata = (BYTE*)calloc(newSize, 1);

			if (!newdata) return;

			memcpy(newdata, data, currentSize);
			currentSize = newSize;
			data = newdata;

			dos_header = (PIMAGE_DOS_HEADER)data;
			nt_header = (PIMAGE_NT_HEADERS64)(data + sizeof(IMAGE_DOS_HEADER));
			section_headers = (PIMAGE_SECTION_HEADER)(data + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64));
		}
	}

	PEFile(vector<FileSection> sections) {
		DWORD currentOffset = 0;
		currentSize = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64);
		data = (BYTE*)calloc(currentSize, 1);
		

		if (!data) return;

		dos_header = (PIMAGE_DOS_HEADER)data;
		dos_header->e_magic = IMAGE_DOS_SIGNATURE;
		dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
		

		currentOffset += dos_header->e_lfanew;
		nt_header = (PIMAGE_NT_HEADERS64)(data + currentOffset);
		

		nt_header->Signature = IMAGE_NT_SIGNATURE;
		nt_header->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
		nt_header->FileHeader.SizeOfOptionalHeader = sizeof(nt_header->OptionalHeader);
		nt_header->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
		nt_header->FileHeader.NumberOfSections = sections.size();

		nt_header->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		nt_header->OptionalHeader.MajorLinkerVersion = 0xe;
		nt_header->OptionalHeader.MinorLinkerVersion = 0x1d;
		nt_header->OptionalHeader.ImageBase = 0x0000000140000000;
		nt_header->OptionalHeader.SectionAlignment = 0x1000; //Has to be 0x1000 - so different sections can have different protections
		nt_header->OptionalHeader.FileAlignment = 0x200;
		nt_header->OptionalHeader.MajorOperatingSystemVersion = 6;
		nt_header->OptionalHeader.MinorOperatingSystemVersion = 0;
		nt_header->OptionalHeader.MajorSubsystemVersion = 6;
		nt_header->OptionalHeader.MinorSubsystemVersion = 0;
		nt_header->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
		nt_header->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
		nt_header->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
		nt_header->OptionalHeader.SizeOfStackReserve = 0x100000;
		nt_header->OptionalHeader.SizeOfStackCommit = 0x1000;
		nt_header->OptionalHeader.SizeOfHeapReserve = 0x100000;
		nt_header->OptionalHeader.SizeOfHeapCommit = 0x1000;
		currentOffset += sizeof(IMAGE_NT_HEADERS64);

		section_headers = (PIMAGE_SECTION_HEADER)(data + currentOffset);

		num_sections = sections.size();
		DWORD fileAlignedOffset = OFFSET_ALIGN(currentOffset + sizeof(IMAGE_SECTION_HEADER) * num_sections, nt_header->OptionalHeader.FileAlignment);
		nt_header->OptionalHeader.SizeOfHeaders = fileAlignedOffset;
		expand(fileAlignedOffset);

		DWORD vaOffset = OFFSET_ALIGN(currentOffset + sizeof(IMAGE_SECTION_HEADER) * num_sections, nt_header->OptionalHeader.SectionAlignment);
		
		for (DWORD i = 0; i < num_sections; i++) {
			FileSection fs = sections.at(i);
			PIMAGE_SECTION_HEADER sh = section_headers + i;
			*(ULONG64*)&sh->Name = *(ULONG64*)&fs.name;
			sh->SizeOfRawData = OFFSET_ALIGN(fs.size, nt_header->OptionalHeader.FileAlignment);
			sh->Misc.VirtualSize = fs.size;
			sh->Characteristics = fs.flags;
			sh->PointerToRawData = fileAlignedOffset;
			fileAlignedOffset += sh->SizeOfRawData;
			sh->VirtualAddress = vaOffset;
			
			expand(fileAlignedOffset);
			sh = section_headers + i;
			memcpy(data + sh->PointerToRawData, fs.data, fs.size);
			vaOffset = OFFSET_ALIGN(vaOffset + sh->SizeOfRawData, nt_header->OptionalHeader.SectionAlignment);

			if ((fs.flags & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0) {
				nt_header->OptionalHeader.SizeOfInitializedData += sh->SizeOfRawData;
			}
			if ((fs.flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0) {
				nt_header->OptionalHeader.SizeOfUninitializedData += sh->SizeOfRawData;
			}
			if ((fs.flags & IMAGE_SCN_CNT_CODE) != 0) {
				nt_header->OptionalHeader.SizeOfCode += sh->SizeOfRawData;
			}
		}

		nt_header->OptionalHeader.SizeOfImage = vaOffset;
	}

	void setTimestamp(DWORD timestamp) {
		nt_header->FileHeader.TimeDateStamp = timestamp;
	}

	void setEntry(FileSection section, DWORD offset) {
		for (WORD i = 0; i < num_sections; i++) {
			PIMAGE_SECTION_HEADER sh = section_headers + i;
			if (*(ULONG64*)&sh->Name == *(ULONG64*)&section.name) {
				nt_header->OptionalHeader.AddressOfEntryPoint = sh->VirtualAddress + offset;
				nt_header->OptionalHeader.BaseOfCode = sh->VirtualAddress;
			}
		}
	}
};