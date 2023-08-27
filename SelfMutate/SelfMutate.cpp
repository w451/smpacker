#include "pefile.hpp"
#include "xorkey.hpp"
#include "embed.hpp"

using namespace std;

XORKEY* getKey(int len) {
	XORKEY* xk = (XORKEY*)malloc(2 + len);
	xk->len = len;
	for (WORD x = 0; x < len; x++) {
		unsigned __int64 val = 0;
		_rdrand64_step(&val);
		xk->key[x] = (val % 0xff) + 1;
	}
	return xk;
}

void applyKey(ULONG64 length, BYTE* data, XORKEY* key) {
	for (ULONG64 x = 0; x < length; x++) {
		data[x] ^= key->key[x % key->len];
	}
}

bool ezWriteFile(const char* name, BYTE* data, ULONG64 size) {
	HANDLE hFile = CreateFileA(name, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Error creating file: " << GetLastError() << std::endl;
		return false;
	}

	DWORD bytesWritten;
	BOOL success = WriteFile(hFile, data, static_cast<DWORD>(size), &bytesWritten, nullptr);

	if (!success) {
		std::cerr << "Error writing to file: " << GetLastError() << std::endl;
		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);
	return true;
}



int main(int argc, char* argv[]) {
	argh::parser cmdl(argc, argv);
	string infilename;
	string outfilename;

	if (!cmdl(2) || !(cmdl(cmdl.size() - 2) >> infilename) || !(cmdl(cmdl.size() - 1) >> outfilename) || cmdl["help"]) {
		cout << "smpacker.exe [options] <inputfile> <outfile>" << endl;
		return 0;
	}

	std::ifstream infile(infilename, std::ios::binary);

	if (!infile.good()) {
		cout << "Can't open input file: " << infilename << endl;
		return 0;
	}

	infile.seekg(0, std::ios::end);
	ULONG64 length = infile.tellg();
	infile.seekg(0, std::ios::beg);

	BYTE* data = (BYTE*)malloc(length);
	infile.read((char*)data, length);
	infile.close();

	if (*(unsigned short*)data!=0x5a4d) {
		cout << "Input file is not a PE file" << endl;
		return 0;
	}

	XORKEY* key = getKey(16);
	key->data_len = length;
	applyKey(length,data,key);

	vector<PEFile::FileSection> sections;

	PEFile::FileSection data_sec = { 0 };
	data_sec.flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
	memcpy(&data_sec.name, ".data", 5);
	data_sec.size = key->len + 8 + length;
	data_sec.data = (BYTE*)malloc(data_sec.size);
	memcpy(data_sec.data, key, key->len + 8);
	memcpy(data_sec.data + key->len + 8, data, length);

	PEFile::FileSection text_sec = { 0 };
	text_sec.flags = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
	memcpy(&text_sec.name, ".text", 5);
	text_sec.size = (ULONG64)selfInjectEnd - (ULONG64)selfInject;
	text_sec.data = (BYTE*)selfInject;

	sections.push_back(data_sec);
	sections.push_back(text_sec);

	PEFile petest(sections);
	petest.setTimestamp(time(0));
	petest.setEntry(text_sec, 0);

	if (!ezWriteFile(outfilename.c_str(), petest.data, petest.currentSize)) {
		cout << "Can't write to output file: " << outfilename << endl;
		return 0;
	}

	cout << "Success :D" << endl;
	return 0;
}