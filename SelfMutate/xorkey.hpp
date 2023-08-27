#pragma once

typedef struct XORKEY_ {
	DWORD len;
	DWORD data_len;
	unsigned char key[];
} XORKEY;