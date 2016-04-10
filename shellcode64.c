// shellcode64.c : extract 64-bit shellcode from 64-bit PE binary and write to file.
//
// Author: Ulf Frisk, shellcode64@frizk.net
// Github: github.com/ufrisk/shellcode64
//
// 
// MIT License
// 
// Copyright(c) 2016 Ulf Frisk
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "bcrypt.lib")

typedef unsigned __int64		QWORD;

#define SHELLCODE64_VERSION		"1.0.0"
#define KMDEXEC_MAGIC			0x3cec1337
#define KMDEXEC_VERSION			0x01
#define FLAG_EXIST				0x01
#define FLAG_OVERWRITE			0x02
#define FLAG_SHOW_BINARY		0x04
#define FLAG_IGNORE				0x08

#pragma pack(push, 1)
typedef struct tdKmdExec {
	DWORD dwMagic;
	BYTE pbChecksumSHA256[32];
	QWORD qwVersion;
	LPSTR szOutFormatPrintf;
	QWORD cbShellcode;
	PBYTE pbShellcode;
	QWORD filler[4];
} KMDEXEC, *PKMDEXEC;
#pragma pack(pop)

VOID Util_SHA256(_In_ PBYTE pb, _In_ DWORD cb, _Out_ __bcount(32) PBYTE pbHash)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
	BCryptHashData(hHash, pb, cb, 0);
	BCryptFinishHash(hHash, pbHash, 32, 0);
	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlg, 0);
}

_Success_(return) BOOL PEGetSectionRawData(_In_ HMODULE hModule, _In_ LPSTR szSection, _Out_ PDWORD pdwSectionBaseRel, _Out_ PDWORD pdwSectionSize)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if(!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { return FALSE; }
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)hModule + dosHeader->e_lfanew);
	if(!ntHeader ||
		ntHeader->Signature != IMAGE_NT_SIGNATURE ||
		ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		ntHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return FALSE;
	}
	WORD nSections = ntHeader->FileHeader.NumberOfSections;
	for(int i = 0; i < nSections; i++) {
		PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)hModule + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + i*sizeof(IMAGE_SECTION_HEADER));
		if(strcmp(sectionHeader->Name, szSection) == 0) {
			*pdwSectionBaseRel = sectionHeader->PointerToRawData;
			*pdwSectionSize = sectionHeader->Misc.VirtualSize;
			return TRUE;
		}
	}
	return FALSE;
}

BOOL ExistsDataDirectoryForbidden(_In_ HMODULE hModule)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)hModule + dosHeader->e_lfanew);
	for(DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		if(i != IMAGE_DIRECTORY_ENTRY_EXCEPTION && i != IMAGE_DIRECTORY_ENTRY_DEBUG) {
			if(ntHeader->OptionalHeader.DataDirectory[i].Size) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

_Success_(return) BOOL Util_LoadFile(_In_ LPSTR szFileName, _Out_ PBYTE* ppb, _Out_ DWORD* pcb)
{
	BOOL result;
	HANDLE hFile = CreateFileA(
		szFileName,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if(!hFile) { return FALSE; }
	*ppb = (PBYTE)LocalAlloc(LMEM_ZEROINIT, 0x400000);
	result = ReadFile(hFile, *ppb, 0x400000, pcb, NULL);
	CloseHandle(hFile);
	return result;
}

_Success_(return) BOOL Util_WriteFile(_In_ LPSTR szFileName, _In_ PBYTE pb, _In_ DWORD cb, _In_ BOOL fOverwrite)
{
	DWORD cbWritten;
	BOOL result;
	HANDLE hFile = CreateFileA(
		szFileName,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		fOverwrite ? CREATE_ALWAYS : CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if(!hFile) { return FALSE; }
	result = WriteFile(hFile, pb, cb, &cbWritten, NULL);
	CloseHandle(hFile);
	return result;
}

VOID Util_ReplaceNL(CHAR* ch, DWORD cch)
{
	for(cch -= 2; cch < 0xf0000000; cch--) {
		if(ch[cch] == '\\' && ch[cch + 1] == 'n') {
			ch[cch] = ' ';
			ch[cch + 1] = '\n';
		}
	}
}

VOID GetOptsSimple(_In_ int argc, _In_ char* argv[], _Out_ PDWORD pFlags)
{
	DWORD i = 0;
	*pFlags = 0;
	if(argc < 2 || argv[1][0] != '-') {
		return;
	}
	*pFlags |= FLAG_EXIST;
	while(argv[1][++i] != 0) {
		switch(argv[1][i]) {
		case 'o':
			*pFlags |= FLAG_OVERWRITE;
			break;
		case 'b':
			*pFlags |= FLAG_SHOW_BINARY;
			break;
		case 'i':
			*pFlags |= FLAG_IGNORE;
			break;
		}
	}
}

int main(_In_ unsigned int argc, _In_ char* argv[])
{
	DWORD flags;
	PBYTE pb, pbKmdExec, pbCode;
	DWORD cb, cbKmdExec, cbCode, cbCodeRVA;
	PKMDEXEC pKmdExec;
	CHAR szFileBIN[MAX_PATH], szFileKSH[MAX_PATH];
	LPSTR szPE, szFormat;
	DWORD cch = 0x10000;
	CHAR ch[0x10000];
	DWORD idxKshFormat;
	GetOptsSimple(argc, argv, &flags);
	idxKshFormat = (flags & FLAG_EXIST) ? 3 : 2;
	if(argc < idxKshFormat || argc > idxKshFormat + 1) {
		printf(
			"SHELLCODE64 - A MINIMAL SHELLCODE EXTRACTOR.  ( github.com/ufrisk/shellcode64 )\n" \
			"Extracts shellcode from 64-bit PE binaries (.exe) to .bin (and .ksh) files.    \n" \
			"Syntax: shellcode64 [<options>] <PE_file> [<printf_format_string_for_ksh>]     \n" \
			"The <PE_file> is the source file - usually an .exe                             \n" \
			"The <printf_format_string_for_ksh> supports \\n but not \\t and \\\\           \n" \
			"Available options: -<options> (in one single argument):                        \n" \
			"  o = overwrite existing .bin and .ksh files.                                  \n" \
			"  b = show binary output if shorter than 8kB.                                  \n" \
			"  i = ignore data directories which may invalidate the extracted shellcode.    \n" \
			"Version: %s\n\n", SHELLCODE64_VERSION);
		return 1;
	}
	szPE = argv[idxKshFormat - 1];
	szFormat = (argc <= idxKshFormat) ? "" : argv[idxKshFormat];
	memset(szFileBIN, 0, MAX_PATH);
	memset(szFileKSH, 0, MAX_PATH);
	memcpy(szFileBIN, szPE, strlen(szPE));
	memcpy(szFileKSH, szPE, strlen(szPE));
	memcpy(szFileBIN + strlen(szPE) - 3, "bin", 3);
	memcpy(szFileKSH + strlen(szPE) - 3, "ksh", 3);
	if(!(flags & FLAG_OVERWRITE) && (Util_LoadFile(szFileBIN, &pb, &cb) || Util_LoadFile(szFileKSH, &pb, &cb))) {
		printf("failed! files '%s' or '%s' already exists!\n", szFileBIN, szFileKSH);
		return 1;
	}
	if(!Util_LoadFile(szPE, &pb, &cb)) {
		printf("failed! cannot open file: %s\n", szPE);
		return 1;
	}
	if(!PEGetSectionRawData((HMODULE)pb, ".text", &cbCodeRVA, &cbCode)) {
		printf("failed! cannot parse 64-bit PE information.\n");
		return 1;
	}
	if(ExistsDataDirectoryForbidden((HMODULE)pb)) {
		if(flags & FLAG_IGNORE) {
			printf("failed! data directory which may invalidate the shellcode exists.\n");
			return 1;
		}
		printf("warning! data directory which may invalidate the shellcode exists.\n");
	}
	pbCode = pb + cbCodeRVA;
	cbKmdExec = (DWORD)(sizeof(KMDEXEC) + strlen(szFormat) + cbCode + 1);
	pbKmdExec = LocalAlloc(LMEM_ZEROINIT, cbKmdExec);
	if(!pbKmdExec) { return 1; }
	memcpy(pbKmdExec + sizeof(KMDEXEC), pbCode, cbCode);
	Util_ReplaceNL(szFormat, (DWORD)strlen(szFormat));
	memcpy(pbKmdExec + sizeof(KMDEXEC) + cbCode, szFormat, strlen(szFormat));
	pKmdExec = (PKMDEXEC)pbKmdExec;
	pKmdExec->dwMagic = KMDEXEC_MAGIC;
	pKmdExec->qwVersion = KMDEXEC_VERSION;
	pKmdExec->cbShellcode = cbCode + 0xfff;
	pKmdExec->pbShellcode = (PBYTE)sizeof(KMDEXEC);
	pKmdExec->szOutFormatPrintf = (LPSTR)(sizeof(KMDEXEC) + cbCode);
	Util_SHA256(pbKmdExec + 40, cbKmdExec - 40, pKmdExec->pbChecksumSHA256);
	Util_WriteFile(szFileBIN, pbCode, cbCode, (flags & FLAG_OVERWRITE));
	Util_WriteFile(szFileKSH, pbKmdExec, cbKmdExec, (flags & FLAG_OVERWRITE));
	printf("Succeded! Loaded PE contents from file: '%s'\nWrote 0x%x (%i) bytes of shellcode to files:\n'%s' and '%s' \n", szPE, cbCode, cbCode, szFileBIN, szFileKSH);
	if((flags & FLAG_SHOW_BINARY) && cbCode < 0x2000) {
		CryptBinaryToStringA(pbCode, cbCode, CRYPT_STRING_HEXASCIIADDR, ch, &cch);
		printf("HEX SHELLCODE OUTPUT AS PER BELOW:\n========================================\n%s\n", ch);
	}
	return 0;
}