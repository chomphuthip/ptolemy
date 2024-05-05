#pragma once

#include<stdint.h>

#define WIN32_LEAN_AND_MEAN
#include<Windows.h>

typedef HINSTANCE(WINAPI* f_LoadLibraryA)
	(const char* lpLibFilename);

typedef FARPROC(WINAPI* f_GetProcAddress)
	(HMODULE hModule, LPCSTR lpProcName);

typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)
	(void* hDll, DWORD dwReason, void* pReserved);

typedef BOOL(WINAPIV* f_RtlAddFunctionTable)
	(PRUNTIME_FUNCTION FunctionTable, 
		DWORD EntryCount, DWORD64 BaseAddress);

struct mapping_data
{
	f_LoadLibraryA _LoadLibraryA;
	f_GetProcAddress _GetProcAddress;
	f_RtlAddFunctionTable _RtlAddFunctionTable;
	void* base;
	HINSTANCE module_handle;
	DWORD reason_param;
	void* reserved_param;
	BOOL seh_supported;
};

int map(HANDLE proc_handle, int64_t file_len, void* file_mmap);

void _stdcall shellcode_fn(struct mapping_data* data);