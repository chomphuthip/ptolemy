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

struct mapping_params
{
	f_LoadLibraryA _LoadLibraryA;
	f_GetProcAddress _GetProcAddress;
	f_RtlAddFunctionTable _RtlAddFunctionTable;

	void* base;
};

int map(HANDLE proc_handle, char* file_view);

DWORD WINAPI loader_fn(struct mapping_params* params);