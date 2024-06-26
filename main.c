#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>

#define WIN32_LEAN_AND_MEAN
#include<Windows.h>

#include "injector.h"

int main(int argc, char** argv) {
	long pid;
	char* end;
	int err_code;

	err_code = 0;
	pid = strtol(argv[1], &end, 10);

	if (argc != 3 || end == argv[1]) {
		fprintf(stderr, "Usage: ptolemy [proc id] [path to dll]");
		return -1;
	}

	HANDLE file_handle;
	file_handle = CreateFileA(
		argv[2],
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (file_handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Unable to open file!");
		return -1;
	}

	HANDLE file_map;
	file_map = CreateFileMapping(file_handle,
		NULL, PAGE_READONLY , 0, 0, NULL);
	if (file_map == 0) { err_code = -2; goto ERR; }

	void* file_view;
	file_view = MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 0);
	if (file_view == 0) { err_code = -3; goto ERR; }

	TOKEN_PRIVILEGES priv;
	HANDLE token;
	memset(&priv, 0, sizeof(priv));
	token = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(token);
	}

	HANDLE proc_handle;
	proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	
	printf("Mapping...\n");

	return map(proc_handle, file_view);
ERR:
	return err_code;
}