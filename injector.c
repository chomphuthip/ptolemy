#include "injector.h"

int map(HANDLE proc_handle, char* file_view) {
	
	IMAGE_DOS_HEADER* file_dos_h;
	IMAGE_NT_HEADERS* file_nt_h;
	IMAGE_OPTIONAL_HEADER* file_opt_h;
	IMAGE_FILE_HEADER* file_file_h;

	file_dos_h = file_view;
	file_nt_h = file_view + file_dos_h->e_lfanew;
	file_opt_h = &file_nt_h->OptionalHeader;
	file_file_h = &file_nt_h->FileHeader;

	char* base_remote;
	base_remote = VirtualAllocEx(proc_handle,
		(void*)0, file_opt_h->SizeOfImage, 
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(proc_handle, base_remote, file_view,
		file_nt_h->OptionalHeader.SizeOfHeaders, (void*)0);

	IMAGE_SECTION_HEADER* section_header;
	section_header = IMAGE_FIRST_SECTION(file_nt_h);

	for (uint32_t i = 0; i < file_file_h->NumberOfSections; i++) {
		if (!section_header->SizeOfRawData)
			continue;

		WriteProcessMemory(proc_handle,
			base_remote + section_header->VirtualAddress,
			file_view + section_header->PointerToRawData,
			section_header->SizeOfRawData,
			(void*)0);

		printf("Wrote %d bytes of %s section at %p\n",
			section_header->SizeOfRawData,
			section_header->Name,
			base_remote + section_header->VirtualAddress
		);

		section_header++;
	}

	struct mapping_params params;
	params.base = base_remote;
	params._LoadLibraryA = LoadLibraryA;
	params._GetProcAddress = GetProcAddress;
	params._RtlAddFunctionTable = RtlAddFunctionTable;

	struct mapping_params* params_remote;
	params_remote = VirtualAllocEx(proc_handle,
		(void*)0, sizeof(params), 
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(proc_handle,	params_remote, 
		&params, sizeof(params), (void*)0);

	void* loader_remote;
	loader_remote = VirtualAllocEx(proc_handle, (void*)0,
		0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(proc_handle, loader_remote,
		loader_fn, 0x1000, (void*)0);

	HANDLE loader_thread;
	loader_thread = CreateRemoteThread(proc_handle,
		(void*)0, 0, loader_remote, params_remote, 0, (void*)0);

	printf("Mapped!\n");
	return 0;
}

DWORD WINAPI loader_fn(struct mapping_params* params) {
	char* base;
	f_LoadLibraryA _LoadLibraryA;
	f_GetProcAddress _GetProcAddress;
	f_RtlAddFunctionTable _RtlAddFunctionTable;

	base = params->base;
	_LoadLibraryA = params->_LoadLibraryA;
	_GetProcAddress = params->_GetProcAddress;
	_RtlAddFunctionTable = params->_RtlAddFunctionTable;
	
	IMAGE_DOS_HEADER* dos_h;
	IMAGE_NT_HEADERS* nt_h;
	IMAGE_OPTIONAL_HEADER* opt_h;
	IMAGE_FILE_HEADER* file_h;

	dos_h = base;
	nt_h = base + dos_h->e_lfanew;
	opt_h = &nt_h->OptionalHeader;
	file_h = &nt_h->FileHeader;

	IMAGE_DATA_DIRECTORY* dd;
	dd = opt_h->DataDirectory;

	int delta;
	IMAGE_BASE_RELOCATION* reloc_entry;
	delta = base - opt_h->ImageBase;
	reloc_entry = &dd[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	IMAGE_BASE_RELOCATION* reloc_data;
	reloc_data = base + reloc_entry->VirtualAddress;

	while (reloc_data->VirtualAddress) {
		if (reloc_data->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
			int count;
			count = (reloc_data->SizeOfBlock -
				sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			uint16_t* list;
			list = reloc_data + 1;

			for (int i = 0; i < count; i++) {
				if (!list[i]) continue;

				uint32_t* offset_ptr;
				offset_ptr = base +
					(reloc_data->VirtualAddress +
						(list[i] & 0xfff));

				*offset_ptr += delta;
			}
		}

		reloc_data = (PIMAGE_BASE_RELOCATION)((LPBYTE)reloc_data + reloc_data->SizeOfBlock);
	}

	IMAGE_DATA_DIRECTORY* import_dir_entry;
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor;

	import_dir_entry = &dd[IMAGE_DIRECTORY_ENTRY_IMPORT];
	import_descriptor = base + import_dir_entry->VirtualAddress;

	while (import_descriptor->Name) {
		char* lib_name;
		lib_name = base + import_descriptor->Name;

		HINSTANCE dll_handle;
		dll_handle = _LoadLibraryA(lib_name);

		uint64_t* thunk_ref;
		uint64_t* func_ref;
		
		thunk_ref = base + import_descriptor->OriginalFirstThunk;
		func_ref = base + import_descriptor->FirstThunk;
		if (!thunk_ref) thunk_ref = func_ref;

		for (; *thunk_ref; thunk_ref++, func_ref++) {
			if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref))
				*func_ref = _GetProcAddress(dll_handle,
					(char*)(*thunk_ref & 0xfff));
			else
				*func_ref = _GetProcAddress(dll_handle,
					((IMAGE_IMPORT_BY_NAME*)
						(base + (*thunk_ref)))->Name);
		}

		import_descriptor++;
	}

	IMAGE_DATA_DIRECTORY* tls_entry;
	tls_entry = &dd[IMAGE_DIRECTORY_ENTRY_TLS];

	if (tls_entry->Size) {
		IMAGE_TLS_DIRECTORY* tls_dir;
		PIMAGE_TLS_CALLBACK* callback;

		tls_dir = base + tls_entry->VirtualAddress;
		callback = tls_dir->AddressOfCallBacks;
		for (; callback && *callback; callback++) {
			(*callback)(base, DLL_PROCESS_ATTACH, (void*)0);
		}
	}

	IMAGE_DATA_DIRECTORY* seh_entry;
	seh_entry = &dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

	if (seh_entry->Size) {
		_RtlAddFunctionTable(
			base + seh_entry->VirtualAddress,
			seh_entry->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
			base);
	}

	f_DLL_ENTRY_POINT _entry;
	_entry = base + opt_h->AddressOfEntryPoint;

	_entry(base, DLL_PROCESS_ATTACH, (void*)0);

	return 0;
}