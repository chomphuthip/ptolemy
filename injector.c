#include "injector.h"

int map(HANDLE proc_handle, int64_t file_len, void* file_mmap) {
	if (((IMAGE_DOS_HEADER*)(file_mmap))->e_magic != 0x5a4d)
		return -3;

	IMAGE_NT_HEADERS* map_nt_header;
	IMAGE_OPTIONAL_HEADER* map_opt_header;
	IMAGE_FILE_HEADER* map_file_header;
	void* target_base;

	map_nt_header =
		((IMAGE_DOS_HEADER*)(file_mmap))->e_lfanew +
		(char*)file_mmap;
	map_opt_header = &map_nt_header->OptionalHeader;
	map_file_header = &map_nt_header->FileHeader;

	target_base = VirtualAllocEx(
		proc_handle,
		(void*)0,
		map_opt_header->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!target_base) return -4;

	struct mapping_data data;
	memset(&data, 0, sizeof(data));

	data._LoadLibraryA = LoadLibraryA;
	data._GetProcAddress = GetProcAddress;
	data._RtlAddFunctionTable =
		(f_RtlAddFunctionTable)RtlAddFunctionTable;
	data.base = target_base;
	data.reason_param = DLL_PROCESS_ATTACH;
	data.reserved_param = (void*)0;
	data.seh_supported = 1;

	BOOL wrote_properly;
	wrote_properly = WriteProcessMemory(proc_handle,
		target_base, file_mmap, 0x1000, (void*)0);
	if (!wrote_properly) return -5;

	IMAGE_SECTION_HEADER* section_header;
	section_header = IMAGE_FIRST_SECTION(map_nt_header);

	for (int i = 0; i != map_file_header->NumberOfSections;
		i++, section_header++)
	{
		if (!section_header->SizeOfRawData) continue;
		wrote_properly = WriteProcessMemory(
			proc_handle,
			(char*)target_base + section_header->VirtualAddress,
			(char*)file_mmap + section_header->PointerToRawData,
			section_header->SizeOfRawData,
			(void*)0
		);
		if (!wrote_properly) return -6;
	}

	void* data_in_target;
	data_in_target = VirtualAllocEx(proc_handle, (void*)0,
		sizeof(data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!data_in_target) return -7;

	wrote_properly = WriteProcessMemory(proc_handle, data_in_target,
		&data, sizeof(data), (void*)0);
	if (!wrote_properly) return -8;

	void* shellcode;
	shellcode = VirtualAllocEx(proc_handle, (void*)0, 0x1000,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellcode) return -9;

	wrote_properly = WriteProcessMemory(proc_handle, shellcode,
		shellcode_fn, 0x1000, (void*)0);
	if (!wrote_properly) return -10;

	HANDLE thread;
	thread = CreateRemoteThread(proc_handle, (void*)0, 0,
		shellcode, data_in_target, 0, (void*)0);
	if (!thread) return -11;

	return 0;
}

#define RELOC_FLAG(info) ((info >> 0x0C) == IMAGE_REL_BASED_DIR64)

void _stdcall shellcode_fn(struct mapping_data* data) {
	void* base;
	base = data->base;

	IMAGE_DOS_HEADER* inside_dos_header;
	IMAGE_NT_HEADERS* inside_nt_header;
	IMAGE_OPTIONAL_HEADER* inside_opt_header;
	
	inside_dos_header = base;
	inside_nt_header = inside_dos_header->e_lfanew;
	inside_opt_header = &inside_nt_header->OptionalHeader;

	f_LoadLibraryA _LoadLibraryA = data->_LoadLibraryA;
	f_GetProcAddress _GetProcAddress = data->_GetProcAddress;
	f_RtlAddFunctionTable _RtlAddFunctionTable = 
		data->_RtlAddFunctionTable;

	f_DLL_ENTRY_POINT _DllMain = (char*)base +
		inside_opt_header->AddressOfEntryPoint;

	void* relative_location;
	relative_location = (char*)base - inside_opt_header->ImageBase;

	if (relative_location) {
		if (inside_opt_header->DataDirectory
			[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			IMAGE_BASE_RELOCATION* reloc_data;
			reloc_data = (char*)base +
				inside_opt_header->DataDirectory
				[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

			IMAGE_BASE_RELOCATION* reloc_end;
			reloc_end = reloc_data +
				inside_opt_header->DataDirectory
				[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

			while (reloc_data < reloc_end && reloc_data->SizeOfBlock)
			{
				uint32_t entries_len;
				entries_len = (reloc_data->SizeOfBlock -
					sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

				char* relative_info;
				relative_info = reloc_data + 1;

				for (int i = 0; i != entries_len; i++, relative_info++)
				{
					if (!RELOC_FLAG(*relative_info)) continue;
					int* patch = (char*)base +
						reloc_data->VirtualAddress +
						((*relative_info) & 0xfff);

					*patch += (int)relative_location;
				}
				reloc_data += reloc_data->SizeOfBlock;
			}
		}
	}

	if (inside_opt_header->DataDirectory
		[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* import_descriptor;
		import_descriptor = (char*)base +
			inside_opt_header->DataDirectory
			[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		while (import_descriptor->Name) {
			char* lib_name = (char*)base + import_descriptor->Name;
			
			HINSTANCE dll_handle;
			dll_handle = _LoadLibraryA(lib_name);

			uint64_t* thunk_ref = (char*)base +
				import_descriptor->OriginalFirstThunk;

			uint64_t* func_ref = (char*)base +
				import_descriptor->FirstThunk;

			if (!thunk_ref)
				thunk_ref = func_ref;

			for (; *thunk_ref; ++thunk_ref, ++func_ref) {
				if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref))
					*func_ref = _GetProcAddress(
						dll_handle, (char*)(*thunk_ref & 0xffff));
				else
					*func_ref = _GetProcAddress(
						dll_handle,
						((IMAGE_IMPORT_BY_NAME*)((char*)base +
							(*thunk_ref)))->Name);
			}
			++import_descriptor;
		}
	}

	if(inside_opt_header->DataDirectory
		[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* tls_directory;
		tls_directory = (char*)base + inside_opt_header->
			DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

		PIMAGE_TLS_CALLBACK* callback;
		callback = tls_directory->AddressOfCallBacks;

		for (; callback && *callback; callback++)
			(*callback)(base, DLL_PROCESS_ATTACH, (void*)0);
	}

	if (data->seh_supported) {
		IMAGE_DATA_DIRECTORY exception;
		exception = inside_opt_header->DataDirectory
			[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

		if (exception.Size) {
			_RtlAddFunctionTable(
				(char*)base + exception.VirtualAddress,
				exception.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
				base
			);
		}
	}

	_DllMain(base, data->reason_param, data->reserved_param);
}