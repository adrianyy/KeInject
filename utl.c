#include "nt.h"
#include "utl.h"
#include <ntstrsafe.h>

static PVOID UtlpRvaToVa(
	_In_ PVOID Module,
	_In_ ULONG Rva
)
{
	if (Rva == 0)
	{
		return NULL;
	}

	return (PVOID)((PUCHAR)Module + Rva);
}

static PVOID UtlpGetModuleBaseWow64(
	_In_ PEPROCESS Process,
	_In_ PUNICODE_STRING ModuleName
)
{
	PPEB32 Peb = (PPEB32)PsGetProcessWow64Process(Process);
	if (Peb == NULL || Peb->Ldr == 0)
	{
		return NULL;
	}

	for (PLIST_ENTRY32 Entry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb->Ldr)->InLoadOrderModuleList.Flink;
		 Entry != &((PPEB_LDR_DATA32)Peb->Ldr)->InLoadOrderModuleList;
		 Entry = (PLIST_ENTRY32)Entry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(
			Entry,
			LDR_DATA_TABLE_ENTRY32,
			InLoadOrderLinks
		);

		if (LdrEntry->BaseDllName.Buffer == 0)
		{
			continue;
		}

		UNICODE_STRING CurrentName = { 0 };
		RtlUnicodeStringInit(&CurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);

		if (RtlEqualUnicodeString(ModuleName, &CurrentName, TRUE))
		{
			return (PVOID)LdrEntry->DllBase;
		}
	}

	return NULL;
}

static PVOID UtlpGetModuleBaseNative(
	_In_ PEPROCESS Process,
	_In_ PUNICODE_STRING ModuleName
)
{
	PPEB Peb = PsGetProcessPeb(Process);
	if (Peb == NULL || Peb->Ldr == NULL)
	{
		return NULL;
	}

	for (PLIST_ENTRY Entry = Peb->Ldr->InLoadOrderModuleList.Flink;
		 Entry != &Peb->Ldr->InLoadOrderModuleList;
		 Entry = Entry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(
			Entry,
			LDR_DATA_TABLE_ENTRY,
			InLoadOrderLinks
		);

		if (LdrEntry->BaseDllName.Buffer == NULL)
		{
			continue;
		}

		if (RtlEqualUnicodeString(ModuleName, &LdrEntry->BaseDllName, TRUE))
		{
			return (PVOID)LdrEntry->DllBase;
		}
	}

	return NULL;
}

static PVOID UtlpGetModuleExport(
	_In_ PVOID Module,
	_In_ PCHAR ExportName
)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS32 NtHeaders32 = (PIMAGE_NT_HEADERS32)UtlpRvaToVa(Module, DosHeader->e_lfanew);
	PIMAGE_NT_HEADERS64 NtHeaders64 = (PIMAGE_NT_HEADERS64)NtHeaders32;
	if (NtHeaders64 == NULL || NtHeaders64->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	PIMAGE_DATA_DIRECTORY DataDirectory = NULL;
	if (NtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		DataDirectory = &NtHeaders64->OptionalHeader.
			DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else if (NtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		DataDirectory = &NtHeaders32->OptionalHeader.
			DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else
	{
		return NULL;
	}

	ULONG ExportDirectorySize = DataDirectory->Size;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		UtlpRvaToVa(Module, DataDirectory->VirtualAddress);
	if (ExportDirectory == NULL)
	{
		return NULL;
	}

	PULONG Names = (PULONG )UtlpRvaToVa(Module, ExportDirectory->AddressOfNames);
	PULONG Funcs = (PULONG )UtlpRvaToVa(Module, ExportDirectory->AddressOfFunctions);
	PUSHORT Ords = (PUSHORT)UtlpRvaToVa(Module, ExportDirectory->AddressOfNameOrdinals);
	if (Names == NULL || Funcs == NULL || Ords == NULL)
	{
		return NULL;
	}

	for (ULONG Index = 0; Index < ExportDirectory->NumberOfNames; ++Index)
	{
		PCHAR CurrentName = (PCHAR)UtlpRvaToVa(Module, Names[Index]);

		if (CurrentName != NULL && strncmp(ExportName, CurrentName, 256) == 0)
		{
			USHORT CurrentOrd = Ords[Index];

			if (CurrentOrd < ExportDirectory->NumberOfFunctions)
			{
				PVOID ExportAddress = UtlpRvaToVa(Module, Funcs[CurrentOrd]);

				// Export is forwarded.
				if ((ULONG_PTR)ExportAddress >= (ULONG_PTR)ExportDirectory &&
					(ULONG_PTR)ExportAddress <= (ULONG_PTR)ExportDirectory + ExportDirectorySize)
				{
					return NULL;
				}

				return ExportAddress;
			}

			return NULL;
		}
	}

	return NULL;
}

PVOID UtlGetModuleExport(
	_In_ PVOID Module,
	_In_ PCHAR ExportName
)
{
	__try
	{
		return UtlpGetModuleExport(Module, ExportName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
}

PVOID UtlGetModuleBase(
	_In_ PEPROCESS Process,
	_In_ PUNICODE_STRING ModuleName,
	_In_ BOOLEAN IsWow64
)
{
	__try
	{
		if (IsWow64)
		{
			return UtlpGetModuleBaseWow64(Process, ModuleName);
		}
		else
		{
			return UtlpGetModuleBaseNative(Process, ModuleName);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
}

PVOID UtlGetLdrLoadDll(
	_In_ PEPROCESS Process, 
	_In_ BOOLEAN IsWow64
)
{
	UNICODE_STRING NtdllString = RTL_CONSTANT_STRING(L"ntdll.dll");
	PVOID Ntdll = UtlGetModuleBase(Process, &NtdllString, IsWow64);
	if (Ntdll == NULL)
	{
		return NULL;
	}

	return UtlGetModuleExport(Ntdll, "LdrLoadDll");
}
