#pragma once
#include <ntddk.h>

PVOID UtlGetModuleExport(
	_In_ PVOID Module,
	_In_ PCHAR ExportName
);

PVOID UtlGetModuleBase(
	_In_ PEPROCESS Process,
	_In_ PUNICODE_STRING ModuleName,
	_In_ BOOLEAN IsWow64
);

PVOID UtlGetLdrLoadDll(
	_In_ PEPROCESS Process, 
	_In_ BOOLEAN IsWow64
);