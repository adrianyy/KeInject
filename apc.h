#pragma once
#include <ntddk.h>

NTSTATUS ApcQueueExecution(
	_In_ PEPROCESS Process,
	_In_ BOOLEAN IsWow64,
	_In_ PVOID Code,
	_In_ PVOID Param
);