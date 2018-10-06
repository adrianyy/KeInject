#include <ntifs.h>
#include "nt.h"
#include "inj.h"
#include "utl.h"
#include "apc.h"

static const UCHAR InjpShellcodeWow64[] =
{
	0xB8, 0x00, 0x00, 0x00, 0x00,								// mov		eax, 0x00
	0x8B, 0x4C, 0x24, 0x04,										// mov		ecx, [esp+0x04]
	0x6A, 0x00,													// push		0
	0x54,														// push		esp
	0x51,														// push		ecx
	0x6A, 0x00,													// push		0
	0x6A, 0x00,													// push		0
	0xFF, 0xD0,													// call		eax
	0x83, 0xC4, 0x04,											// add		esp, 0x04
	0xC3														// ret
};

static const UCHAR InjpShellcodeNative[] =
{
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov		rax, 0x00
	0x48, 0x83, 0xEC, 0x28,										// sub		rsp, 0x28
	0x49, 0x89, 0xC8,											// mov		r8 , rcx
	0x4C, 0x8D, 0x4C, 0x24, 0x20,								// lea		r9 , [rsp+0x20]
	0x48, 0x31, 0xC9,											// xor		rcx, rcx
	0x48, 0x31, 0xD2,											// xor		rdx, rdx
	0xFF, 0xD0,													// call		rax
	0x48, 0x83, 0xC4, 0x28,										// add		rsp, 0x28
	0xC3														// ret
};

static NTSTATUS InjpFindProcess(
	_In_ HANDLE ProcessId,
	_Out_ PEPROCESS* Process,
	_Out_ PBOOLEAN IsWow64
)
{
	NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, Process);
	if (!NT_SUCCESS(Status) || *Process == NULL)
	{
		return STATUS_NOT_FOUND;
	}

	LARGE_INTEGER ZeroTime = { 0 };
	if (KeWaitForSingleObject(*Process, Executive, KernelMode, FALSE, &ZeroTime) == STATUS_WAIT_0)
	{
		// Process is terminating.
		ObDereferenceObject(*Process);
		return STATUS_PROCESS_IS_TERMINATING;
	}

	*IsWow64 = PsGetProcessWow64Process(*Process) != NULL;

	return Status;
}

static NTSTATUS InjpPrepareShellcode(
	_In_ PUNICODE_STRING ModulePath,
	_In_ PVOID LdrLoadDll,
	_In_ BOOLEAN IsWow64,
	_Out_ PVOID* Shellcode,
	_Out_ PVOID* ShellcodeParam
)
{
	PVOID Allocation = NULL;
	SIZE_T AllocationSize = PAGE_SIZE;

	NTSTATUS Status = ZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&Allocation,
		0,
		&AllocationSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	const UCHAR* ShellcodeBytes = IsWow64 ? InjpShellcodeWow64 : InjpShellcodeNative;
	const SIZE_T ShellcodeSize  = IsWow64 ? sizeof(InjpShellcodeWow64) : sizeof(InjpShellcodeNative);

	UNICODE_STRING   String64 = { 0 };
	UNICODE_STRING32 String32 = { 0 };

	String64.Length = String64.MaximumLength = ModulePath->Length;
	String32.Length = String32.MaximumLength = ModulePath->Length;
	String64.Buffer = (PWSTR)(ULONG_PTR)((PUCHAR)Allocation + ShellcodeSize + sizeof(String64));
	String32.Buffer = (ULONG)(ULONG_PTR)((PUCHAR)Allocation + ShellcodeSize + sizeof(String32));

	PVOID  String     = IsWow64 ? (PVOID)&String32 : (PVOID)&String64;
	SIZE_T StringSize = IsWow64 ? sizeof(String32) : sizeof(String64);

	RtlCopyMemory(Allocation, ShellcodeBytes, ShellcodeSize);
	RtlCopyMemory((PUCHAR)Allocation + ShellcodeSize, String, StringSize);
	RtlCopyMemory((PUCHAR)Allocation + ShellcodeSize + StringSize, ModulePath->Buffer, ModulePath->Length);

	if (IsWow64)
	{
		*(ULONG*)((PUCHAR)Allocation + 1) = (ULONG)(ULONG_PTR)LdrLoadDll;
	}
	else
	{
		*(ULONG_PTR*)((PUCHAR)Allocation + 2) = (ULONG_PTR)LdrLoadDll;
	}

	*Shellcode = Allocation;
	*ShellcodeParam = (PVOID)((PUCHAR)Allocation + ShellcodeSize);

	return Status;
}

static NTSTATUS InjpExecuteShellcode(
	_In_ PEPROCESS Process,
	_In_ BOOLEAN IsWow64,
	_In_ PVOID Shellcode,
	_In_ PVOID ShellcodeParam
)
{
	return ApcQueueExecution(Process, IsWow64, Shellcode, ShellcodeParam);
}

NTSTATUS InjPerformInjection(
	_In_ HANDLE ProcessId,
	_In_ PUNICODE_STRING ModulePath
)
{
	PEPROCESS Process = NULL;
	BOOLEAN IsWow64 = FALSE;

	NTSTATUS Status = InjpFindProcess(ProcessId, &Process, &IsWow64);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	KAPC_STATE ApcState = { 0 };
	KeStackAttachProcess(Process, &ApcState);

	PVOID LdrLoadDll = UtlGetLdrLoadDll(Process, IsWow64);
	if (LdrLoadDll == NULL)
	{
		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(Process);
		return Status;
	}

	PVOID Shellcode = NULL;
	PVOID ShellcodeParam = NULL;
	Status = InjpPrepareShellcode(
		ModulePath,
		LdrLoadDll,
		IsWow64,
		&Shellcode,
		&ShellcodeParam
	);

	if (!NT_SUCCESS(Status))
	{
		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(Process);
		return Status;
	}

	Status = InjpExecuteShellcode(Process, IsWow64, Shellcode, ShellcodeParam);
	if (!NT_SUCCESS(Status))
	{
		ZwFreeVirtualMemory(ZwCurrentProcess(), &Shellcode, NULL, MEM_FREE);
	}

	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(Process);
	return Status;
}