#include <ntifs.h>
#include "global.h"
#include "apc.h"
#include "nt.h"

static VOID ApcpKernelRoutineAlertThreadCallback(
	_In_ PKAPC Apc,
	_In_ PKNORMAL_ROUTINE* NormalRoutine,
	_In_ PVOID* NormalContext,
	_In_ PVOID* SystemArgument1,
	_In_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	KeTestAlertThread(UserMode);
	ExFreePoolWithTag(Apc, KEINJ_POOL_TAG);
}

static VOID ApcpKernelRoutineNormalCallback(
	_In_ PKAPC Apc,
	_In_ PKNORMAL_ROUTINE* NormalRoutine,
	_In_ PVOID* NormalContext,
	_In_ PVOID* SystemArgument1,
	_In_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	if (PsIsThreadTerminating(PsGetCurrentThread()))
	{
		*NormalRoutine = NULL;
	}

	if (PsGetCurrentProcessWow64Process() != NULL)
	{
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
	}

	ExFreePoolWithTag(Apc, KEINJ_POOL_TAG);
}

static BOOLEAN ApcpShouldSkipThread(
	_In_ PETHREAD Thread,
	_In_ BOOLEAN IsWow64
)
{
	PUCHAR Teb64 = PsGetThreadTeb(Thread);
	if (Teb64 == NULL || PsIsThreadTerminating(Thread))
	{
		return TRUE;
	}

	// Skip GUI threads.
	if (*(PULONG64)(Teb64 + 0x78) != 0)
	{
		return TRUE;
	}

	// Skip threads with no ActivationContext or TLS pointer.
	if (IsWow64)
	{
		PUCHAR Teb32 = Teb64 + 0x2000;

		if (*(PULONG32)(Teb32 + 0x1A8) == 0 ||
			*(PULONG32)(Teb32 + 0x2C) == 0)
		{
			return TRUE;
		}
	}
	else
	{
		if (*(PULONG64)(Teb64 + 0x2C8) == 0 ||
			*(PULONG64)(Teb64 + 0x58) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

static NTSTATUS ApcpQuerySystemProcessInformation(
	_Out_ PSYSTEM_PROCESS_INFO* SystemInfo  
)
{
	PSYSTEM_PROCESS_INFO Buffer = NULL;
	ULONG BufferSize = 0;
	ULONG RequiredSize = 0;
	
	NTSTATUS Status = STATUS_SUCCESS;
	while ((Status = ZwQuerySystemInformation(
		SystemProcessInformation, 
		Buffer, 
		BufferSize, 
		&RequiredSize
	)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		BufferSize = RequiredSize;
		Buffer = ExAllocatePoolWithTag(PagedPool, BufferSize, KEINJ_POOL_TAG);
	}

	if (!NT_SUCCESS(Status))
	{
		if (Buffer != NULL)
		{
			ExFreePoolWithTag(Buffer, KEINJ_POOL_TAG);
		}

		return Status;
	}

	*SystemInfo = Buffer;
	return Status;
}

static NTSTATUS ApcpQueryExecutionOnThread(
	_In_ PETHREAD Thread,
	_In_ PVOID Code,
	_In_ PVOID Param
)
{
	PKAPC AlertThreadApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), KEINJ_POOL_TAG);
	PKAPC ExecutionApc   = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), KEINJ_POOL_TAG);
	if (ExecutionApc == NULL || AlertThreadApc == NULL)
	{
		if (AlertThreadApc != NULL)
		{
			ExFreePoolWithTag(AlertThreadApc, KEINJ_POOL_TAG);
		}

		if (ExecutionApc != NULL)
		{
			ExFreePoolWithTag(ExecutionApc, KEINJ_POOL_TAG);
		}

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	KeInitializeApc(
		AlertThreadApc,
		Thread,
		OriginalApcEnvironment,
		ApcpKernelRoutineAlertThreadCallback,
		NULL,
		NULL,
		KernelMode,
		NULL
	);

	KeInitializeApc(
		ExecutionApc,
		Thread,
		OriginalApcEnvironment,
		ApcpKernelRoutineNormalCallback,
		NULL,
		(PKNORMAL_ROUTINE)Code,
		UserMode,
		Param
	);

	if (KeInsertQueueApc(ExecutionApc, NULL, NULL, 0))
	{
		if (KeInsertQueueApc(AlertThreadApc, NULL, NULL, 0))
		{
			return PsIsThreadTerminating(Thread) ? STATUS_THREAD_IS_TERMINATING : STATUS_SUCCESS;
		}
		else
		{
			ExFreePoolWithTag(AlertThreadApc, KEINJ_POOL_TAG);
		}
	}
	else
	{
		ExFreePoolWithTag(ExecutionApc, KEINJ_POOL_TAG);
		ExFreePoolWithTag(AlertThreadApc, KEINJ_POOL_TAG);
	}

	return STATUS_UNSUCCESSFUL;
}

static NTSTATUS ApcpQueryExecutionOnFirstProcessThread(
	_In_ PEPROCESS Process,
	_In_ BOOLEAN IsWow64,
	_In_ PVOID Code,
	_In_ PVOID Param
)
{
	PSYSTEM_PROCESS_INFO OriginalSystemProcessInfo = NULL;
	NTSTATUS Status = ApcpQuerySystemProcessInformation(&OriginalSystemProcessInfo);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	PSYSTEM_PROCESS_INFO SystemProcessInfo = OriginalSystemProcessInfo;
	Status = STATUS_NOT_FOUND;
	do
	{
		if (SystemProcessInfo->UniqueProcessId == PsGetProcessId(Process))
		{
			Status = STATUS_SUCCESS;
			break;
		}
		
		SystemProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)SystemProcessInfo + SystemProcessInfo->NextEntryOffset);
	} while (SystemProcessInfo->NextEntryOffset != 0);

	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(OriginalSystemProcessInfo, KEINJ_POOL_TAG);
		return Status;
	}

	for (ULONG Index = 0; Index < SystemProcessInfo->NumberOfThreads; ++Index)
	{
		HANDLE UniqueThreadId = SystemProcessInfo->Threads[Index].ClientId.UniqueThread;
		if (UniqueThreadId == PsGetCurrentThreadId())
		{
			continue;
		}

		PETHREAD Thread = NULL;
		Status = PsLookupThreadByThreadId(UniqueThreadId, &Thread);
		if (NT_SUCCESS(Status) && Thread != NULL)
		{
			if (ApcpShouldSkipThread(Thread, IsWow64))
			{
				ObDereferenceObject(Thread);
				continue;
			}

			Status = ApcpQueryExecutionOnThread(Thread, Code, Param);
			ObDereferenceObject(Thread);

			if (NT_SUCCESS(Status))
			{
				break;
			}
		}
	}

	ExFreePoolWithTag(OriginalSystemProcessInfo, KEINJ_POOL_TAG);
	return STATUS_SUCCESS;
}

NTSTATUS ApcQueueExecution(
	_In_ PEPROCESS Process,
	_In_ BOOLEAN IsWow64,
	_In_ PVOID Code,
	_In_ PVOID Param
)
{
	return ApcpQueryExecutionOnFirstProcessThread(Process, IsWow64, Code, Param);
}