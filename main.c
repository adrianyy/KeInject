#include <ntddk.h>
#include "inj.h"

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

#define MODULE_MAX_LENGTH 512
#define IOCTL_INJECT_MODULE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _INJECTION_DATA
{
	ULONG64	ProcessId;
	wchar_t	ModulePath[MODULE_MAX_LENGTH];
} INJECTION_DATA, *PINJECTION_DATA;

static UNICODE_STRING DeviceName		= RTL_CONSTANT_STRING(L"\\Device\\KeInject");
static UNICODE_STRING DeviceSymlink		= RTL_CONSTANT_STRING(L"\\??\\KeInject");
static BOOLEAN DoCleanup				= FALSE;

VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	if (DoCleanup)
	{
		IoDeleteSymbolicLink(&DeviceSymlink);
		IoDeleteDevice(DriverObject->DeviceObject);

		DoCleanup = FALSE;
	}
}

NTSTATUS DeviceDefaultDispatch(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	return STATUS_SUCCESS;
}

NTSTATUS DeviceControlDispatch(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;

	if (Irp->AssociatedIrp.SystemBuffer != NULL &&
		StackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_INJECT_MODULE &&
		StackLocation->Parameters.DeviceIoControl.InputBufferLength == sizeof(INJECTION_DATA))
	{
		PINJECTION_DATA InjectionData = (PINJECTION_DATA)Irp->AssociatedIrp.SystemBuffer;
		InjectionData->ModulePath[MODULE_MAX_LENGTH - 1] = 0;

		UNICODE_STRING ModulePath = { 0 };
		RtlInitUnicodeString(&ModulePath, InjectionData->ModulePath);

		Status = InjPerformInjection(
			(HANDLE)InjectionData->ProcessId,
			&ModulePath
		);
	}
	else
	{
		Status = STATUS_INVALID_PARAMETER;
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS Status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject
	);

	if (!NT_SUCCESS(Status))
	{
		return STATUS_UNSUCCESSFUL;
	}

	Status = IoCreateSymbolicLink(&DeviceSymlink, &DeviceName);

	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}

	DoCleanup = TRUE;

	for (SIZE_T Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; ++Index)
	{
		DriverObject->MajorFunction[Index] = DeviceDefaultDispatch;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;

	return STATUS_SUCCESS;
}