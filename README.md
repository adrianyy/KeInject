Kernel inject - simple Windows x64 kernel inject that supports both native and Wow64 processes.
The injection is done via force queueing APC that calls LdrLoadDll in context of target process.

Everything you need to interact with in in usermode:
```
#define MODULE_MAX_LENGTH 512
#define IOCTL_INJECT_MODULE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _INJECTION_DATA
{
	ULONG64	ProcessId;
	wchar_t	ModulePath[MODULE_MAX_LENGTH];
} INJECTION_DATA, *PINJECTION_DATA;
```