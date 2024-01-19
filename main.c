#include <ntddk.h>
#include "Native.h"
#include "ObCallbacks.h"
#include "PsNotify.h"
#include "Utils.h"
#include "Global.h"


Module DriverInfo = { 0 };
PDRIVER_OBJECT g_pDriverObject = 0;
DYNDATA g_DynData = { 0 };

/* 
	I/O Driver Control Function:
	CTL_GET_DRIVERINFO: 
		Retrieves Base Address and Size of the Driver Specified in SystemBuffer.

	CTL_DISABLE_OB_CALLBACKS:
		Disables ObCallbacks of the thread and process of the driver specified ( call CTL_GET_DRIVERINFO before this ).

	CTL_RESTORE_OB_CALLBACKS:
		Restores ObCallbacks of the thread and process of the driver specified ( call CTL_GET_DRIVERINFO before this ).

	CTL_DISABLE_IMAGE_CALLBACK:
		Disables ImageLoadNotifyRoutine of the specified driver ( call CTL_GET_DRIVERINFO before this ).

	CTL_DISABLE_PROCESS_CALLBACK:
		Disables ProcessNotifyRoutine of the specified driver ( call CTL_GET_DRIVERINFO before this ).

	CTL_DISABLE_THREAD_CALLBACK:
		Disables ThreadNotifyRoutine of the specified driver ( call CTL_GET_DRIVERINFO before this ).
*/
NTSTATUS IOControl(DEVICE_OBJECT* pDeviceObject, IRP* Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	kprintf("Called %s!\n", __FUNCTION__);

	IO_STACK_LOCATION* pStackLoc = IoGetCurrentIrpStackLocation(Irp);

	if (pStackLoc)
	{
		switch (pStackLoc->Parameters.DeviceIoControl.IoControlCode)
		{
		case CTL_GET_DRIVERINFO:
			
			kprintf("%s: Getting Driver Info\n", __FUNCTION__);
			DRIVERNAME name = *(DRIVERNAME*)Irp->AssociatedIrp.SystemBuffer;
			GetDriverInformation(name.Name, g_pDriverObject, &DriverInfo.Base, &DriverInfo.Size);
			kprintf("Base: %p \t Size: 0x%X\n", DriverInfo.Base, DriverInfo.Size);
			break;

		case CTL_DISABLE_OB_CALLBACKS:

			kprintf("%s: Disabling ObCallbacks\n", __FUNCTION__);
			DisableObCallbacks();
			break;

		case CTL_RESTORE_OB_CALLBACKS:

			kprintf("%s: Restore ObCallbacks\n", __FUNCTION__);
			RestoreObCallbacks();
			break;

		case CTL_DISABLE_IMAGE_CALLBACK:

			kprintf("%s: Disabling Image Callback\n", __FUNCTION__);
			status = DisablePsImageCallback();
			break;

		case CTL_DISABLE_PROCESS_CALLBACK:

			kprintf("%s: Disabling Process Callback\n", __FUNCTION__);
			status = DisablePsProcessCallback();
			break;

		case CTL_DISABLE_THREAD_CALLBACK:

			kprintf("%s: Disabling Thread Callback\n", __FUNCTION__);
			status = DisablePsThreadCallback();
			break;

		default:
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		Irp->IoStatus.Status = status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

	return status;
}

NTSTATUS MJCreateAndClose(DEVICE_OBJECT* pDeviceObject, IRP* Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*
	Restore ObCallbacks if I/O forgot to do it to prevent BSOD.
*/
void DriverUnload(PDRIVER_OBJECT pDriver)
{
	kprintf("%s: Done!\n", __FUNCTION__);

	UNICODE_STRING usDosDeviceName;
	RtlInitUnicodeString(&usDosDeviceName, DosDeviceName);
	IoDeleteSymbolicLink(&usDosDeviceName);

	RestoreObCallbacks();

	IoDeleteDevice(pDriver->DeviceObject);
}

/*
	Check if OS is supported.
	Create Symbolic Link for I/O.
	Save Original ObCallbacks for restoring them later.
*/
NTSTATUS LoadBlocker()
{

}
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
PVOID GetSystemRoutineAddress(LPCWSTR name)
{
	UNICODE_STRING unicodeName;
	RtlInitUnicodeString(&unicodeName, name);
	return MmGetSystemRoutineAddress(&unicodeName);
}
PVOID GetSystemModuleBase(LPCWSTR name)
{
	PLIST_ENTRY loadedModuleList = (PLIST_ENTRY)(GetSystemRoutineAddress(L"PsLoadedModuleList"));
	if (!loadedModuleList)
	{
		return NULL;
	}
	__try
	{
		for (PLIST_ENTRY link = loadedModuleList->Flink; link != loadedModuleList; link = link->Flink)
		{
			LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (_wcsicmp(name, entry->BaseDllName.Buffer) == 0)
			{
				return entry->DllBase;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
	return NULL;
}




BOOLEAN IsDriverValid(PVOID driverBase)
{

	if (driverBase == NULL) {
		return FALSE;
	}
	UCHAR* driverCode = (UCHAR*)driverBase;

	if (driverCode[0] == 'M' && driverCode[1] == 'Z') {
		return TRUE;
	}


	return FALSE;
}
VOID PerformActionsOnDriverFound()
{
	KdPrint("Found Randgrid : %s\n", L"randgrid.sys");

	DRIVERNAME gemmaDriverName = { L"randgrid.sys" };
	GetDriverInformation(gemmaDriverName.Name, g_pDriverObject, &DriverInfo.Base, &DriverInfo.Size);
	SaveOrigObCallbacks();
	DisableObCallbacks();
}

NTSTATUS searcherThreadRoutine(_In_ PVOID Context)
{

	while (TRUE)
	{
		PVOID ranggrid = GetSystemModuleBase(L"randgrid.sys");

		if (ranggrid)
		{
			DRIVERNAME gemmaDriverName = { L"randgrid.sys" };
			GetDriverInformation(gemmaDriverName.Name, g_pDriverObject, &DriverInfo.Base, &DriverInfo.Size);
			SaveOrigObCallbacks();
			DisableObCallbacks();
		}

		LARGE_INTEGER Interval;
		Interval.QuadPart = -5 * 10 * 1000 * 1000; 

		KeDelayExecutionThread(KernelMode, FALSE, &Interval);
	}

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT kdmapperParam1, _In_ PUNICODE_STRING RegistryPath)
{

	UNREFERENCED_PARAMETER(kdmapperParam1);
	UNREFERENCED_PARAMETER(RegistryPath);


	if (!InitDynamicData())
		return STATUS_UNSUCCESSFUL;

	PDEVICE_OBJECT pDevice = NULL;
	UNICODE_STRING usDeviceName, usDosDeviceName;
	g_pDriverObject = kdmapperParam1;

	RtlInitUnicodeString(&usDeviceName, DeviceName);
	RtlInitUnicodeString(&usDosDeviceName, DosDeviceName);

	NTSTATUS status = IoCreateDevice(kdmapperParam1, 0, &usDeviceName
		, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN
		, FALSE, &pDevice);
	if (NT_SUCCESS(status))
	{
		status = IoCreateSymbolicLink(&usDosDeviceName, &usDeviceName);

		if (NT_SUCCESS(status))
		{
			kdmapperParam1->DriverUnload = DriverUnload;
			kdmapperParam1->MajorFunction[IRP_MJ_CREATE] = MJCreateAndClose;
			kdmapperParam1->MajorFunction[IRP_MJ_CLOSE] = MJCreateAndClose;
			kdmapperParam1->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOControl;

			HANDLE hThread;
			PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, searcherThreadRoutine, NULL);

				
			
		}
	}

	return status;
}


