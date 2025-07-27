#include <ntddk.h>
#include <initguid.h>
#include <wdmguid.h>
#include "winmem.h"
#include "FastMutex.h"

//Mapped memory information list
typedef struct tagMAPINFO
{
	//SINGLE_LIST_ENTRY	link;
	LIST_ENTRY	ListEntry;
	PMDL				pMdl;	//allocated mdl
	PVOID				pvk;	//kernel mode virtual address
	PVOID				pvu;	//user mode virtual address
	ULONG				memSize;//memory size in bytes
} MAPINFO, * PMAPINFO;

//SINGLE_LIST_ENTRY lstMapInfo;	//mapped memory information
LIST_ENTRY linkListHead;

//forward function declaration
NTSTATUS WinMemCreate(IN PDEVICE_OBJECT fdo, IN PIRP irp);
NTSTATUS WinMemClose(IN PDEVICE_OBJECT fdo, IN PIRP irp);
NTSTATUS WinMemIoCtl(IN PDEVICE_OBJECT fdo, IN PIRP irp);
VOID WinMemUnload(IN PDRIVER_OBJECT dro);

extern "C" NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	_In_ PUNICODE_STRING ObjectPath,
	_In_ ULONG Attributes,
	_In_opt_ PACCESS_STATE PassedAccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Inout_opt_ PVOID ParseContext,
	_Out_ PVOID * Object
);

extern "C" NTSTATUS
IoEnumerateDeviceObjectList(
	IN PDRIVER_OBJECT  DriverObject,
	IN PDEVICE_OBJECT * DeviceObjectList,
	IN ULONG  DeviceObjectListSize,
	OUT PULONG  ActualNumberDeviceObjects
);

extern "C" POBJECT_TYPE * IoDriverObjectType;

NTSTATUS ReadWriteConfigSpace(
	IN PDEVICE_OBJECT DeviceObject,
	IN ULONG	      ReadOrWrite, // 0 for read 1 for write
	IN PVOID	      Buffer,
	IN ULONG	      Offset,
	IN ULONG	      Length
);

NTSTATUS
GetPCIBusInterfaceStandard(
	IN  PDEVICE_OBJECT DeviceObject,
	OUT PBUS_INTERFACE_STANDARD	BusInterfaceStandard
);

FastMutex locker;

/*++
DriverEntry routine
--*/
extern "C"
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING DeviceNameU;
	UNICODE_STRING DeviceLinkU;
	NTSTATUS ntStatus;
	PDEVICE_OBJECT fdo = NULL;

	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("Entering DriverEntry\n");

	//lstMapInfo.Next = NULL;
	InitializeListHead(&linkListHead);

	locker.Init();

	RtlInitUnicodeString(&DeviceNameU, DeviceName);

	//Create an EXCLUSIVE device object
	ntStatus = IoCreateDevice(DriverObject,		//IN: Driver Object
		0,					//IN: Device Extension Size
		&DeviceNameU,		//IN: Device Name
		FILE_DEVICE_WINMEM,	//IN: Device Type
		0,					//IN: Device Characteristics
		FALSE,				//IN: Exclusive
		&fdo);				//OUT:Created Device Object

	if (NT_SUCCESS(ntStatus))
	{
		if (NT_SUCCESS(ntStatus))
		{
			//Dispatch functions
			DriverObject->MajorFunction[IRP_MJ_CREATE] = WinMemCreate;
			DriverObject->MajorFunction[IRP_MJ_CLOSE] = WinMemClose;
			DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WinMemIoCtl;
			DriverObject->DriverUnload = WinMemUnload;

			//Create a symbolic link
			RtlInitUnicodeString(&DeviceLinkU, DeviceSymLink);
			ntStatus = IoCreateSymbolicLink(&DeviceLinkU, &DeviceNameU);

			if (!NT_SUCCESS(ntStatus))
			{
				DbgPrint("Error: IoCreateSymbolicLink failed\n");

				IoDeleteDevice(fdo);
			}
		}
		else
		{
			DbgPrint("Error: IoGetDeviceObjectPointer failed\n");

			IoDeleteDevice(fdo);
		}
	}
	else
		DbgPrint("Error: IoCreateDevice failed\n");

	DbgPrint("Leaving DriverEntry\n");

	return ntStatus;
}

/*++
IRP_MJ_CREATE dispatch routine
--*/
NTSTATUS WinMemCreate(IN PDEVICE_OBJECT fdo, IN PIRP irp)
{
	UNREFERENCED_PARAMETER(fdo);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrint("IRP_MJ_CREATE\n");

	return STATUS_SUCCESS;
}

/*++
IRP_MJ_CLOSE dispatch routine
--*/
NTSTATUS WinMemClose(IN PDEVICE_OBJECT fdo, IN PIRP irp)
{
	UNREFERENCED_PARAMETER(fdo);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrint("IRP_MJ_CLOSE\n");

	return STATUS_SUCCESS;
}
/*++
IRP_MJ_DEVICE_CONTROL dispatch routine
--*/
NTSTATUS WinMemIoCtl(IN PDEVICE_OBJECT fdo, IN PIRP irp)
{
	NTSTATUS ntStatus;

	bool bRet = false;
	UNICODE_STRING name;
	ULONG propertyAddress, BusNumber;
	USHORT FunctionNumber, DeviceNumber;
	ULONG  length;

	UNREFERENCED_PARAMETER(fdo);

	//Init to default settings
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(irp);

	//Get the pointer to the input/output buffer and it's length
	PVOID pSysBuf = (PVOID)irp->AssociatedIrp.SystemBuffer;
	PWINMEM_MEM pMem = (PWINMEM_MEM)pSysBuf;
	PWINMEM_PORT pPort = (PWINMEM_PORT)pSysBuf;
	PWINMEM_PCI pPci = (PWINMEM_PCI)pSysBuf;
	ULONG dwInBufLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG dwOutBufLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	RtlInitUnicodeString(&name, DriverName);
	PDRIVER_OBJECT driver;
	ULONG actualCount;
	PDEVICE_OBJECT* m_ppDevices = nullptr;

	switch (irpStack->MajorFunction)
	{
	case IRP_MJ_DEVICE_CONTROL:

		ULONG dwIoCtlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

		switch (dwIoCtlCode)
		{
		case IOCTL_WINMEM_READ_MEM:
			if (dwInBufLen == sizeof(WINMEM_MEM) && ((pMem->dwRegOff + pMem->dwBytes) <= pMem->dwSize) && (dwOutBufLen >= pMem->dwBytes)) {
				PHYSICAL_ADDRESS phyAddr;
				PVOID pvk;

				phyAddr.QuadPart = (ULONGLONG)pMem->pvAddr;

				//get mapped kernel address
				pvk = MmMapIoSpace(phyAddr, pMem->dwSize, MmNonCached);

				if (pvk)
				{
					PVOID pValue;
					pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

					if (!pValue) {
						irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
						break;
					}

					if (pValue != nullptr) {
						switch (pMem->dwBytes) {
						case 1:
							READ_REGISTER_BUFFER_UCHAR((UINT8*)pvk + pMem->dwRegOff, (PUCHAR)pValue, 1);
							break;
						case 2:
							READ_REGISTER_BUFFER_USHORT((USHORT*)((UINT8*)pvk + pMem->dwRegOff), (PUSHORT)pValue, 1);
							break;
						case 4:
							READ_REGISTER_BUFFER_ULONG((ULONG*)((UINT8*)pvk + pMem->dwRegOff), (PULONG)pValue, 1);
							break;
						case 8:
							READ_REGISTER_BUFFER_ULONG64((ULONG64*)((UINT8*)pvk + pMem->dwRegOff), (PULONG64)pValue, 1);
							break;
						default:
							break;
						}
					}
					irp->IoStatus.Information = pMem->dwBytes;
					DbgPrint("pMem->dwBytes : %x\n", pMem->dwBytes);
					MmUnmapIoSpace(pvk, pMem->dwSize);
				}

			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
			break;

		case IOCTL_WINMEM_WRITE_MEM:
			if (dwInBufLen == sizeof(WINMEM_MEM) && ((pMem->dwRegOff + pMem->dwBytes) <= pMem->dwSize) && (dwOutBufLen >= pMem->dwBytes)) {
				PHYSICAL_ADDRESS phyAddr;
				PVOID pvk;

				phyAddr.QuadPart = (ULONGLONG)pMem->pvAddr;

				//get mapped kernel address
				pvk = MmMapIoSpace(phyAddr, pMem->dwSize, MmNonCached);

				if (pvk)
				{
					PVOID pValue;
					pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);

					if (!pValue) {
						irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
						break;
					}

					if (pValue != nullptr) {
						switch (pMem->dwBytes) {
						case 1:
							WRITE_REGISTER_BUFFER_UCHAR((UINT8*)pvk + pMem->dwRegOff, (PUCHAR)pValue, 1);
							break;
						case 2:
							WRITE_REGISTER_BUFFER_USHORT((USHORT*)((UINT8*)pvk + pMem->dwRegOff), (PUSHORT)pValue, 1);
							break;
						case 4:
							WRITE_REGISTER_BUFFER_ULONG((ULONG*)((UINT8*)pvk + pMem->dwRegOff), (PULONG)pValue, 1);
							break;
						case 8:
							WRITE_REGISTER_BUFFER_ULONG64((ULONG64*)((UINT8*)pvk + pMem->dwRegOff), (PULONG64)pValue, 1);
							break;
						default:
							break;
						}
					}
					irp->IoStatus.Information = pMem->dwBytes;
					MmUnmapIoSpace(pvk, pMem->dwSize);
				}
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
			break;

		case IOCTL_WINMEM_MAP:

			if (dwInBufLen == sizeof(WINMEM_MEM) && dwOutBufLen == sizeof(PVOID))
			{
				PHYSICAL_ADDRESS phyAddr;
				PVOID pvk, pvu;
			
				phyAddr.QuadPart = (ULONGLONG)pMem->pvAddr;

				//get mapped kernel address
				pvk = MmMapIoSpace(phyAddr, pMem->dwSize, MmNonCached);

				if (pvk)
				{
					//allocate mdl for the mapped kernel address
					PMDL pMdl = IoAllocateMdl(pvk, pMem->dwSize, FALSE, FALSE, NULL);
					if (pMdl)
					{
						PMAPINFO pMapInfo;

						//build mdl and map to user space
						MmBuildMdlForNonPagedPool(pMdl);
					
						//pvu = MmMapLockedPages(pMdl, UserMode);
						pvu = MmMapLockedPagesSpecifyCache(pMdl, UserMode, MmNonCached, NULL, FALSE, NormalPagePriority);

						if (pvu) {
							//insert mapped infomation to list
							pMapInfo = (PMAPINFO)ExAllocatePool(NonPagedPool, sizeof(MAPINFO));
							pMapInfo->pMdl = pMdl;
							pMapInfo->pvk = pvk;
							pMapInfo->pvu = pvu;
							pMapInfo->memSize = pMem->dwSize;

							locker.Lock();
							InsertHeadList(&linkListHead, &pMapInfo->ListEntry);
							locker.UnLock();

							RtlCopyMemory(pSysBuf, &pvu, sizeof(PVOID));
							irp->IoStatus.Information = sizeof(PVOID);
						}
						else {
							IoFreeMdl(pMdl);
							MmUnmapIoSpace(pvk, pMem->dwSize);
							irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
						}
					}
					else
					{
						//allocate mdl error, unmap the mapped physical memory
						MmUnmapIoSpace(pvk, pMem->dwSize);
						irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					}
				}
				else
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			}
			else
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			break;

		case IOCTL_WINMEM_UNMAP:

			//DbgPrint("IOCTL_WINMEM_UNMAP\n");

			if (dwInBufLen == sizeof(WINMEM_MEM))
			{
				PMAPINFO pMapInfo;
				PLIST_ENTRY pLink;
				
				//initialize to head
				pLink = linkListHead.Flink;

				while (pLink)
				{
					pMapInfo = CONTAINING_RECORD(pLink, MAPINFO, ListEntry);

					if (pMapInfo->pvu == pMem->pvAddr)
					{
						if (pMapInfo->memSize == pMem->dwSize)
						{
							//free mdl, unmap mapped memory
							MmUnmapLockedPages(pMapInfo->pvu, pMapInfo->pMdl);
							IoFreeMdl(pMapInfo->pMdl);
							MmUnmapIoSpace(pMapInfo->pvk, pMapInfo->memSize);

							locker.Lock();
							RemoveEntryList(&pMapInfo->ListEntry);
							locker.UnLock();

							ExFreePool(pMapInfo);
						}
						else
							irp->IoStatus.Status = STATUS_INVALID_PARAMETER;

						break;
					}
					pLink = pLink->Flink;
				}
			}
			else
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;

			break;

		case IOCTL_WINMEM_GETPORT:

			DbgPrint("IOCTL_WINMEM_GETPORT\n");

			if (dwInBufLen == sizeof(WINMEM_PORT) && dwOutBufLen == sizeof(ULONG))
			{
				irp->IoStatus.Information = sizeof(ULONG);

				if (pPort->dwSize == 1)
				{
					*(PULONG)pSysBuf = (ULONG)READ_PORT_UCHAR((PUCHAR)pPort->dwPort);
				}
				else if (pPort->dwSize == 2)
				{
					*(PULONG)pSysBuf = (ULONG)READ_PORT_USHORT((PUSHORT)pPort->dwPort);
				}
				else if (pPort->dwSize == 4)
				{
					*(PULONG)pSysBuf = READ_PORT_ULONG((PULONG)pPort->dwPort);
				}
				else
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
			else
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;

			break;

		case IOCTL_WINMEM_SETPORT:

			DbgPrint("IOCTL_WINMEM_SETPORT\n");

			if (dwInBufLen == sizeof(WINMEM_PORT))
			{
				if (pPort->dwSize == 1)
				{
					WRITE_PORT_UCHAR((PUCHAR)pPort->dwPort, (UCHAR)pPort->dwValue);
				}
				else if (pPort->dwSize == 2)
				{
					WRITE_PORT_USHORT((PUSHORT)pPort->dwPort, (USHORT)pPort->dwValue);
				}
				else if (pPort->dwSize == 4)
				{
					WRITE_PORT_ULONG((PULONG)pPort->dwPort, pPort->dwValue);
				}
				else
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
			else
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			break;

		case IOCTL_WINMEM_GETPCI:
			DbgPrint("IOCTL_WINMEM_GETPCI\n");

			if (dwInBufLen == sizeof(WINMEM_PCI) && ((pPci->dwRegOff + pPci->dwBytes) <= 4096) && (dwOutBufLen >= pPci->dwBytes)) {
				
				PVOID pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				if (!pValue) {
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				irp->IoStatus.Status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE /* | OBJ_OPENIF */, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driver);

				if (!NT_SUCCESS(irp->IoStatus.Status)) {
					DbgPrint("Failure  ObReferenceObjectByName\n");
					break;
				}
				else {
					DbgPrint("Success   ObReferenceObjectByName\n");
				}

				if ((STATUS_BUFFER_TOO_SMALL == (irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, NULL, 0, &actualCount))   && actualCount) ) {
					DbgPrint("Success IoEnumerateDeviceObjectList :%d \n", actualCount);

					m_ppDevices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool, sizeof(PDEVICE_OBJECT) * actualCount);

					if (m_ppDevices) {
						irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, m_ppDevices, actualCount * sizeof(PDEVICE_OBJECT), &actualCount);

						if (NT_SUCCESS(irp->IoStatus.Status)) {
							DbgPrint("Success IoEnumerateDeviceObjectList \n");

							for (size_t i = 0; i < actualCount; ++i) {
								//pdo = IoGetAttachedDeviceReference(m_ppDevices[i]);

								irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyBusNumber, sizeof(ULONG), (PVOID)&BusNumber, &length);
								if (NT_SUCCESS(irp->IoStatus.Status)) {
									DbgPrint("BusNumber:%x\n", BusNumber);

									irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyAddress, sizeof(ULONG), (PVOID)&propertyAddress, &length);
									if (NT_SUCCESS(irp->IoStatus.Status)) {
										DeviceNumber = (USHORT)(((propertyAddress) >> 16) & 0x0000FFFF);
										FunctionNumber = (USHORT)((propertyAddress) & 0x0000FFFF);
										DbgPrint("DeviceNumber:%x\n", DeviceNumber);
										DbgPrint("FunctionNumber:%x\n", FunctionNumber);

										if (BusNumber == pPci->dwBusNum && DeviceNumber == pPci->dwDevNum && FunctionNumber == pPci->dwFuncNum) {
											irp->IoStatus.Status = ReadWriteConfigSpace(m_ppDevices[i], 0, pValue, pPci->dwRegOff, pPci->dwBytes);
											if (NT_SUCCESS(irp->IoStatus.Status)) {
												DbgPrint("Success read config\n");
												bRet = true;
												irp->IoStatus.Information = pPci->dwBytes;
											}
											else {
												irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
											}
											for(size_t j = i; j < actualCount;++j)	ObDereferenceObject(m_ppDevices[j]);
											break;
										}
									}
									else {
										DbgPrint("Failure IoGetDeviceProperty\n");
									}
								}
								else {
									DbgPrint("Failure IoGetDeviceProperty\n");
								}

								ObDereferenceObject(m_ppDevices[i]);

							} // for (i = 0; i < actualCount; i++)

							if (bRet == false) {
								DbgPrint("Object not found\n");
								irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
							}
						}
						ExFreePool(m_ppDevices);
					}
					else {
						DbgPrint("Failure allocation device object list\n");
					}
				}
				else {
					DbgPrint("Failure IoEnumerateDeviceObjectList, cannot get size\n");
				}
				ObDereferenceObject(driver);
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}

			break;

		case IOCTL_WINMEM_SETPCI:

			DbgPrint("IOCTL_WINMEM_SETPCI\n");

			if (dwInBufLen == sizeof(WINMEM_PCI) && ((pPci->dwRegOff + pPci->dwBytes) <= 4096) && (dwOutBufLen >= pPci->dwBytes)) {

				PVOID pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				if (!pValue) {
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				irp->IoStatus.Status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE /* | OBJ_OPENIF */, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driver);

				if (!NT_SUCCESS(irp->IoStatus.Status)) {
					DbgPrint("Failure  ObReferenceObjectByName\n");
					break;
				}
				else {
					DbgPrint("Success   ObReferenceObjectByName\n");
				}

				if ((STATUS_BUFFER_TOO_SMALL == (irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, NULL, 0, &actualCount)) && actualCount)) {
					DbgPrint("Success IoEnumerateDeviceObjectList :%d \n", actualCount);

					m_ppDevices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool, sizeof(PDEVICE_OBJECT) * actualCount);

					if (m_ppDevices) {
						irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, m_ppDevices, actualCount * sizeof(PDEVICE_OBJECT), &actualCount);

						if (NT_SUCCESS(irp->IoStatus.Status)) {
							DbgPrint("Success IoEnumerateDeviceObjectList \n");

							for (size_t i = 0; i < actualCount; ++i) {
								//pdo = IoGetAttachedDeviceReference(m_ppDevices[i]);

								irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyBusNumber, sizeof(ULONG), (PVOID)&BusNumber, &length);
								if (NT_SUCCESS(irp->IoStatus.Status)) {
									DbgPrint("BusNumber:%x\n", BusNumber);

									irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyAddress, sizeof(ULONG), (PVOID)&propertyAddress, &length);
									if (NT_SUCCESS(irp->IoStatus.Status)) {
										DeviceNumber = (USHORT)(((propertyAddress) >> 16) & 0x0000FFFF);
										FunctionNumber = (USHORT)((propertyAddress) & 0x0000FFFF);
										DbgPrint("DeviceNumber:%x\n", DeviceNumber);
										DbgPrint("FunctionNumber:%x\n", FunctionNumber);

										if (BusNumber == pPci->dwBusNum && DeviceNumber == pPci->dwDevNum && FunctionNumber == pPci->dwFuncNum) {
											irp->IoStatus.Status = ReadWriteConfigSpace(m_ppDevices[i], 1, pValue, pPci->dwRegOff, pPci->dwBytes);
											if (NT_SUCCESS(irp->IoStatus.Status)) {
												DbgPrint("Success read config\n");
												bRet = true;
												irp->IoStatus.Information = pPci->dwBytes;
											}
											else {
												irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
											}
											for (size_t j = i; j < actualCount; ++j)	ObDereferenceObject(m_ppDevices[j]);
											break;

										}
									}
									else {
										DbgPrint("Failure IoGetDeviceProperty\n");
									}
								}
								else {
									DbgPrint("Failure IoGetDeviceProperty\n");
								}

								ObDereferenceObject(m_ppDevices[i]);
							} // for (i = 0; i < actualCount; i++)

							if (bRet == false) {
								DbgPrint("Object not found\n");
								irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
							}
						}
						ExFreePool(m_ppDevices);
					}
					else {
						DbgPrint("Failure allocation device object list\n");
					}
				}
				else {
					DbgPrint("Failure IoEnumerateDeviceObjectList, cannot get size\n");
				}

				ObDereferenceObject(driver);
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}

			break;

		case IOCTL_WINMEM_GETPCI_2:
			DbgPrint("IOCTL_WINMEM_GETPCI_2\n");

			if (dwInBufLen == sizeof(WINMEM_PCI) && ((pPci->dwRegOff + pPci->dwBytes) <= 4096) && (dwOutBufLen >= pPci->dwBytes)) {

				PVOID pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				if (!pValue) {
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				irp->IoStatus.Status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE /* | OBJ_OPENIF */, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driver);

				if (!NT_SUCCESS(irp->IoStatus.Status)) {
					DbgPrint("Failure  ObReferenceObjectByName\n");
					break;
				}
				else {
					DbgPrint("Success   ObReferenceObjectByName\n");
				}

				if ((STATUS_BUFFER_TOO_SMALL == (irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, NULL, 0, &actualCount)) && actualCount)) {
					DbgPrint("Success IoEnumerateDeviceObjectList :%d \n", actualCount);

					m_ppDevices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool, sizeof(PDEVICE_OBJECT) * actualCount);

					if (m_ppDevices) {
						irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, m_ppDevices, actualCount * sizeof(PDEVICE_OBJECT), &actualCount);

						if (NT_SUCCESS(irp->IoStatus.Status)) {
							DbgPrint("Success IoEnumerateDeviceObjectList \n");

							for (size_t i = 0; i < actualCount; ++i) {
								//pdo = IoGetAttachedDeviceReference(m_ppDevices[i]);

								irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyBusNumber, sizeof(ULONG), (PVOID)&BusNumber, &length);
								if (NT_SUCCESS(irp->IoStatus.Status)) {
									DbgPrint("BusNumber:%x\n", BusNumber);

									irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyAddress, sizeof(ULONG), (PVOID)&propertyAddress, &length);
									if (NT_SUCCESS(irp->IoStatus.Status)) {
										DeviceNumber = (USHORT)(((propertyAddress) >> 16) & 0x0000FFFF);
										FunctionNumber = (USHORT)((propertyAddress) & 0x0000FFFF);
										DbgPrint("DeviceNumber:%x\n", DeviceNumber);
										DbgPrint("FunctionNumber:%x\n", FunctionNumber);

										if (BusNumber == pPci->dwBusNum && DeviceNumber == pPci->dwDevNum && FunctionNumber == pPci->dwFuncNum) {

											BUS_INTERFACE_STANDARD busInterfaceStandard;
											irp->IoStatus.Status  = GetPCIBusInterfaceStandard(m_ppDevices[i], &busInterfaceStandard);
											if (NT_SUCCESS(irp->IoStatus.Status)) {
												ULONG bytes = busInterfaceStandard.GetBusData(
													busInterfaceStandard.Context,
													PCI_WHICHSPACE_CONFIG,
													pValue,
													pPci->dwRegOff,
													pPci->dwBytes);
												
												if (bytes == pPci->dwBytes) {
													DbgPrint("Success read config\n");
													bRet = true;
													irp->IoStatus.Information = pPci->dwBytes;
												}
												else {
													irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
												}
											}

											for (size_t j = i; j < actualCount; ++j)	ObDereferenceObject(m_ppDevices[j]);
											break;
										}
									}
									else {
										DbgPrint("Failure IoGetDeviceProperty\n");
									}
								}
								else {
									DbgPrint("Failure IoGetDeviceProperty\n");
								}
								ObDereferenceObject(m_ppDevices[i]);
							} // for (i = 0; i < actualCount; i++)

							if (bRet == false) {
								DbgPrint("Object not found\n");
								irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
							}
						}
						ExFreePool(m_ppDevices);
					}
					else {
						DbgPrint("Failure allocation device object list\n");
					}
				}
				else {
					DbgPrint("Failure IoEnumerateDeviceObjectList, cannot get size\n");
				}
				ObDereferenceObject(driver);
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}

			break;

		case IOCTL_WINMEM_SETPCI_2:
			DbgPrint("IOCTL_WINMEM_SETPCI_2\n");

			if (dwInBufLen == sizeof(WINMEM_PCI) && ((pPci->dwRegOff + pPci->dwBytes) <= 4096) && (dwOutBufLen >= pPci->dwBytes)) {

				PVOID pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				if (!pValue) {
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				irp->IoStatus.Status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE /* | OBJ_OPENIF */, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driver);

				if (!NT_SUCCESS(irp->IoStatus.Status)) {
					DbgPrint("Failure  ObReferenceObjectByName\n");
					break;
				}
				else {
					DbgPrint("Success   ObReferenceObjectByName\n");
				}

				if ((STATUS_BUFFER_TOO_SMALL == (irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, NULL, 0, &actualCount)) && actualCount)) {
					DbgPrint("Success IoEnumerateDeviceObjectList :%d \n", actualCount);

					m_ppDevices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool, sizeof(PDEVICE_OBJECT) * actualCount);

					if (m_ppDevices) {
						irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, m_ppDevices, actualCount * sizeof(PDEVICE_OBJECT), &actualCount);

						if (NT_SUCCESS(irp->IoStatus.Status)) {
							DbgPrint("Success IoEnumerateDeviceObjectList \n");

							for (size_t i = 0; i < actualCount; ++i) {
								//pdo = IoGetAttachedDeviceReference(m_ppDevices[i]);

								irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyBusNumber, sizeof(ULONG), (PVOID)&BusNumber, &length);
								if (NT_SUCCESS(irp->IoStatus.Status)) {
									DbgPrint("BusNumber:%x\n", BusNumber);

									irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyAddress, sizeof(ULONG), (PVOID)&propertyAddress, &length);
									if (NT_SUCCESS(irp->IoStatus.Status)) {
										DeviceNumber = (USHORT)(((propertyAddress) >> 16) & 0x0000FFFF);
										FunctionNumber = (USHORT)((propertyAddress) & 0x0000FFFF);
										DbgPrint("DeviceNumber:%x\n", DeviceNumber);
										DbgPrint("FunctionNumber:%x\n", FunctionNumber);

										if (BusNumber == pPci->dwBusNum && DeviceNumber == pPci->dwDevNum && FunctionNumber == pPci->dwFuncNum) {

											BUS_INTERFACE_STANDARD busInterfaceStandard;
											irp->IoStatus.Status = GetPCIBusInterfaceStandard(m_ppDevices[i], &busInterfaceStandard);
											if (NT_SUCCESS(irp->IoStatus.Status)) {
												ULONG bytes = busInterfaceStandard.SetBusData(
													busInterfaceStandard.Context,
													PCI_WHICHSPACE_CONFIG,
													pValue,
													pPci->dwRegOff,
													pPci->dwBytes);

												if (bytes == pPci->dwBytes) {
													DbgPrint("Success write config\n");
													bRet = true;
													irp->IoStatus.Information = pPci->dwBytes;
												}
												else {
													irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
												}
											}

											for (size_t j = i; j < actualCount; ++j)	ObDereferenceObject(m_ppDevices[j]);
											break;
										}
									}
									else {
										DbgPrint("Failure IoGetDeviceProperty\n");
									}
								}
								else {
									DbgPrint("Failure IoGetDeviceProperty\n");
								}
								ObDereferenceObject(m_ppDevices[i]);
							} // for (i = 0; i < actualCount; i++)

							if (bRet == false) {
								DbgPrint("Object not found\n");
								irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
							}
						}

						ExFreePool(m_ppDevices);
					}
					else {
						DbgPrint("Failure allocation device object list\n");
					}
				}
				else {
					DbgPrint("Failure IoEnumerateDeviceObjectList, cannot get size\n");

				}
				ObDereferenceObject(driver);
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}

			break;

		case IOCTL_WINMEM_GETPCI_3:
			DbgPrint("IOCTL_WINMEM_GETPCI_3\n");

			if (dwInBufLen == sizeof(WINMEM_PCI) && ((pPci->dwRegOff + pPci->dwBytes) <= 4096) && (dwOutBufLen >= pPci->dwBytes)) {
				PVOID pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				if (!pValue) {
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				PCI_SLOT_NUMBER slot = { 0 };
				slot.u.bits.DeviceNumber = pPci->dwDevNum;
				slot.u.bits.FunctionNumber = pPci->dwFuncNum;
				ULONG bytes = HalGetBusDataByOffset(PCIConfiguration,
					pPci->dwBusNum, slot.u.AsULONG,
					pValue, pPci->dwRegOff, pPci->dwBytes);

				if (pPci->dwBytes == bytes) {
					irp->IoStatus.Information = pPci->dwBytes;
				}
				else {
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				}
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}

			break;

		case IOCTL_WINMEM_SETPCI_3:
			DbgPrint("IOCTL_WINMEM_SETPCI_3\n");

			if (dwInBufLen == sizeof(WINMEM_PCI) && ((pPci->dwRegOff + pPci->dwBytes) <= 4096) && (dwOutBufLen >= pPci->dwBytes)) {
				PVOID pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				if (!pValue) {
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				PCI_SLOT_NUMBER slot = { 0 };
				slot.u.bits.DeviceNumber = pPci->dwDevNum;
				slot.u.bits.FunctionNumber = pPci->dwFuncNum;
				ULONG bytes = HalSetBusDataByOffset(PCIConfiguration,
					pPci->dwBusNum, slot.u.AsULONG,
					pValue, pPci->dwRegOff, pPci->dwBytes);

				if (pPci->dwBytes == bytes) {
					irp->IoStatus.Information = pPci->dwBytes;
				}
				else {
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				}
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}

			break;
		
		case IOCTL_WINMEM_TEST:

			irp->IoStatus.Status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE /* | OBJ_OPENIF */, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driver);

			if (!NT_SUCCESS(irp->IoStatus.Status)) {
				DbgPrint("Failure  ObReferenceObjectByName\n");
				break;
			}
			else {
				DbgPrint("Success   ObReferenceObjectByName\n");
			}

			if ((STATUS_BUFFER_TOO_SMALL == (irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, NULL, 0, &actualCount)) && actualCount)) {
				DbgPrint("Success IoEnumerateDeviceObjectList :%d \n", actualCount);

				m_ppDevices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool, sizeof(PDEVICE_OBJECT) * actualCount);

				if (m_ppDevices) {
					irp->IoStatus.Status = IoEnumerateDeviceObjectList(driver, m_ppDevices, actualCount * sizeof(PDEVICE_OBJECT), &actualCount);

					if (NT_SUCCESS(irp->IoStatus.Status)) {
						DbgPrint("Success IoEnumerateDeviceObjectList \n");

						for (size_t i = 0; i < actualCount; ++i) {
							//pdo = IoGetAttachedDeviceReference(m_ppDevices[i]);

							irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyBusNumber, sizeof(ULONG), (PVOID)&BusNumber, &length);
							if (NT_SUCCESS(irp->IoStatus.Status)) {
								DbgPrint("BusNumber:%x\n", BusNumber);

								irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyAddress, sizeof(ULONG), (PVOID)&propertyAddress, &length);
								if (NT_SUCCESS(irp->IoStatus.Status)) {
									DeviceNumber = (USHORT)(((propertyAddress) >> 16) & 0x0000FFFF);
									FunctionNumber = (USHORT)((propertyAddress) & 0x0000FFFF);
									DbgPrint("DeviceNumber:%x\n", DeviceNumber);
									DbgPrint("FunctionNumber:%x\n", FunctionNumber);

									if (BusNumber == pPci->dwBusNum && DeviceNumber == pPci->dwDevNum && FunctionNumber == pPci->dwFuncNum) {

#if 1
										irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyAllocatedResources, 0, NULL, &length);

										if (irp->IoStatus.Status == STATUS_BUFFER_TOO_SMALL && length) {
											PVOID   buf = ExAllocatePool(PagedPool, length);

											if (buf) {
												irp->IoStatus.Status = IoGetDeviceProperty(m_ppDevices[i], DevicePropertyAllocatedResources, length, buf, &length);
												PCM_RESOURCE_LIST prl = (PCM_RESOURCE_LIST)buf;
												PCM_FULL_RESOURCE_DESCRIPTOR pfrd = prl->List;
												PCM_PARTIAL_RESOURCE_LIST pprl = &pfrd->PartialResourceList;

												DbgPrint("count: %d\n", pprl->Count);
												ULONG			nres = pprl->Count;

												PCM_PARTIAL_RESOURCE_DESCRIPTOR pprd = pprl->PartialDescriptors;

												for (int i = 0; i < nres; ++i, ++pprd) {
													switch (pprd->Type) {
														case CmResourceTypePort:
															DbgPrint("CmResourceTypePort\n");
															break;
														case CmResourceTypeMemory:
															DbgPrint("CmResourceTypeMemory\n");
															break;
														case CmResourceTypeBusNumber:
															DbgPrint("CmResourceTypeBusNumber\n");
															break;
														case CmResourceTypeInterrupt:
															DbgPrint("CmResourceTypeInterrupt\n");
															break;
														case CmResourceTypeDma:
															DbgPrint("CmResourceTypeDma\n");
															break;
													
													}
												}
												ExFreePool(buf);
											}
										}
#endif
										for (size_t j = i; j < actualCount; ++j)	ObDereferenceObject(m_ppDevices[j]);
										break;
									}
								}
								else {
									DbgPrint("Failure IoGetDeviceProperty\n");
								}
							}
							else {
								DbgPrint("Failure IoGetDeviceProperty\n");
							}

							ObDereferenceObject(m_ppDevices[i]);

						} // for (i = 0; i < actualCount; i++)

						if (bRet == false) {
							DbgPrint("Object not found\n");
							irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
						}
					}

					ExFreePool(m_ppDevices);
				}
				else {
					DbgPrint("Failure allocation device object list\n");
				}
			}
			else {
				DbgPrint("Failure IoEnumerateDeviceObjectList, cannot get size\n");

			}

			ObDereferenceObject(driver);
			break;

		default:

			DbgPrint("Error: Unknown IO CONTROL CODE\n");

			break;
		}
		break;
	}

	ntStatus = irp->IoStatus.Status;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	//DbgPrint("Leaving WINMEMIoCtl\n");

	return ntStatus;
}

/*++
Driver Unload routine
--*/
VOID WinMemUnload(IN PDRIVER_OBJECT dro)
{
	UNICODE_STRING DeviceLinkU;
	NTSTATUS ntStatus;
	PMAPINFO pMapInfo;

	DbgPrint("Entering WinMemUnload\n");

	while (!IsListEmpty(&linkListHead))
	{
		PLIST_ENTRY pEntry = RemoveTailList(&linkListHead);
		pMapInfo = CONTAINING_RECORD(pEntry, MAPINFO, ListEntry);

		//DbgPrint("Map physical 0x%p to virtual 0x%p, size %u\n", pMapInfo->pvk, pMapInfo->pvu , pMapInfo->memSize );

		MmUnmapLockedPages(pMapInfo->pvu, pMapInfo->pMdl);
		IoFreeMdl(pMapInfo->pMdl);
		MmUnmapIoSpace(pMapInfo->pvk, pMapInfo->memSize);

		ExFreePool(pMapInfo);

	}

	RtlInitUnicodeString(&DeviceLinkU, DeviceSymLink);

	ntStatus = IoDeleteSymbolicLink(&DeviceLinkU);

	if (NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(dro->DeviceObject);
	}
	else
	{
		DbgPrint("Error: IoDeleteSymbolicLink failed\n");
	}
	DbgPrint("Leaving WinMemUnload\n");
}

NTSTATUS
ReadWriteConfigSpace(
	IN PDEVICE_OBJECT DeviceObject,
	IN ULONG	      ReadOrWrite, // 0 for read 1 for write
	IN PVOID	      Buffer,
	IN ULONG	      Offset,
	IN ULONG	      Length
)
{
	KEVENT event;
	NTSTATUS status;
	PIRP irp;
	IO_STATUS_BLOCK ioStatusBlock;
	PIO_STACK_LOCATION irpStack;
	PDEVICE_OBJECT targetObject;

	PAGED_CODE();

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	targetObject = IoGetAttachedDeviceReference(DeviceObject);

	irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
		targetObject,
		NULL,
		0,
		NULL,
		&event,
		&ioStatusBlock);

	if (irp == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto End;
	}

	irpStack = IoGetNextIrpStackLocation(irp);

	if (ReadOrWrite == 0) {
		irpStack->MinorFunction = IRP_MN_READ_CONFIG;
	}
	else {
		irpStack->MinorFunction = IRP_MN_WRITE_CONFIG;
	}

	irpStack->Parameters.ReadWriteConfig.WhichSpace = PCI_WHICHSPACE_CONFIG;
	irpStack->Parameters.ReadWriteConfig.Buffer = Buffer;
	irpStack->Parameters.ReadWriteConfig.Offset = Offset;
	irpStack->Parameters.ReadWriteConfig.Length = Length;

	// 
	// Initialize the status to error in case the bus driver does not 
	// set it correctly.
	// 

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	status = IoCallDriver(targetObject, irp);

	if (status == STATUS_PENDING) {

		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = ioStatusBlock.Status;
	}

End:
	// 
	// Done with reference
	// 
	ObDereferenceObject(targetObject);

	return status;

}



NTSTATUS
GetPCIBusInterfaceStandard(
	IN  PDEVICE_OBJECT DeviceObject,
	OUT PBUS_INTERFACE_STANDARD	BusInterfaceStandard
)
/*++

Routine Description:

	This routine gets the bus interface standard information from the PDO.

Arguments:

	DeviceObject - Device object to query for this information.

	BusInterface - Supplies a pointer to the retrieved information.

Return Value:

	NT status.

--*/
{
	KEVENT event;
	NTSTATUS status;
	PIRP irp;
	IO_STATUS_BLOCK ioStatusBlock;
	PIO_STACK_LOCATION irpStack;
	PDEVICE_OBJECT targetObject;

	DbgPrint("GetPciBusInterfaceStandard entered.\n");

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	targetObject = IoGetAttachedDeviceReference(DeviceObject);

	irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
		targetObject,
		NULL,
		0,
		NULL,
		&event,
		&ioStatusBlock);

	if (irp == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto End;
	}

	irpStack = IoGetNextIrpStackLocation(irp);
	irpStack->MinorFunction = IRP_MN_QUERY_INTERFACE;
	irpStack->Parameters.QueryInterface.InterfaceType =
		(LPGUID)&GUID_BUS_INTERFACE_STANDARD;
	irpStack->Parameters.QueryInterface.Size = sizeof(BUS_INTERFACE_STANDARD);
	irpStack->Parameters.QueryInterface.Version = 1;
	irpStack->Parameters.QueryInterface.Interface = (PINTERFACE)
		BusInterfaceStandard;
	irpStack->Parameters.QueryInterface.InterfaceSpecificData = NULL;

	// 
	// Initialize the status to error in case the bus driver does not 
	// set it correctly.
	// 

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	status = IoCallDriver(targetObject, irp);

	if (status == STATUS_PENDING) {

		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = ioStatusBlock.Status;
	}

End:
	// 
	// Done with reference
	// 
	ObDereferenceObject(targetObject);

	return status;

}


