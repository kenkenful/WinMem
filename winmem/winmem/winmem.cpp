#include <ntddk.h>
#include "winmem.h"

//Mapped memory information list
typedef struct tagMAPINFO
{
	SINGLE_LIST_ENTRY	link;
	PMDL				pMdl;	//allocated mdl
	PVOID				pvk;	//kernel mode virtual address
	PVOID				pvu;	//user mode virtual address
	ULONG				memSize;//memory size in bytes
} MAPINFO, * PMAPINFO;

SINGLE_LIST_ENTRY lstMapInfo;	//mapped memory information

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
	_Out_ PVOID * Object);



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

typedef struct tagWINMEM_PCIINFO {
	WINMEM_PCI    s;
	PDEVICE_OBJECT   obj;
}WINMEM_PCIINFO, *PWINMEM_PCIINFO;

const int MAX_OBJECT_SIZE = 256;
UCHAR gucCounter;
WINMEM_PCIINFO info[MAX_OBJECT_SIZE];     // nvme or secondary bus

KSPIN_LOCK singlelist_spinLock;

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

	lstMapInfo.Next = NULL;

#if 0
	//initialize pci bus interface buffer
	busInterface = (PPCI_BUS_INTERFACE_STANDARD)ExAllocatePool(NonPagedPool,
		sizeof(PCI_BUS_INTERFACE_STANDARD));
	if (busInterface == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(busInterface, sizeof(PCI_BUS_INTERFACE_STANDARD));
#endif

	RtlInitUnicodeString(&DeviceNameU, DeviceName);

	KeInitializeSpinLock(&singlelist_spinLock);

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
	PIO_STACK_LOCATION irpStack;
	ULONG dwInBufLen;
	ULONG dwOutBufLen;
	ULONG dwIoCtlCode;
	NTSTATUS ntStatus;
	PVOID pSysBuf;
	PWINMEM_MEM pMem;
	PWINMEM_PORT pPort;
	PWINMEM_PCI pPci;


	bool bRet = false;
	UNICODE_STRING name;
	PDEVICE_OBJECT pdo;
	//PCI_COMMON_CONFIG pci_config;
	ULONG propertyAddress, BusNumber;
	USHORT FunctionNumber, DeviceNumber;
	ULONG  length;


	UNREFERENCED_PARAMETER(fdo);
	//DbgPrint("Entering WinMemIoCtl\n");

	//Init to default settings
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	irpStack = IoGetCurrentIrpStackLocation(irp);

	//Get the pointer to the input/output buffer and it's length
	pSysBuf = (PVOID)irp->AssociatedIrp.SystemBuffer;
	pMem = (PWINMEM_MEM)pSysBuf;
	pPort = (PWINMEM_PORT)pSysBuf;
	pPci = (PWINMEM_PCI)pSysBuf;
	dwInBufLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	dwOutBufLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (irpStack->MajorFunction)
	{
	case IRP_MJ_DEVICE_CONTROL:

		dwIoCtlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

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

					if (pValue != nullptr) {
						switch (pMem->dwBytes) {
						case 1:
							*(UINT8*)pValue = *(UINT8*)((UINT8*)pvk + pMem->dwRegOff);
							break;
						case 2:
							*(UINT16*)pValue = *(UINT16*)((UINT8*)pvk + pMem->dwRegOff);
							break;
						case 4:
							*(UINT32*)pValue = *(UINT32*)((UINT8*)pvk + pMem->dwRegOff);
							break;

						case 8:
							*(UINT64*)pValue = *(UINT64*)((UINT8*)pvk + pMem->dwRegOff);
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
					if (pValue != nullptr) {
						switch (pMem->dwBytes) {
						case 1:
							*(UINT8*)((UINT8*)pvk + pMem->dwRegOff) = *(UINT8*)pValue;
							break;
						case 2:
							*(UINT16*)((UINT8*)pvk + pMem->dwRegOff) = *(UINT16*)pValue;
							break;
						case 4:
							*(UINT32*)((UINT8*)pvk + pMem->dwRegOff) = *(UINT32*)pValue;
							break;

						case 8:
							*(UINT64*)((UINT8*)pvk + pMem->dwRegOff) = *(UINT64*)pValue;
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

							//PushEntryList(&lstMapInfo, &pMapInfo->link);
							ExInterlockedPushEntryList(&lstMapInfo, &pMapInfo->link, &singlelist_spinLock);

							//DbgPrint("Map kernel virtual addr: 0x%p , user virtual addr: 0x%p, size %u\n", pvk, pvu, pMem->dwSize);

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
				PSINGLE_LIST_ENTRY pLink, pPrevLink;
				KIRQL oldIrql;
				
				KeAcquireSpinLock(&singlelist_spinLock, &oldIrql);

				//initialize to head
				pPrevLink = pLink = lstMapInfo.Next;

				while (pLink)
				{
					pMapInfo = CONTAINING_RECORD(pLink, MAPINFO, link);

					if (pMapInfo->pvu == pMem->pvAddr)
					{
						if (pMapInfo->memSize == pMem->dwSize)
						{
							//free mdl, unmap mapped memory
							MmUnmapLockedPages(pMapInfo->pvu, pMapInfo->pMdl);
							IoFreeMdl(pMapInfo->pMdl);
							MmUnmapIoSpace(pMapInfo->pvk, pMapInfo->memSize);

							//DbgPrint("Unmap user virtual address 0x%p, size %u\n", pMapInfo->pvu, pMapInfo->memSize);

							//delete matched element from the list
							if (pLink == lstMapInfo.Next)
								lstMapInfo.Next = pLink->Next;	//delete head elememt
							else
								pPrevLink->Next = pLink->Next;

							ExFreePool(pMapInfo);
						}
						else
							irp->IoStatus.Status = STATUS_INVALID_PARAMETER;

						break;
					}

					pPrevLink = pLink;
					pLink = pLink->Next;
				}

				KeReleaseSpinLock(&singlelist_spinLock, oldIrql);

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

#if 1
		case IOCTL_WINMEM_GETPCI:
			DbgPrint("IOCTL_WINMEM_GETPCI\n");
			if (dwInBufLen == sizeof(WINMEM_PCI) && ((pPci->dwRegOff + pPci->dwBytes) <= 4096) && (dwOutBufLen >= pPci->dwBytes)) {
				for (int i = 0; i < gucCounter; ++i) {
					if (info[i].s.dwBusNum == pPci->dwBusNum && info[i].s.dwDevNum == pPci->dwDevNum && info[i].s.dwFuncNum == pPci->dwFuncNum) {
						PVOID pValue;
						pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
						irp->IoStatus.Status = ReadWriteConfigSpace(info[i].obj, 0, pValue, pPci->dwRegOff, pPci->dwBytes);

						if (NT_SUCCESS(irp->IoStatus.Status)){
							bRet = true;
							DbgPrint("Success read config\n");

							irp->IoStatus.Information = pPci->dwBytes;
							break;
						}
					}
				}
				if (bRet == false) {
					DbgPrint("Object not found\n");
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				}
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
			break;

		case IOCTL_WINMEM_SETPCI:

			DbgPrint("IOCTL_WINMEM_SETPCI\n");

			if (dwInBufLen == sizeof(WINMEM_PCI) && ((pPci->dwRegOff + pPci->dwBytes) <= 4096) && (dwOutBufLen >= pPci->dwBytes)) {
				for (int i = 0; i < gucCounter; ++i) {
					if (info[i].s.dwBusNum == pPci->dwBusNum && info[i].s.dwDevNum == pPci->dwDevNum && info[i].s.dwFuncNum == pPci->dwFuncNum) {
						PVOID pValue;
						pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
						irp->IoStatus.Status = ReadWriteConfigSpace(info[i].obj, 1, pValue, pPci->dwRegOff, pPci->dwBytes);

						if (NT_SUCCESS(irp->IoStatus.Status)) {
							bRet = true;
							DbgPrint("Success write config\n");

							irp->IoStatus.Information = pPci->dwBytes;
							break;
						}
					}
				}
				if (bRet == false) {
					DbgPrint("Object not found\n");
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				}
			}
			else {
				DbgPrint("invalid parameter\n");
				irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			}
			break;
#endif

		case IOCTL_WINMEM_GETOBJ:
			RtlInitUnicodeString(&name, DriverName);
			PDRIVER_OBJECT driver;
			ULONG actualCount ;
			PDEVICE_OBJECT *m_ppDevices;

			ntStatus = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, nullptr, 0,
				*IoDriverObjectType, KernelMode, nullptr, (PVOID*)&driver);

			if (!NT_SUCCESS(ntStatus)) {
				DbgPrint("Failure  ObReferenceObjectByName\n");
				break;
			}
			else {
				DbgPrint("Success   ObReferenceObjectByName\n");
			}

#if 1
			ntStatus = IoEnumerateDeviceObjectList(driver, NULL, 0, &actualCount);

			 DbgPrint("Success IoEnumerateDeviceObjectList :%d \n", actualCount);


			//m_ppDevices = new PDEVICE_OBJECT[actualCount];
			m_ppDevices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPool, sizeof(PDEVICE_OBJECT) * actualCount);


			ntStatus = IoEnumerateDeviceObjectList(driver, m_ppDevices, actualCount * sizeof(PDEVICE_OBJECT), &actualCount);
			if (NT_SUCCESS(ntStatus)) {
				DbgPrint("Success IoEnumerateDeviceObjectList \n");
				for (size_t i = 0; i < actualCount; i++) {
					//pdo = IoGetAttachedDeviceReference(m_ppDevices[i]);
					
					ntStatus = IoGetDeviceProperty(m_ppDevices[i],
						DevicePropertyBusNumber,
						sizeof(ULONG),
						(PVOID)&BusNumber,
						&length);
					if (NT_SUCCESS(ntStatus)) {
						DbgPrint("BusNumber:%x\n", BusNumber);

						ntStatus = IoGetDeviceProperty(m_ppDevices[i],
							DevicePropertyAddress,
							sizeof(ULONG),
							(PVOID)&propertyAddress,
							&length);
						
						if (NT_SUCCESS(ntStatus)) {
							FunctionNumber = (USHORT)((propertyAddress) & 0x0000FFFF);
							DeviceNumber = (USHORT)(((propertyAddress) >> 16) & 0x0000FFFF);
							DbgPrint("DeviceNumber:%x\n", DeviceNumber);
							DbgPrint("FunctionNumber:%x\n", FunctionNumber);

							if (BusNumber == pPci->dwBusNum && DeviceNumber == pPci->dwDevNum && FunctionNumber == pPci->dwFuncNum) {
								PCI_COMMON_CONFIG pci_config;
								auto status = ReadWriteConfigSpace(m_ppDevices[i], 0, &pci_config, 0, sizeof(PCI_COMMON_CONFIG));
								if (NT_SUCCESS(status))
								{
									DbgPrint("======================PCI_COMMON_CONFIG Begin=====================\n");
									DbgPrint("VendorID:%x\n", pci_config.VendorID);
									DbgPrint("DeviceID:%x\n", pci_config.DeviceID);
									DbgPrint("CapabilitiesPtr: %x\n", pci_config.u.type0.CapabilitiesPtr);
								}
								break;
							}
							
						}else
							DbgPrint("Failure IoGetDeviceProperty\n");

					}
					else
						DbgPrint("Failure IoGetDeviceProperty\n");

				}
			}

			for (size_t i = 0; i < actualCount; i++)
				ObDereferenceObject(m_ppDevices[i]);

			ExFreePool(m_ppDevices);

			ObDereferenceObject(driver);

#endif


#if 0
			pdo = driver->DeviceObject;


			while (pdo)
			{
				IoGetDeviceProperty(pdo,
					DevicePropertyBusNumber,
					sizeof(ULONG),
					(PVOID)&BusNumber,
					&length);

				// 
				// Get the DevicePropertyAddress
				// 
				IoGetDeviceProperty(pdo,
					DevicePropertyAddress,
					sizeof(ULONG),
					(PVOID)&propertyAddress,
					&length);
				// 
				// For PCI, the DevicePropertyAddress has device number 
				// in the high word and the function number in the low word. 
				// 
				FunctionNumber = (USHORT)((propertyAddress) & 0x0000FFFF);
				DeviceNumber = (USHORT)(((propertyAddress) >> 16) & 0x0000FFFF);


				if (BusNumber == pPci->dwBusNum && DeviceNumber == pPci->dwDevNum && FunctionNumber == pPci->dwFuncNum && gucCounter < MAX_OBJECT_SIZE) {
					info[gucCounter].s.dwBusNum = pPci->dwBusNum;
					info[gucCounter].s.dwDevNum = pPci->dwDevNum;
					info[gucCounter].s.dwFuncNum = pPci->dwFuncNum;
					info[gucCounter].obj = pdo;

					PCI_COMMON_CONFIG pci_config;
					auto status = ReadWriteConfigSpace(info[gucCounter].obj, 0, &pci_config, 0, sizeof(PCI_COMMON_CONFIG));
					if (NT_SUCCESS(status))
					{
						DbgPrint("======================PCI_COMMON_CONFIG Begin=====================\n");
						DbgPrint("VendorID:%x\n", pci_config.VendorID);
						DbgPrint("DeviceID:%x\n", pci_config.DeviceID);
						DbgPrint("CapabilitiesPtr: %x\n", pci_config.u.type0.CapabilitiesPtr);
					}
					else {
						DbgPrint("Failure ReadWriteconfig\n");
					}

					gucCounter++;
					break;
				}
				pdo = pdo->NextDevice;
			}
#endif 
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
	PSINGLE_LIST_ENTRY pLink;

	DbgPrint("Entering WinMemUnload\n");

#if 0
	pLink = lstMapInfo.Next;
	
	for (int i = 0; i < 100, pLink != nullptr ; ++i) {
		pMapInfo = CONTAINING_RECORD(pLink, MAPINFO, link);
		DbgPrint("WinMemUnload: kernel addr: 0x%p,  virtual addr: 0x%p, size %u\n", pMapInfo->pvk, pMapInfo->pvu, pMapInfo->memSize);
		pLink = pLink->Next;
	}
#endif

#if 1
	//free resources
	pLink = PopEntryList(&lstMapInfo);
	//pLink = ExInterlockedPopEntryList(&lstMapInfo, &spinLock);

	while (pLink)
	{
		pMapInfo = CONTAINING_RECORD(pLink, MAPINFO, link);

		//DbgPrint("Map physical 0x%p to virtual 0x%p, size %u\n", pMapInfo->pvk, pMapInfo->pvu , pMapInfo->memSize );

		MmUnmapLockedPages(pMapInfo->pvu, pMapInfo->pMdl);
		IoFreeMdl(pMapInfo->pMdl);
		MmUnmapIoSpace(pMapInfo->pvk, pMapInfo->memSize);

		ExFreePool(pMapInfo);

		pLink = PopEntryList(&lstMapInfo);
		//pLink = ExInterlockedPopEntryList(&lstMapInfo, &spinLock);
	}
#endif

#if 0
	if (busInterface && busInterface->InterfaceDereference)
	{
		(*busInterface->InterfaceDereference)(busInterface->Context);

		ExFreePool(busInterface);
	}
#endif

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

#if 0
//prepare to get bus interface
static NTSTATUS PreGetBus()
{
	NTSTATUS ntStatus;
	UNICODE_STRING pcifidoNameU;

	ntStatus = STATUS_SUCCESS;

	//get pci filter driver do
	if (pcifido == NULL)
	{
		RtlInitUnicodeString(&pcifidoNameU, L"\\Device\\WinMemPCIFilter");

		ntStatus = IoGetDeviceObjectPointer(&pcifidoNameU,
			FILE_READ_DATA | FILE_WRITE_DATA,
			&pcifo,
			&pcifido);

		if (NT_SUCCESS(ntStatus))
		{
			DbgPrint("Got pci filter device object: 0x%x", pcifido);
		}
		else
		{
			DbgPrint("Get pci filter device object failed, code=0x%x", ntStatus);

			return STATUS_UNSUCCESSFUL;
		}
	}

	//get bus interface
	if (busInterface->ReadConfig == NULL)
	{
		ntStatus = GetBusInterface(pcifido, busInterface);

		if (NT_SUCCESS(ntStatus))
		{
			DbgPrint("Got pci bus filter driver interface");
		}
		else
		{
			DbgPrint("Get pci bus driver interface failed, code=0x%x", ntStatus);
		}
	}

	return ntStatus;
}

//read pci configuration
static NTSTATUS ReadWriteConfig(PIRP irp, PWINMEM_PCI pPci, BOOLEAN isRead)
{
	NTSTATUS ntStatus;

	//get pci filter driver interface
	ntStatus = PreGetBus();

	if (NT_SUCCESS(ntStatus))
	{
		PVOID pValue;

		//get out buffer kernel address
		pValue = (PVOID)MmGetSystemAddressForMdlSafe(irp->MdlAddress,
			NormalPagePriority);

		if (pValue)
		{
			PCI_SLOT_NUMBER slot;
			ULONG ulRet;

			slot.u.AsULONG = 0;
			slot.u.bits.DeviceNumber = pPci->dwDevNum;
			slot.u.bits.FunctionNumber = pPci->dwFuncNum;

			if (isRead)
				ulRet = (*busInterface->ReadConfig)(busInterface->Context,	//context
					(UCHAR)pPci->dwBusNum,	//busoffset
					slot.u.AsULONG,			//slot
					pValue,					//buffer
					pPci->dwRegOff,			//offset
					pPci->dwBytes);			//length

			else
				ulRet = (*busInterface->WriteConfig)(busInterface->Context,	//context
					(UCHAR)pPci->dwBusNum,	//busoffset
					slot.u.AsULONG,			//slot
					pValue,					//buffer
					pPci->dwRegOff,			//offset
					pPci->dwBytes);			//length

			if (ulRet == pPci->dwBytes)
			{
				ntStatus = STATUS_SUCCESS;

				if (isRead)
					DbgPrint("Read %d bytes from pci config space", ulRet);
				else
					DbgPrint("Write %d bytes to pci config space", ulRet);
			}
			else
				ntStatus = STATUS_UNSUCCESSFUL;
		}
		else
			ntStatus = STATUS_INVALID_PARAMETER;
	}

	return ntStatus;
}


#endif

NTSTATUS
ReadWriteConfigSpace(
	IN PDEVICE_OBJECT DeviceObject,
	//IN PDEVICE_OBJECT targetObject,
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