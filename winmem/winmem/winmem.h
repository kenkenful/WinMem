#pragma once
#define	FILE_DEVICE_WINMEM	0x8000

const WCHAR DeviceSymLink[] = L"\\??\\WinMem";
const WCHAR DeviceName[] = L"\\Device\\WinMem";
const WCHAR DriverName[] = L"\\driver\\pci";




#define	IOCTL_WINMEM_MAP			CTL_CODE(FILE_DEVICE_WINMEM, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_WINMEM_UNMAP		CTL_CODE(FILE_DEVICE_WINMEM, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_WINMEM_GETPORT	CTL_CODE(FILE_DEVICE_WINMEM, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	IOCTL_WINMEM_SETPORT	CTL_CODE(FILE_DEVICE_WINMEM, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define	IOCTL_WINMEM_GETPCI		CTL_CODE(FILE_DEVICE_WINMEM, 0x804,	METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define	IOCTL_WINMEM_SETPCI		CTL_CODE(FILE_DEVICE_WINMEM, 0x805,	METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define	IOCTL_WINMEM_READ_MEM			CTL_CODE(FILE_DEVICE_WINMEM, 0x807, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define	IOCTL_WINMEM_WRITE_MEM		CTL_CODE(FILE_DEVICE_WINMEM, 0x808, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define	IOCTL_WINMEM_GETPCI_2		CTL_CODE(FILE_DEVICE_WINMEM, 0x809,	METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define	IOCTL_WINMEM_SETPCI_2		CTL_CODE(FILE_DEVICE_WINMEM, 0x80A,	METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

#define	IOCTL_WINMEM_GETPCI_3		CTL_CODE(FILE_DEVICE_WINMEM, 0x80B,	METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define	IOCTL_WINMEM_SETPCI_3		CTL_CODE(FILE_DEVICE_WINMEM, 0x80C,	METHOD_OUT_DIRECT, FILE_ANY_ACCESS)


typedef struct tagWINMEM_MEM
{
	PVOID pvAddr;	//physical addr when mapping, virtual addr when unmapping
	ULONG dwSize;	//memory size to map or unmap
	ULONG dwRegOff;		//register offset: 0-255
	ULONG dwBytes;		//bytes to read or write
} WINMEM_MEM, * PWINMEM_MEM;

typedef struct tagWINMEM_PORT
{
	ULONG dwPort;	//port number: 0-0xFFFF
	ULONG dwSize;	//must be 1, 2, 4
	ULONG dwValue;	//new value to set
} WINMEM_PORT, * PWINMEM_PORT;

typedef struct tagWINMEM_PCI
{
	ULONG dwBusNum;		//bus number: 0-255
	ULONG dwDevNum;		//device number: 0-31
	ULONG dwFuncNum;	//function number: 0-7
	ULONG dwRegOff;		//register offset: 0-255
	ULONG dwBytes;		//bytes to read or write
} WINMEM_PCI, * PWINMEM_PCI;
