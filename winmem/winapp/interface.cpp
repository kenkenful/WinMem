#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include "interface.h"
#include "../winmem/winmem.h"

HANDLE hDriver = INVALID_HANDLE_VALUE;

BOOL InstallDriver(PCSTR pszDriverPath, PCSTR pszDriverName);
BOOL RemoveDriver(PCSTR pszDriverName);
BOOL StartDriver(PCSTR pszDriverName);
BOOL StopDriver(PCSTR pszDriverName);

//get driver(WinMem.sys) full path
static BOOL GetDriverPath(PSTR szDriverPath)
{
	PSTR pszSlash;

	if (!GetModuleFileName(GetModuleHandle(nullptr), szDriverPath, MAX_PATH))
		return FALSE;

	pszSlash = strrchr(szDriverPath, '\\');

	if (pszSlash)
		pszSlash[1] = '\0';
	else
		return FALSE;

	return TRUE;
}

//install and start driver
BOOL LoadWinMemDriver()
{
	std::cout << "LoadWinMemDriver" << std::endl;
	BOOL bResult;
	CHAR szDriverPath[MAX_PATH] = {0};

	CHAR szDeviceSymLink[MAX_PATH] = {0};
	size_t iReturnValue;
	errno_t ret = wcstombs_s(&iReturnValue,
		szDeviceSymLink,
	    sizeof(szDeviceSymLink),
		 DeviceSymLink,
		_TRUNCATE
	);

	if (ret != 0){
		printf("wcstombs_s error!! ret=%d\n", ret);
		return FALSE;
	}
	std::cout << szDeviceSymLink << std::endl;
	hDriver = CreateFile(szDeviceSymLink,
		GENERIC_READ | GENERIC_WRITE,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	//If the driver is not running, install it
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		GetDriverPath(szDriverPath);
		strcat(szDriverPath, "winmem.sys");
		std::cout << szDriverPath << std::endl;
		bResult = InstallDriver(szDriverPath, "WINMEM");

		if (!bResult) {
			std::cout << "fail to install winmem" << std::endl;
			return FALSE;
		}
			
		bResult = StartDriver("WINMEM");

		if (!bResult)
			return FALSE;

		hDriver = CreateFile(szDeviceSymLink,
			GENERIC_READ | GENERIC_WRITE,
			0,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);

		if (hDriver == INVALID_HANDLE_VALUE)
			return FALSE;
	}

	std::cout << "install winmem driver" << std::endl;
	return TRUE;
}

//stop and remove driver
VOID UnloadWinMemDriver()
{
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hDriver);
		hDriver = INVALID_HANDLE_VALUE;
	}

	if (RemoveDriver("WINMEM")) {
		std::cout << "uninstall winmem driver" << std::endl;
	}
}

//map physical memory to user space
PVOID MapWinMem(DWORD phyAddr, DWORD memSize)
{
	PVOID pVirAddr = nullptr;	//mapped virtual addr
	WINMEM_MEM pm;
	DWORD dwBytes = 0;
	BOOL bRet = FALSE;

	pm.pvAddr = (PVOID)phyAddr;	//physical address
	pm.dwSize = memSize;	//memory size

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_MAP, &pm,
			sizeof(WINMEM_MEM), &pVirAddr, sizeof(PVOID), &dwBytes, nullptr);
	}

	if (bRet && dwBytes == sizeof(PVOID))
		return pVirAddr;
	else
		return nullptr;
}

//unmap memory
VOID UnmapWinMem(PVOID pVirAddr, DWORD memSize)
{
	WINMEM_MEM pm;
	DWORD dwBytes = 0;

	pm.pvAddr = pVirAddr;	//virtual address
	pm.dwSize = memSize;	//memory size

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_WINMEM_UNMAP, &pm,
			sizeof(WINMEM_MEM), nullptr, 0, &dwBytes, nullptr);
	}
}


//read 1 byte from port
BYTE ReadPortByte(WORD portAddr)
{
	WINMEM_PORT pp;
	DWORD pv = 0;	//returned port value
	DWORD dwBytes;

	pp.dwPort = portAddr;
	pp.dwSize = 1;	//1 byte

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_WINMEM_GETPORT, &pp,
			sizeof(WINMEM_PORT), &pv, sizeof(DWORD), &dwBytes, nullptr);
	}

	return (BYTE)pv;
}

//read 2 bytes from port
WORD ReadPortWord(WORD portAddr)
{
	WINMEM_PORT pp;
	DWORD pv = 0;	//returned port value
	DWORD dwBytes;

	pp.dwPort = portAddr;
	pp.dwSize = 2;	//2 bytes

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_WINMEM_GETPORT, &pp,
			sizeof(WINMEM_PORT), &pv, sizeof(DWORD), &dwBytes, nullptr);
	}

	return (WORD)pv;
}

//read 4 bytes from port
DWORD ReadPortLong(WORD portAddr)
{
	WINMEM_PORT pp;
	DWORD pv = 0;	//returned port value
	DWORD dwBytes;

	pp.dwPort = portAddr;
	pp.dwSize = 4;	//4 bytes

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_WINMEM_GETPORT, &pp,
			sizeof(WINMEM_PORT), &pv, sizeof(DWORD), &dwBytes, nullptr);
	}

	return pv;
}

//write 1 byte to port
VOID WritePortByte(WORD portAddr, BYTE portValue)
{
	WINMEM_PORT pp;
	DWORD dwBytes;

	pp.dwPort = portAddr;
	pp.dwValue = portValue;
	pp.dwSize = 1;	//1 byte

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_WINMEM_SETPORT, &pp,
			sizeof(WINMEM_PORT), nullptr, 0, &dwBytes, nullptr);
	}
}

//write 2 bytes to port
VOID WritePortWord(WORD portAddr, WORD portValue)
{
	WINMEM_PORT pp;
	DWORD dwBytes;

	pp.dwPort = portAddr;
	pp.dwValue = portValue;
	pp.dwSize = 2;	//2 bytes

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_WINMEM_SETPORT, &pp,
			sizeof(WINMEM_PORT), nullptr, 0, &dwBytes, nullptr);
	}
}

//write 4 bytes to port
VOID WritePortLong(WORD portAddr, DWORD portValue)
{
	WINMEM_PORT pp;
	DWORD dwBytes;

	pp.dwPort = portAddr;
	pp.dwValue = portValue;
	pp.dwSize = 4;	//4 bytes

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_WINMEM_SETPORT, &pp,
			sizeof(WINMEM_PORT), nullptr, 0, &dwBytes, nullptr);
	}
}


VOID GetDeviceObj(DWORD busNum, DWORD devNum, DWORD funcNum) {
	BOOL bRet = FALSE;
	DWORD dwBytes;
	WINMEM_PCI pp;
	pp.dwBusNum = busNum;
	pp.dwDevNum = devNum;
	pp.dwFuncNum = funcNum;

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		DeviceIoControl(hDriver, IOCTL_WINMEM_GETOBJ, &pp, sizeof(WINMEM_PCI), nullptr, 0, &dwBytes, nullptr);
	}

}



//read pci configuration
BOOL ReadPCI(DWORD busNum, DWORD devNum, DWORD funcNum,
	DWORD regOff, DWORD bytes, PVOID pValue)
{
	BOOL bRet = FALSE;
	DWORD dwBytes;
	WINMEM_PCI pp;

	pp.dwBusNum = busNum;
	pp.dwDevNum = devNum;
	pp.dwFuncNum = funcNum;
	pp.dwRegOff = regOff;
	pp.dwBytes = bytes;
	//	pp.pValue=NULL;

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_GETPCI, &pp,
			sizeof(WINMEM_PCI), pValue, bytes, &dwBytes, nullptr);
	}

	if (bRet && dwBytes == bytes)
		return TRUE;
	else
		return FALSE;
}

//write pci configuration
BOOL WritePCI(DWORD busNum, DWORD devNum, DWORD funcNum,
	DWORD regOff, DWORD bytes, PVOID pValue)
{
	BOOL bRet = FALSE;
	DWORD dwBytes;
	WINMEM_PCI pp;

	pp.dwBusNum = busNum;
	pp.dwDevNum = devNum;
	pp.dwFuncNum = funcNum;
	pp.dwRegOff = regOff;
	pp.dwBytes = bytes;

	if (hDriver != INVALID_HANDLE_VALUE)
	{
		//we use out buffer for storing the new values to write
		//it's strange but it works (METHOD_OUT_DIRECT) and ease the driver
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_SETPCI, &pp,
			sizeof(WINMEM_PCI), pValue, bytes, &dwBytes, nullptr);
	}

	if (bRet && dwBytes == bytes)
		return TRUE;
	else
		return FALSE;
}
