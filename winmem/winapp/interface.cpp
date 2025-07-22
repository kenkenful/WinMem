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


BOOL StartWinMemDriver() {
	CHAR szDriverPath[MAX_PATH] = { 0 };
	BOOL bResult;
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

	return TRUE;
}

//stop and remove driver
VOID StopWinMemDriver()
{

	if (RemoveDriver("WINMEM")) {
		std::cerr << "uninstall winmem driver" << std::endl;
	}
}


BOOL OpenWinMemHandle() {

	CHAR szDeviceSymLink[MAX_PATH] = { 0 };
	size_t iReturnValue;
	errno_t ret = wcstombs_s(&iReturnValue,
		szDeviceSymLink,
		sizeof(szDeviceSymLink),
		DeviceSymLink,
		_TRUNCATE
	);

	std::cout << szDeviceSymLink << std::endl;

	if (ret != 0) {
		std::cerr << "wcstombs_s error!! ret=%d\n" << ret << std::endl;
		return FALSE;
	}
	std::cout << szDeviceSymLink << std::endl;
	hDriver = CreateFile(szDeviceSymLink,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	if (hDriver == INVALID_HANDLE_VALUE) {
		std::cerr << GetLastError() << std::endl;
		return FALSE;
	}

	return TRUE;
}


VOID CloseWinMemHandle() {
	if (hDriver != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hDriver);
		hDriver = INVALID_HANDLE_VALUE;
	}


}

//map physical memory to user space
PVOID MapWinMem(DWORD phyAddr, DWORD mapSize)
{
	PVOID pVirAddr = nullptr;	//mapped virtual addr
	WINMEM_MEM pm;
	DWORD dwBytes = 0;
	BOOL bRet = FALSE;

	pm.pvAddr = (PVOID)phyAddr;	//physical address
	pm.dwSize = mapSize;	//memory size

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
VOID UnmapWinMem(PVOID pVirAddr, DWORD mapSize)
{
	WINMEM_MEM pm;
	DWORD dwBytes = 0;

	pm.pvAddr = pVirAddr;	//virtual address
	pm.dwSize = mapSize;	//memory size

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


//read pci configuration
BOOL ReadPCI2(DWORD busNum, DWORD devNum, DWORD funcNum,
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
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_GETPCI_2, &pp,
			sizeof(WINMEM_PCI), pValue, bytes, &dwBytes, nullptr);
	}

	if (bRet && dwBytes == bytes)
		return TRUE;
	else
		return FALSE;
}

//write pci configuration
BOOL WritePCI2(DWORD busNum, DWORD devNum, DWORD funcNum,
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
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_SETPCI_2, &pp,
			sizeof(WINMEM_PCI), pValue, bytes, &dwBytes, nullptr);
	}

	if (bRet && dwBytes == bytes)
		return TRUE;
	else
		return FALSE;
}





//read pci configuration
BOOL ReadPCI3(DWORD busNum, DWORD devNum, DWORD funcNum,
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
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_GETPCI_3, &pp,
			sizeof(WINMEM_PCI), pValue, bytes, &dwBytes, nullptr);
	}

	if (bRet && dwBytes == bytes)
		return TRUE;
	else
		return FALSE;
}

//write pci configuration
BOOL WritePCI3(DWORD busNum, DWORD devNum, DWORD funcNum,
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
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_SETPCI_3, &pp,
			sizeof(WINMEM_PCI), pValue, bytes, &dwBytes, nullptr);
	}

	if (bRet && dwBytes == bytes)
		return TRUE;
	else
		return FALSE;
}





BOOL ReadMem(DWORD phyAddr, DWORD mapSize, DWORD regOff, DWORD bytes, PVOID pValue)
{
	BOOL bRet = FALSE;
	DWORD dwBytes;
	WINMEM_MEM pm;

	pm.pvAddr = (PVOID)phyAddr;
	pm.dwSize = mapSize;
	pm.dwRegOff = regOff;
	pm.dwBytes = bytes;


	if (hDriver != INVALID_HANDLE_VALUE)
	{
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_READ_MEM, &pm,
			sizeof(WINMEM_MEM), pValue, bytes, &dwBytes, nullptr);
	}

	if (bRet && dwBytes == bytes)
		return TRUE;
	else
		return FALSE;
}

BOOL WriteMem(DWORD phyAddr, DWORD mapSize, DWORD regOff, DWORD bytes, PVOID pValue)
{
	BOOL bRet = FALSE;
	DWORD dwBytes;
	WINMEM_MEM pm;

	pm.pvAddr = (PVOID)phyAddr;
	pm.dwSize = mapSize;
	pm.dwRegOff = regOff;
	pm.dwBytes = bytes;


	if (hDriver != INVALID_HANDLE_VALUE)
	{
		bRet = DeviceIoControl(hDriver, IOCTL_WINMEM_WRITE_MEM, &pm,
			sizeof(WINMEM_MEM), pValue, bytes, &dwBytes, nullptr);
	}

	if (bRet && dwBytes == bytes)
		return TRUE;
	else
		return FALSE;
}

