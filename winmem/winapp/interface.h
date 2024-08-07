#pragma once

#include <windows.h>

BOOL LoadWinMemDriver();
VOID UnloadWinMemDriver();


BOOL StartWinMemDriver();
VOID StopWinMemDriver();

BOOL OpenWinMemHandle();
VOID CloseWinMemHandle();

// Memomory mapped IO
PVOID MapWinMem(DWORD phyAddr, DWORD memSize);
VOID UnmapWinMem(PVOID pVirAddr, DWORD memSize);

// 

// Port mapped IO
BYTE ReadPortByte(WORD portAddr);
WORD ReadPortWord(WORD portAddr);
DWORD ReadPortLong(WORD portAddr);
VOID WritePortByte(WORD portAddr, BYTE portValue);
VOID WritePortWord(WORD portAddr, WORD portValue);
VOID WritePortLong(WORD portAddr, DWORD portValue);

// via PCI bus driver
VOID GetDeviceObj(DWORD busNum, DWORD devNum, DWORD funcNum);

BOOL ReadPCI(DWORD busNum, DWORD devNum, DWORD funcNum,
	DWORD regOff, DWORD bytes, PVOID pValue);
BOOL WritePCI(DWORD busNum, DWORD devNum, DWORD funcNum,
	DWORD regOff, DWORD bytes, PVOID pValue);