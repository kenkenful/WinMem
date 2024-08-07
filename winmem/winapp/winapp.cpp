
#include <windows.h>
#include <memory>
#include <iostream>
#include "interface.h"
#include "acpi.h"


enum {
	NVME_REG_CAP = 0x0000,	/* Controller Capabilities */
	NVME_REG_VS = 0x0008,	/* Version */
	NVME_REG_INTMS = 0x000c,	/* Interrupt Mask Set */
	NVME_REG_INTMC = 0x0010,	/* Interrupt Mask Clear */
	NVME_REG_CC = 0x0014,	/* Controller Configuration */
	NVME_REG_CSTS = 0x001c,	/* Controller Status */
	NVME_REG_NSSR = 0x0020,	/* NVM Subsystem Reset */
	NVME_REG_AQA = 0x0024,	/* Admin Queue Attributes */
	NVME_REG_ASQ = 0x0028,	/* Admin SQ Base Address */
	NVME_REG_ACQ = 0x0030,	/* Admin CQ Base Address */
	NVME_REG_CMBLOC = 0x0038,	/* Controller Memory Buffer Location */
	NVME_REG_CMBSZ = 0x003c,	/* Controller Memory Buffer Size */
	NVME_REG_BPINFO = 0x0040,	/* Boot Partition Information */
	NVME_REG_BPRSEL = 0x0044,	/* Boot Partition Read Select */
	NVME_REG_BPMBL = 0x0048,	/* Boot Partition Memory Buffer
					 * Location
					 */
					 NVME_REG_CMBMSC = 0x0050,	/* Controller Memory Buffer Memory
									  * Space Control
									  */
									  NVME_REG_PMRCAP = 0x0e00,	/* Persistent Memory Capabilities */
									  NVME_REG_PMRCTL = 0x0e04,	/* Persistent Memory Region Control */
									  NVME_REG_PMRSTS = 0x0e08,	/* Persistent Memory Region Status */
									  NVME_REG_PMREBS = 0x0e0c,	/* Persistent Memory Region Elasticity
													   * Buffer Size
													   */
													   NVME_REG_PMRSWTP = 0x0e10,	/* Persistent Memory Region Sustained
																		* Write Throughput
																		*/
																		NVME_REG_DBS = 0x1000,	/* SQ 0 Tail Doorbell */
};



int Error(DWORD code = GetLastError()) {
    printf("Error: %d\n", ::GetLastError());
    return 1;
}

int wmain(int argc, const wchar_t* argv[]) {

   DWORD busNum = 0x41;
   DWORD devNum = 0x00; 
   DWORD funcNum = 0x00;


    //if (!LoadWinMemDriver()) {
     //   getchar();
     //   return 1;
    // }

	BOOL ret;
	//ret = StartWinMemDriver();
	//if (ret) std::cout << "sucess start driver" << std::endl;
	//else std::cout << "failure start driver" << std::endl;

	ret =  OpenWinMemHandle();
	if (ret) std::cout << "sucess open handle" << std::endl;
	else std::cout << "failure open handle" << std::endl;

	//ret = OpenWinMemHandle();
	//if (ret) std::cout << "sucess open handle" << std::endl;
	//else std::cout << "failure open handle" << std::endl;

	//Sleep(10000);




	//StopWinMemDriver();

#if 1
    DWORD MCFGDataSize;

    MCFGDataSize = GetSystemFirmwareTable(
        'ACPI',
        *(DWORD*)"MCFG",
        &MCFG,
        sizeof(EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE)
    );

    UINT64 base_addr = MCFG.Segment.BaseAddress;
    printf("BaseAddress = 0x%llx  \n", base_addr);


	for (int i = 0; i < 30000; ++i) {

		DWORD map_address = base_addr + 4096 * (funcNum + 8 * (devNum + 32 * busNum));
		UCHAR* va = (UCHAR*)MapWinMem(map_address, 4096);

		//system("pause");

		DWORD bar0 = *(DWORD*)(va + 0x10) & 0xfffffff0;
		printf("BAR0: %x\n", bar0);

		UCHAR* ctrl_reg = (UCHAR*)MapWinMem(bar0, 4096);



		USHORT csts_reg = *(USHORT*)(ctrl_reg + NVME_REG_CSTS);
		printf("csts reg: %x\n", csts_reg);

		UnmapWinMem(ctrl_reg, 4096);

		UnmapWinMem(va, 4096);

		//Sleep(10);


	}
    


	//printf("clear nssro\n");
	//*(USHORT*)(ctrl_reg + NVME_REG_CSTS) = csts_reg & 0xef;
	
	

	//csts_reg = *(USHORT*)(ctrl_reg + NVME_REG_CSTS);
	//printf("csts reg: %x\n", csts_reg);


	// NSSR
	//*(ULONG*)(ctrl_reg + NVME_REG_NSSR) = 0x4E564D65;


	//sleep 5sec
	//Sleep(5000);


	//csts_reg = *(USHORT*)(ctrl_reg + NVME_REG_CSTS);
	//printf("csts reg: %x\n", csts_reg);

	//sleep 5sec
	//Sleep(5000);


	//csts_reg = *(USHORT*)(ctrl_reg + NVME_REG_CSTS);
	//printf("csts reg: %x\n", csts_reg);


#endif

//	GetDeviceObj(busNum, devNum, funcNum);
 //   UnloadWinMemDriver();

	CloseWinMemHandle();
	if (ret) std::cout << "sucess close handle" << std::endl;
	else std::cout << "failure close handle" << std::endl;

	system("pause");
}

