
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
	 Space Control
	/
	VME_REG_PMRCAP = 0x0e00,	/* Persistent Memory Capabilities */
	VME_REG_PMRCTL = 0x0e04,	/* Persistent Memory Region Control */
	VME_REG_PMRSTS = 0x0e08,	/* Persistent Memory Region Status */
	VME_REG_PMREBS = 0x0e0c,	/* Persistent Memory Region Elasticity
	* Buffer Size
	*/
	NVME_REG_PMRSWTP = 0x0e10,	/* Persistent Memory Region Sustained
	* Write Throughput
	*/
	NVME_REG_DBS = 0x1000,	/* SQ 0 Tail Doorbell */
};

union capability_header {
	uint32_t data;

	struct {
		uint32_t cap_id : 8;
		uint32_t next_ptr : 8;
		uint32_t cap : 16;
	};
};

struct msi_capability {
	union {
		uint32_t data;

		struct {
			uint32_t cap_id : 8;
			uint32_t next_ptr : 8;
			uint32_t msi_enable : 1;
			uint32_t multi_msg_capable : 3;
			uint32_t multi_msg_enable : 3;
			uint32_t addr_64_capable : 1;
			uint32_t per_vector_mask_capable : 1;
			uint32_t : 7;
		}bits;
	}header;

	uint32_t msg_addr;
	uint32_t msg_upper_addr;
	uint32_t msg_data;
	uint32_t mask_bits;
	uint32_t pending_bits;
};



struct msi_x_capability {
	union {
		uint32_t data;

		struct {
			uint32_t cap_id : 8;
			uint32_t next_ptr : 8;
			uint32_t size_of_table : 11;
			uint32_t reserved : 3;
			uint32_t function_mask : 1;
			uint32_t enable : 1;
		};
	} header;

	union address_field {
		uint32_t data;

		struct {
			uint32_t bar : 3;
			uint32_t offset : 29;
		};
	} table, pba;
};


struct msix_table_entry {
	uint32_t msg_addr;
	uint32_t msg_upper_addr;
	uint32_t msg_data;
	uint32_t vector_control;
};


int Error(DWORD code = GetLastError()) {
    printf("Error: %d\n", ::GetLastError());
    return 1;
}

int wmain(int argc, const wchar_t* argv[]) {

	DWORD busNum = 0x06;
	DWORD devNum = 0x00;
	DWORD funcNum = 0x00;


	if (!LoadWinMemDriver()) {
		getchar();
		return 1;
	}

	DWORD MCFGDataSize;

	MCFGDataSize = GetSystemFirmwareTable(
		'ACPI',
		*(DWORD*)"MCFG",
		&MCFG,
		sizeof(EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE)
	);

	UINT64 base_addr = MCFG.Segment.BaseAddress;
	printf("BaseAddress = 0x%llx  \n", base_addr);


	DWORD map_address = base_addr + 4096 * (funcNum + 8 * (devNum + 32 * busNum));

	UINT32 val;
	BOOL ret =  ReadMem(map_address, 256, 0, 4, &val);

	if(ret == TRUE)
	printf("%x\n", val);



#if 0
	BOOL ret;
	//ret = StartWinMemDriver();
	//if (ret) std::cout << "sucess start driver" << std::endl;
	//else std::cout << "failure start driver" << std::endl;

	//ret =  OpenWinMemHandle();
	//if (ret) std::cout << "sucess open handle" << std::endl;
	//else std::cout << "failure open handle" << std::endl;

	//ret = OpenWinMemHandle();
	//if (ret) std::cout << "sucess open handle" << std::endl;
	//else std::cout << "failure open handle" << std::endl;

	//Sleep(10000);




	//StopWinMemDriver();


	DWORD MCFGDataSize;

	MCFGDataSize = GetSystemFirmwareTable(
		'ACPI',
		*(DWORD*)"MCFG",
		&MCFG,
		sizeof(EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE)
	);

	UINT64 base_addr = MCFG.Segment.BaseAddress;
	printf("BaseAddress = 0x%llx  \n", base_addr);


	//for (int i = 0; i < 30000; ++i) {
	//
	DWORD map_address = base_addr + 4096 * (funcNum + 8 * (devNum + 32 * busNum));
	UCHAR* va = (UCHAR*)MapWinMem(map_address, 4096);

	DWORD bar0 = *(DWORD*)(va + 0x10) & 0xfffffff0;
	//UCHAR* vector_table = (UCHAR*)MapWinMem(bar0 + 0x3000, 256);
	//UCHAR* pba = (UCHAR*)MapWinMem(bar0 + 0x2000, 256);

	UINT8 next = va[0x34];


	UINT8 cap;
	while (1) {
		cap = va[next];
		if (cap == 0x5) {
			break;
		}
		else {
			next = va[next + 1];
			if (next == 0x0) break;
		}
	}

	struct  msi_capability *msi = (struct msi_capability*)(va+next);

	printf("cap id %x\n", msi->header.bits.cap_id);
	printf("next ptr %x\n", msi->header.bits.next_ptr);
	printf("msi enable %x\n", msi->header.bits.msi_enable);


	printf("msg addr %x\n", msi->msg_addr);
	printf("msg data %x\n", msi->msg_data);

	while (1) {
		cap = va[next];
		if (cap == 0x11) {
			break;
		}
		else {
			next = va[next + 1];
			if (next == 0x0) break;
		}
	}

#if 1
	//struct msi_x_capability  msix = {0};
	printf("--------------------\n");
	struct msi_x_capability* msix = (struct msi_x_capability*)(va + next);

	printf("mask %x\n", msix->header.function_mask);
	printf("table size %x\n", msix->header.size_of_table);
	printf("enable %x\n", msix->header.enable);

	printf("pba bar %x\n", msix->pba.bar);
	printf("pba offset %x\n", msix->pba.offset << 3);

	printf("table bar %x\n", msix->table.bar);
	printf("table offset %x\n", msix->table.offset << 3);

	struct msix_table_entry* entry = (struct msix_table_entry*)MapWinMem(bar0 + (msix->table.offset << 3), msix->header.size_of_table);


	for (int i = 0; i < 50; ++i) {
		printf("--------------------\n");
		printf("msg addr: %x\n", (entry + i)->msg_addr);
		printf("msg data: %x\n", (entry + i)->msg_data);
		printf("vector control: %x\n", (entry + i)->vector_control);
	}

#endif
	//UCHAR* apic = (UCHAR*)MapWinMem(0xfee00020, 4);
	//UnmapWinMem(apic , 4);
	//UnmapWinMem(pba, 256);
	UnmapWinMem(entry, msix->header.size_of_table);
	UnmapWinMem(va, 4096);

#endif
	UnloadWinMemDriver();

	system("pause");


}

