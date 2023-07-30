// winapp.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <windows.h>
#include <memory>
#include <iostream>
#include "interface.h"
#include "acpi.h"

int Error(DWORD code = GetLastError()) {
    printf("Error: %d\n", ::GetLastError());
    return 1;
}

int wmain(int argc, const wchar_t* argv[]) {

    DWORD busNum = 0x00;
    DWORD devNum = 0x1d; 
    DWORD funcNum = 0x00;

    if (!LoadWinMemDriver()) {
        getchar();
        return 1;
    }


#if 0

#if 1
    DWORD MCFGDataSize;

    MCFGDataSize = GetSystemFirmwareTable(
        'ACPI',
        *(DWORD*)"MCFG",
        &MCFG,
        sizeof(EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE));

    UINT64 base_addr = MCFG.Segment.BaseAddress;
    printf("BaseAddress = 0x%llx  \n", base_addr);
#else 
    UCHAR mcfg[1024] = { 0 };
    ULONG mcfg_size;
    mcfg_size = GetSystemFirmwareTable('ACPI', 'GFCM', mcfg, sizeof(mcfg));

    UINT64  base_addr = *(UINT64*)((UCHAR*)mcfg + 0x2c);

    printf("BaseAddress = 0x%llx bytes\n", base_addr);
#endif

    ULONG map_address = base_addr + 4096 * (funcNum + 8 * (devNum + 32 * busNum));
    CHAR* va = (CHAR*)MapWinMem(map_address, 4096);

    ULONG vendor_id = *(ULONG*)va; 
    printf("%x\n", vendor_id);

    UnmapWinMem(va, 4096);;

#else 
    BYTE  bridge_control_defo, bridge_control ;
    GetDeviceObj(busNum, devNum, funcNum);
    if (ReadPCI(busNum, devNum, funcNum, 0x3e, sizeof(BYTE), &bridge_control_defo)) {
        printf("%x\n", bridge_control_defo);
    }
    else {
        std::cout << "read error" << std::endl;
    }
    
    bridge_control = bridge_control_defo | 0x40;

    if (WritePCI(busNum, devNum, funcNum, 0x3e, sizeof(BYTE), &bridge_control)) {
        printf("%x\n", bridge_control);
    }
    else {
        std::cout << "write error" << std::endl;
    }

    Sleep(2000);

    if (WritePCI(busNum, devNum, funcNum, 0x3e, sizeof(BYTE), &bridge_control_defo)) {
        printf("%x\n", bridge_control_defo);
    }
    else {
        std::cout << "write error" << std::endl;
    }

#endif

    UnloadWinMemDriver();


    getchar();
}

// プログラムの実行: Ctrl + F5 または [デバッグ] > [デバッグなしで開始] メニュー
// プログラムのデバッグ: F5 または [デバッグ] > [デバッグの開始] メニュー

// 作業を開始するためのヒント: 
//    1. ソリューション エクスプローラー ウィンドウを使用してファイルを追加/管理します 
//   2. チーム エクスプローラー ウィンドウを使用してソース管理に接続します
//   3. 出力ウィンドウを使用して、ビルド出力とその他のメッセージを表示します
//   4. エラー一覧ウィンドウを使用してエラーを表示します
//   5. [プロジェクト] > [新しい項目の追加] と移動して新しいコード ファイルを作成するか、[プロジェクト] > [既存の項目の追加] と移動して既存のコード ファイルをプロジェクトに追加します
//   6. 後ほどこのプロジェクトを再び開く場合、[ファイル] > [開く] > [プロジェクト] と移動して .sln ファイルを選択します
