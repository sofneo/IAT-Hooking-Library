#include <iostream>
#include <vector>
#include <Windows.h>
#include "iat_parser.hpp"
#include "trampoline_assembler.hpp"

// Here we define the trampoline we will deploy into the target process.
// This trampoline is a copy of the import we will be hooking (MoveWindow).
// We must take the same arguments so that when the function is invoked
// by MoveWindow, we can call the original MoveWindow and thus return
// the original call
BOOL __stdcall Trampoline(HWND a1, int a2, int a3, int a4, int a5, BOOL a6)
{
    uint64_t MessageBoxW_A = 0x7FFFFFFFFFFFFFFF;
    uint64_t MoveWindow_A = 0x7FFFFFFFFFFFFFF0;

    typedef int __stdcall MessageBoxW_Proto(HWND, LPCWSTR, LPCWSTR, UINT);
    MessageBoxW_Proto* MessageBoxW_F = (MessageBoxW_Proto*)MessageBoxW_A;
    MessageBoxW_F(NULL, NULL, NULL, MB_OK);

    typedef BOOL __stdcall MoveWindow_Proto(HWND, int, int, int, int, BOOL);
    MoveWindow_Proto* MoveWindow_F = (MoveWindow_Proto*)MoveWindow_A;
    return MoveWindow_F(a1, a2, a3, a4, a5, a6);
}

int main()
{
    // Both the TargetProcessID & TargetModuleBase should be found at runtime!
    const int32_t TargetProcessID = 1384;
    const uint64_t TargetModuleBase = 0x7ff6eb910000;

    CExternalImports* ExternalImportManager = new CExternalImports(TargetProcessID, TargetModuleBase);

    if (!ExternalImportManager->PopulateImports())
        return 0;

    const uint64_t Notepad_MessageBoxW = ExternalImportManager->LocateImport("MessageBoxW");
    const uint64_t Notepad_MoveWindow = ExternalImportManager->LocateImport("MoveWindow");

    if (!Notepad_MessageBoxW || !Notepad_MoveWindow)
        return 0;

    // Assemble the trampoline from function Trampoline above into this vector
    // so that we can copy it into the target process.
    std::vector<char> AssembledTrampoline;
    if (!TAssembler::AssembleTrampoline(
        &Trampoline,
        { {0x7FFFFFFFFFFFFFFF, Notepad_MessageBoxW}, {0x7FFFFFFFFFFFFFF0, Notepad_MoveWindow } },
        &AssembledTrampoline))
    {
        return 0;
    }

    uint64_t External_Trampoline = ExternalImportManager->DeployTrampline(AssembledTrampoline);
    if (!External_Trampoline)
        return 0;

    if (!ExternalImportManager->HookImport("MoveWindow", External_Trampoline))
        return 0;
    
    printf("Hook Information:\n");
    printf("\tnotepad.exe!MessageBoxW=%llx\n", Notepad_MessageBoxW);
    printf("\tnotepad.exe!Trampoline=%llx\n", Notepad_MoveWindow);
    printf("\tAssembledTrampoline=%llx\n", (uint64_t)AssembledTrampoline.data());
    printf("\tDeployedTrampoline=%llx\n", External_Trampoline);
    
    getchar();
    return 0;
}