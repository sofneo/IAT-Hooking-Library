#pragma once

class CExternalImports
{
public:
    struct ImportedFunction
    {
        char Name[256];
        uint64_t OFT_A;
        uint64_t FT_A;
        IMAGE_THUNK_DATA OriginalFirstThunk;
        IMAGE_THUNK_DATA FirstThunk;
    };

    struct Library
    {
        char Name[256];
        std::vector<ImportedFunction> ChildImports;
    };

    std::vector<Library> LocatedImports;
private:
    struct _TargetProc
    {
        HANDLE TargetHandle = INVALID_HANDLE_VALUE;
        int32_t ProcessID = NULL;
        uint64_t ImageBase = NULL;
    } TargetProc;

    template <class t>
    t ReadMem(uint64_t Address) {
        t ReadBuffer;
        ReadProcessMemory(this->TargetProc.TargetHandle, (LPVOID)Address, &ReadBuffer, sizeof(t), NULL);
        return ReadBuffer;
    }

    bool FindFunctionInCache(const char* FunctionName, ImportedFunction* ReturnFunction)
    {
        for (const auto& Lib : this->LocatedImports)
        {
            // Enumerate the functions
            for (const auto& Function : Lib.ChildImports)
            {
                if (!strcmp(Function.Name, FunctionName))
                {
                    *ReturnFunction = Function;
                    return true;
                }
            }
        }

        return false;
    }

    bool CreateHandle()
    {
        this->TargetProc.TargetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, this->TargetProc.ProcessID);

        return this->TargetProc.TargetHandle != INVALID_HANDLE_VALUE;
    }

public:
    bool NextImportDescriptor(uint64_t* Address, IMAGE_IMPORT_DESCRIPTOR* Descriptor)
    {
        // Read new *Descriptor
        *Descriptor = this->ReadMem<IMAGE_IMPORT_DESCRIPTOR>(*Address);

        if (Descriptor->Name == NULL)
            return false;

        *Address += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        return true;
    }

    bool NextThunkPair(uint64_t* OriginalFirstThunkAddress, uint64_t* FirstThunkAddress, IMAGE_THUNK_DATA* OriginalFirstThunk, IMAGE_THUNK_DATA* FirstThunk)
    {
        *OriginalFirstThunk = this->ReadMem<IMAGE_THUNK_DATA>(*OriginalFirstThunkAddress);
        *FirstThunk = this->ReadMem<IMAGE_THUNK_DATA>(*FirstThunkAddress);

        if (OriginalFirstThunk->u1.AddressOfData == NULL || OriginalFirstThunk->u1.Function == NULL)
            return false;

        *OriginalFirstThunkAddress += sizeof(IMAGE_THUNK_DATA);
        *FirstThunkAddress += sizeof(IMAGE_THUNK_DATA);
        return true;
    }

    bool PopulateImports()
    {
        if (!this->TargetProc.TargetHandle || this->TargetProc.TargetHandle == INVALID_HANDLE_VALUE)
        {
            // Attempt to create a handle
            if (!this->CreateHandle())
                return false;
        }

        if (this->ReadMem<SHORT>(this->TargetProc.ImageBase) != 0x5A4D)
            return false;

        IMAGE_DOS_HEADER DOSHeader = this->ReadMem<IMAGE_DOS_HEADER>(this->TargetProc.ImageBase);
        IMAGE_NT_HEADERS NTHeaders = this->ReadMem<IMAGE_NT_HEADERS>(this->TargetProc.ImageBase + DOSHeader.e_lfanew);

        if (NTHeaders.OptionalHeader.ImageBase != this->TargetProc.ImageBase)
            return false;

        IMAGE_DATA_DIRECTORY ImportDirectory = NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        uint64_t ImportDescriptorAddress = this->TargetProc.ImageBase + ImportDirectory.VirtualAddress;

        IMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
        while (NextImportDescriptor(&ImportDescriptorAddress, &ImportDescriptor))
        {
            Library ConstructedLibrary;
            if (!ReadProcessMemory(this->TargetProc.TargetHandle, (void*)(this->TargetProc.ImageBase + ImportDescriptor.Name), &ConstructedLibrary.Name, sizeof(ConstructedLibrary.Name), nullptr))
                break;

            uint64_t OFTAddress = this->TargetProc.ImageBase + ImportDescriptor.OriginalFirstThunk;
            uint64_t FTAddress = this->TargetProc.ImageBase + ImportDescriptor.FirstThunk;

            IMAGE_THUNK_DATA OFT, FT;
            while (NextThunkPair(&OFTAddress, &FTAddress, &OFT, &FT))
            {
                ImportedFunction Import = {
                    "",
                    OFTAddress - sizeof(IMAGE_THUNK_DATA),
                    FTAddress - sizeof(IMAGE_THUNK_DATA),
                    OFT,
                    FT
                };

                if (ReadProcessMemory(this->TargetProc.TargetHandle, (void*)(this->TargetProc.ImageBase + OFT.u1.AddressOfData + sizeof(WORD)), &Import.Name, sizeof(Import.Name), nullptr))
                    ConstructedLibrary.ChildImports.push_back(Import);
            }

            this->LocatedImports.push_back(ConstructedLibrary);
        }

        return true;
    }

    uint64_t LocateImport(const char* ImportName)
    {
        ImportedFunction Import;
        if (this->FindFunctionInCache(ImportName, &Import))
            return Import.FirstThunk.u1.Function;

        return NULL;
    }

    bool HookImport(const char* ImportName, uint64_t Detour)
    {
        ImportedFunction Import;
        if (this->FindFunctionInCache(ImportName, &Import))
        {
            IMAGE_THUNK_DATA NewFirstThunk = Import.FirstThunk;
            NewFirstThunk.u1.Function = Detour;

            DWORD OldProtection;
            if (!VirtualProtectEx(this->TargetProc.TargetHandle, (void*)Import.FT_A, sizeof(NewFirstThunk), PAGE_READWRITE, &OldProtection))
                return false;

            if (!WriteProcessMemory(this->TargetProc.TargetHandle, (void*)Import.FT_A, &NewFirstThunk, sizeof(NewFirstThunk), nullptr))
                return false;

            VirtualProtectEx(this->TargetProc.TargetHandle, (void*)Import.FT_A, sizeof(NewFirstThunk), OldProtection, nullptr);

            return true;
        }

        return false;
    }

    uint64_t DeployTrampline(std::vector<char> Shellcode)
    {
        uint64_t LocalAllocation = reinterpret_cast<uint64_t>(VirtualAllocEx(this->TargetProc.TargetHandle, nullptr, Shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        if (!LocalAllocation)
            return NULL;

        if (!WriteProcessMemory(this->TargetProc.TargetHandle, (void*)LocalAllocation, Shellcode.data(), Shellcode.size(), nullptr))
            return NULL;

        return LocalAllocation;
    }

    CExternalImports(int32_t ProcID, uint64_t TargetImageBase)
    {
        this->TargetProc.ProcessID = ProcID;
        this->TargetProc.ImageBase = TargetImageBase;
    }
};