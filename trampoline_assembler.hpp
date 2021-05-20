#pragma once

namespace TAssembler
{
    size_t FetchSizeOfFunction(void* Function, uint64_t MaxIter = 0x200)
    {
        int32_t CurrentIter = 1;
        while (CurrentIter != MaxIter)
        {
            uint64_t SearchAddress = (uint64_t)Function + CurrentIter;
            if (*(uint8_t*)(SearchAddress) == 0xC3) // 0xC3 = Ret (marking the end of a function)
                return CurrentIter;

            CurrentIter++;
        }

        return 0;
    }

    bool ChangeAddressInFunctionCopy(void* Function, uint64_t AddressToChange, uint64_t NewAddress, size_t FunctionSize)
    {
        // If the function size is less than 8 bytes then 
        // we will hit a nasty error in the while loop
        if (!FunctionSize || FunctionSize < 0x10)
            return false;

        uint64_t CurrentAddress = (uint64_t)Function;
        uint64_t FinalAddress = (uint64_t)Function + FunctionSize - sizeof(uint64_t);
        while (CurrentAddress != FinalAddress)
        {
            if (*(uint64_t*)CurrentAddress == AddressToChange)
            {
                memcpy((void*)CurrentAddress, (void*)&NewAddress, sizeof(uint64_t));
                return true;
            }

            CurrentAddress += 0x1;
        }

        return false;
    }

    bool AssembleTrampoline(void* Function, std::vector<std::pair<uint64_t, uint64_t>> AddressReplacements, std::vector<char>* FunctionCopy)
    {
        size_t FunctionSize = FetchSizeOfFunction(Function);
        if (!FunctionSize || FunctionSize < 0x10)
            return false;

        // Could easily be changed for something like assign or reserve!
        for (size_t i = 0; i < FunctionSize + 1; i++)
            FunctionCopy->push_back(0x0);

        memcpy(FunctionCopy->data(), Function, FunctionSize + 1);

        for (const auto& AddressReplacement : AddressReplacements)
        {
            if (!ChangeAddressInFunctionCopy(FunctionCopy->data(), AddressReplacement.first, AddressReplacement.second, FunctionSize))
                return false;
        }

        return true;
    }
}