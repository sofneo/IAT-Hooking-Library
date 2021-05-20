# IAT-Hooking-Library

Hooking imports through the enumeration of the Import Address Table has been a common method of obtaining code execution (without creating remote threads) and a general hooking technique. On the contrary, to my knowlege there have not been any Import Address Table hooking libraries which deploy hooks from one process to another, rather they usually just hook imports within the same context. This method requires a little more skill as you must enumerate the Import Address Table of the other process by copying data from the target process into your own context.

# Proof Of Concept
The worked example of this project (in main.cpp) deploys a trampoline inside of notepad.exe, swapping an import called MoveWindow for a custom trampoline. The trampoline then calls notepad.exe!MessageBoxW with NULL for all of the arguments and then returns the original call of notepad.exe!MoveWindow. 

Here you can see the MessageBoxW being called with Error as lpText title because NULL is passed:
![poc](https://user-images.githubusercontent.com/64642265/119012147-ac77ed00-b98d-11eb-8853-d188bde012d7.png)

# The Possibilities Of IAT Hooking
IAT Hooking allows you to obtain code execution. It may be easy to deploy your data into another process or context however it is often not so easy to start the initial execution of your code. In often times where CreateRemoteThread() cannot be used to start a remote thread, code execution must be obtained by other means. 

One of the uses I'm sure someone will put this project to will be a Dynamic Link Library Manual Mapper. The same concept could be applied to one's DllMain, in the sense that you would hook an import which is often called by the game or program you are trying to deploy your module in to (such as PeekMessageW or PeekMessageA) and swap the pointer of the import for your trampoline which would call your DllMain (or you could swap the pointer of the import directly for DllMain assuming DllMain accepted the same arguments as the import. 

IAT Hooking allows for reverse engineers to deploy hooks on imports and change data at runtime. One may hook an import and change the arguments at runtime, for example hooking MessageBoxA and changing lpText to your own custom string. 

# Trampoline Assembler
This hooking library is extremely efficient and also includes a trampoline assembler which allows you to assemble trampolines at runtime and change addresses within said function without having to convert the function into shellcode to change the addresses. 
Example of this assembler's usage:
A typical inline hook will include an instruction set similar to:
```
mov rax, 0xDEADBEEF;
jmp rax
```
The programmer would then convert this instruction set into shellcode, a byte array works usually. This translates into: 
```
char Shellcode[] = {0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};                
```
Then the programmer would copy their address that they want the inline hook to call by the following:
```
memcpy(Shellcode + 2, WantedAddress, 8);
```

This assembler handles that all for you; instead of copying addresses in manually, you can simply pass in the value of the fake address (so 0xDEADBEEF in this case) and the wanted address to change to. Please see main.cpp for a literal example.

