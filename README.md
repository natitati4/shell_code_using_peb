# shell_code_using_peb
A (basic) shellcode that pops a message box using the PEB (process environment block) to find the main module's ImageBase address, find LoadLibraryW and GetProcAddress,
to make it load user32.dll, and the find MessageBoxA and call it. All within the shellcodes, without any imports because it's all opcodes.
