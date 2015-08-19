##Brief Descriptions - See IDC files for usage instructions.

### IDA-Scripts

The following are a list of IDC scripts I've created over the last couple of years.

Should you see room for improvement, please contact me.
This is my first time using GIT, so please be patient.


####DefineDwords.idc

Repeatedly defines a sequence of bytes as a DWORD as many times as the user tells the script.

####DumpMemoryToDisk.idc

Dumps out data that exists between the cursor location and the entered end address, an even number of bytes will be written to the "idaout,bin" file.

#### FindShellCode_V2.idc

Finds shellcode and stops execution once found, allowing for the shellcode to be stepped through and debugged.

####FindSysCalls_x32.idc / FindSysCalls_x64.idc

Scans for 32/64 bit syscall operands and renames the function that the syscall is located within and adds a comment to the syscall instruction line.

All found syscalls have a comment added to the IDA Output window and if a ptrace call exists, is noted at the end of the log output.

This script traces the disassembly should the syscall value be declared prior to the syscall.

Not all SYSCALLS are included and would be better if they were stored in an external file.


####NOPBytes.idc

NOPs out a sequence of bytes

####XOR.idc

XORs a sequence of bytes with the provided one byte key.
