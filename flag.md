## Description
flag - 7 pt [writeup]

> Papa brought me a packed present! let's open it.
>
> Download : http://pwnable.kr/bin/flag
>
> This is reversing task. all you need is binary

## Solution
This time we are only given a binary file `flag`, and we are told that this is a reversing task.
Let's take examine the binary.
```shell
$ file flag
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
$ checksec --file=flag
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   No Symbols        No    0               0               flag
```

Let's run the binary:
```shell
$ ./flag
I will malloc() and strcpy the flag there. take it.
```

After some time trying to debug the binary with gdb, I understood that the binary is probably stripped.
I decided to then take a look at the strings in the binary:
```shell
$ strings flag -n 10
...
&9223372036854775807L`
<http://w(
PROT_EXEC|PROT_WRITE failed.
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
/proc/self/exe
...
```
After going over the strings, I noticed that the binary is packed with a tool called UPX.
I decided to unpack the binary using UPX:
```shell
$ upx -d flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    883745 <-    335288   37.94%   linux/amd64   flag

Unpacked 1 file.
```
Now that we have the unpacked binary, we can try and debug it with gdb:
```shell
$ gdb flag
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000401164 <+0>:	push   rbp
   ....
   0x000000000040117b <+23>:	call   0x4099d0 <malloc>
   0x0000000000401180 <+28>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000401184 <+32>:	mov    rdx,QWORD PTR [rip+0x2c0ee5]        # 0x6c2070 <flag>
   0x000000000040118b <+39>:	mov    rax,QWORD PTR [rbp-0x8]
   ....
# We can clearly see that a variable called flag is stored at address 0x6c2070, let's take a look at it:
pwndbg> x/s *0x6c2070
0x496628:	"UPX...? sounds like a delivery service :)"
```
That's it, we got the flag :)

## Setup
```shell
$ wget http://pwnable.kr/bin/flag
$ chmod +x flag
```
