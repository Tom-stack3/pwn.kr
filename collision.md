## Description
collision - 3 pt [writeup]

> Daddy told me about cool MD5 hash collision today.
> I wanna do something like that too!
>
> ssh col@pwnable.kr -p2222 (pw:guest)

## Solution
We are given a binary file `col`, and it's source code `col.c`. Let's take a look at the source code:
### col.c
```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}
```

We can see that the program is checking the hashcode of a password, which is passed as the first argument to the program.\
The hashcode is `0x21DD09EC`, and the password should be 20 bytes long.\
The program then calls `check_password` with the password as the argument.\
`check_password` adds the first 5 integers in the password together and returns the result.
So we need to find a password that will make `check_password` return `0x21DD09EC`.

If the first four integers will be 0x01010101, the fifth integer should be 0x21DD09EC - 4 * 0x01010101 = 0X1DD905E8.\

That's basically it, here's the exploit code:
```python
#!/usr/bin/env python3

from pwn import *

context.log_level = 'debug'
context.arch = 'i386'
# context.binary = './col'

shell=ssh('col','pwnable.kr',password='guest',port=2222)
p = shell.process(['col', '\x01\x01\x01\x01'*4+'\xe8\x05\xd9\x1d'])

p.interactive()
```

## Setup
```shell
mkdir collision && scp -P2222 col@pwnable.kr:* ./collision # Download the files from the server
```
