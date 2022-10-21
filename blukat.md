## Description
blukat - 3 pt [writeup]

> Sometimes, pwnable is strange...
> hint: if this challenge is hard, you are a skilled player.
>
> ssh blukat@pwnable.kr -p2222 (pw: guest)

## Solution
Ok, so this chllenge is pretty funny.

If we look at the source code, we can see that we need to guess some sort of password, in order to get the flag.\
The correct password is loaded from the file `password`, and then compared to the input we give to the program.\
Oh, so let's just read the file `password` and pass it to the program as the password:
```shell
blukat@pwnable:~$ cat password
cat: password: Permission denied
```
Oh no, we don't have permission to read the file `password` 😭😭

But guess what? We in fact do have permission to read the file `password`!

```shell
blukat@pwnable:~$ whoami
blukat
blukat@pwnable:~$ groups blukat
blukat : blukat blukat_pwn
blukat@pwnable:~$ ls -l
total 20
-r-xr-sr-x 1 root blukat_pwn 9144 Aug  8  2018 blukat
-rw-r--r-- 1 root root        645 Aug  8  2018 blukat.c
-rw-r----- 1 root blukat_pwn   33 Jan  6  2017 password
```

Why is that so? The file `password` is owned by the user `root`, but it's group is `blukat_pwn`.\
The user `blukat` is a member of the group `blukat_pwn`, so it has read permission to the file `password`.

So the contents of the file `password` is literally: `cat: password: Permission denied`.\
Lol.

So to get the flag:
```shell
$ ssh blukat@pwnable.kr -p2222
blukat@pwnable:~$ cat password | ./blukat 
guess the password!
congrats! here is your flag: [ ... FLAG ... ]
```

## Setup
```shell
mkdir blukat && scp -P2222 blukat@pwnable.kr:* ./blukat # Download the files from the server
```
