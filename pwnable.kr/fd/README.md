# fd

## Description

```Text
Mommy! what is a file descriptor in Linux?

* try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link:
https://youtu.be/971eZhMHQQw

ssh fd@pwnable.kr -p2222 (pw:guest)
```

## Analysis

```Shell
$ ssh fd@pwnable.kr -p2222
fd@pwnable.kr's password:
...

Last login: Sun Jun  6 02:43:55 2021 from 111.252.186.121
fd@pwnable:~$ ls -l
total 16
-r-sr-x--- 1 fd_pwn fd   7322 Jun 11  2014 fd
-rw-r--r-- 1 root   root  418 Jun 11  2014 fd.c
-r--r----- 1 fd_pwn root   50 Jun 11  2014 flag
fd@pwnable:~$
```

Without the permission to the flag, let’s take a look at the source:

```C
// fd.c

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

}
```

We know that `fd` is an abbreviation for file descriptor, and there are 3 file descriptors: `stdin`, `stdout`, `stderr`.

Give the program `4660` to get `fd = 4660 - 4660 = 0`,  which represents `stdin`.

Instead of printing `learn about Linux file IO`, it’s reading our input –> `len = read(fd, buf, 32);`.

Make `buf = “LETMEWIN”` to execute the first if condition and we can get the flag: `mommy! I think I know what a file descriptor is!!`. 

## Solution

Write-up: [exploit.py](exploit.py).

```Shell
$ python3 pwnable.kr/fd/exploit.py
[+] Connecting to pwnable.kr on port 2222: Done
[*] fd@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Starting remote process './fd' on pwnable.kr: pid 333931
[+] Receiving all data: Done (62B)
[*] Stopped remote process 'fd' on pwnable.kr (pid 333931)
[+] good job :)
    mommy! I think I know what a file descriptor is!!
$
```

## Point

File descriptors simply are indicators or handles used to access a file or i/o (input/output) resource. File descriptors are represented in `C` as integers and there are 3 types of file descriptors:

- `stdin`, its integer value is `0`
- `stdout`, its integer value is `1`
- `stderr`, its integer value is `2`
