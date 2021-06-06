# collision

## Description

```txt
Daddy told me about cool MD5 hash collision today.
I wanna do something like that too!

ssh col@pwnable.kr -p2222 (pw:guest)
```

## Analysis

```shell
$ ssh col@pwnable.kr -p2222
col@pwnable.kr's password:
...

Last login: Sun Jun  6 11:09:10 2021 from 112.36.209.23
col@pwnable:~$ ls -l
total 16
-r-sr-x--- 1 col_pwn col     7341 Jun 11  2014 col
-rw-r--r-- 1 root    root     555 Jun 12  2014 col.c
-r--r----- 1 col_pwn col_pwn   52 Jun 11  2014 flag
col@pwnable:~$
col@pwnable:~$
col@pwnable:~$ uname -a
Linux pwnable 4.4.179-0404179-generic #201904270438 SMP Sat Apr 27 08:41:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
col@pwnable:~$ lscpu | grep -i byte
Byte Order:            Little Endian
col@pwnable:~$
```

Without the permission to the flag, let’s take a look at the source:

```C
// col.c

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

So we need our input to be 20 bytes length and we also need to make the function `check_password()` return `0x21DD09EC` when our input is given to it.

This function `check_password()` casts the given passcode(`p`) into integer, declares `ip` which is an array of pointers starting with the pointer to `p`, and declares an `int` variable called `res`. It loops 5 times through `ip` (because length of passcode is 20, `20/4 == 5`) and adds each value to `res`, finally it returns `res`.

```Shell
$ python3
Python 3.9.5 (default, May  4 2021, 03:36:27)
[Clang 12.0.0 (clang-1200.0.32.29)] on darwin
Type "help", "copyright", "credits" or "license" for more information.

# As the `hashcode` is a hex value, let’s convert it to decimal with python
>>> 0x21DD09EC
568134124

# Divide the original value by 5
>>> 568134124/5
113626824.8
>>> 568134124%5
4

# We got 568134124 = 113626824 * 4 + 113626828, and then convert them to hex
>>> hex(113626824)
'0x6c5cec8'
>>> hex(113626828)
'0x6c5cecc'
```

Notice that it’s little endian and we should reverse the order, final payload will be:

```Text
python -c 'print "\xc8\xce\xc5\x06" * 4 + "\xcc\xce\xc5\x06"'
```

## Solution

Write-up: [exploit.py](exploit.py).

```Shell
$ python3 pwnable.kr/collision/exploit.py
[+] Connecting to pwnable.kr on port 2222: Done
[*] fd@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Starting remote process './col' on pwnable.kr: pid 37478
[+] Receiving all data: Done (52B)
[*] Stopped remote process 'col' on pwnable.kr (pid 37478)
[+] daddy! I just managed to create a hash collision :)
[*] Closed connection to 'pwnable.kr'
$
```
