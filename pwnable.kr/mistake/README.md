# mistake

## Description

```Text
We all make mistakes, let's move on.
(don't take this too seriously, no fancy hacking skill is required at all)

This task is based on real event
Thanks to dhmonkey

hint : operator priority

ssh mistake@pwnable.kr -p2222 (pw:guest)
```

## Analysis

```Shell
λ ssh mistake@pwnable.kr -p2222
mistake@pwnable.kr's password:
.....

mistake@pwnable:~$ ls -al
-r--------   1 mistake_pwn root      51 Jul 29  2014 flag
-r-sr-x---   1 mistake_pwn mistake 8934 Aug  1  2014 mistake
-rw-r--r--   1 root        root     792 Aug  1  2014 mistake.c
-r--------   1 mistake_pwn root      10 Jul 29  2014 password
```

Without the permission to the flag, let’s take a look at the source:

```C
mistake@pwnable:~$ cat mistake.c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
        int i;
        for(i=0; i<len; i++){
                s[i] ^= XORKEY;
        }
}

int main(int argc, char* argv[]){

        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
                printf("can't open password %d\n", fd);
                return 0;
        }

        printf("do not bruteforce...\n");
        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                system("/bin/cat flag\n");
        }
        else{
                printf("Wrong Password\n");
        }

        close(fd);
        return 0;
}

```

**Process analysis**

1. Open and read the file `./password`, which stores the correct answers, and read the data to pw_buf`(length: 11bytes). Interestingly, a random sleep is added to prevent brute force cracking.
2. Read user input and store it to `pw_buf2`(length: 11 bytes)
3. XOR `pw_buf2`(length: 10 bytes)
4. Compare `pw_buf` and `pw_buf2`, if same, output flag

**Our Target**

Find a input(`pw_buf2`), which as same as password(`pw_buf`) after xor with `XORKEY`.

But ! `pw_buf2` is unkown for us. So we need to find a way to rewrite it:, maybe`buffer overflow`?

If you think like that, you fall into a trap!

-----

Notice this tip

> hint : operator priority

**The comparison operator takes precedence over the assignment operator**

**The comparison operator takes precedence over the assignment operator**

**The comparison operator takes precedence over the assignment operator**

Important things need to be repeated for 3 times(重要的事情说三遍).

```c
if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){...}
```

Equivalent to:

```c
int tmp = open("/home/mistake/password",O_RDONLY,0400);
fd = (tmp < 0)
```

Due to `open()` is success，so `tmp` is a positive number.

∴ `(tmp < 0)` == 0

∴`fd` == 0

So `if(fd)` ==> `if(0)`, will not print "open error".

-----

```c
if(!(len=read(fd,pw_buf,PW_LEN) > 0)) {...}
```

Equivalent to

```c
int tmp = read(0,pw_buf,PW_LEN); // read input from stdin
len = (tmp > 0)
if (!len) {...}
```

∵ `read()` is success

∴`tmp` > 0

∴`len` == `tmp > 0` == 1

∴`if (!len)` ==> `if (!1)` ==> `if(0)`

So will not print "read error".

-----

Now the question turns to thus:

1. We need to input two string: `A` and `B`. 
2. `A` XOR `1` byte by byte to get `A'`
3. Make sure that `A'` is same as `B`

A and B are easy to construct,  such as

`A` : "2222222222"

`B` : "3333333333"

because `0x32 xor 1 == 0x33`

## Solution

Write-up: [exploit.py](exploit.py)

```Shell
λ python exploit.py
C:\Python27\lib\site-packages\paramiko-2.7.2-py2.7.egg\paramiko\transport.py:33: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends import default_backend
[x] Connecting to pwnable.kr on port 2222
[+] Connecting to pwnable.kr on port 2222: Done
[*] mistake@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[x] Starting remote process bytearray(b'./mistake') on pwnable.kr
[+] Starting remote process bytearray(b'./mistake') on pwnable.kr: pid 313386
[x] Receiving all data
[x] Receiving all data: 0B
[x] Receiving all data: 21B
[x] Receiving all data: 101B
[+] Receiving all data: Done (101B)
[*] Stopped remote process u'mistake' on pwnable.kr (pid 313386)
[+] do not bruteforce...
    input password : Password OK
    Mommy, the operator priority always confuses me :(
[*] Closed connection to 'pwnable.kr'
```
