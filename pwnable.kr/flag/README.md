# flag

## Description

```Text
Papa brought me a packed present! let's open it.

Download : http://pwnable.kr/bin/flag

This is reversing task. all you need is binary
```

## Analysis

Firstly, Confirm the file's type. We could use `file` like this:

```shell
$ file flag 
flag: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
```

Obviously, this is an executable file, but the symbols has been stripped, which means that there are no enough debugging infomations for GDB debugging

Execute it:

```shell
$ ./flag 
I will malloc() and strcpy the flag there. take it.
```

> See here, I've tried to use LD_PRELOAD to inject strcpy() to print out parameters. But this file is statically linked, so this method is useless

Use `ltrace` and `strace`, but there is also no useful information

Use `strings` to review the strings in the file.

```shell
$ strings ./flag 
UPX!
@/x8
gX lw_
H/\_@
	Kl$
H9\$(t
[]]y
nIV,Uh
......
```

there are too many content! So we add a parameter to filter the length of the string:

```shell
velscode@ubuntu:~/code$ strings -20 flag
_~SO/IEC 14652 i18n FDC
*+,-./0>3x6789:;<=>?
@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
`abcdefghijklmnopqrstuvwxyz{|}~
 "9999$%&/999956799999:<DG9999HI_`
 ''''!#$`''''abcd''''efgh''''ijkl''''mnop''''qrst''''uvwx''''yz{|''''}~
Q2R''''STUV''''WXYZ''''[\]^''''_
MNONNNNPRTUNNNNVWYZNNNN[\_`NNNNabcdNNNNefhi
 rrrr!"#$rrrr%&'(rrrr)*+,rrrr-./0rrrr1234rrrr5678rrrr9;<=rrrr>@ABrrrrCDFJrrrrKLMNrrrrOPRSrrrrTUVWrrrrXYZ[rrrr\]^_rrrr`abcrrrrdefgrrrrhijkrrrrlmnorrrrpqrsrrrrtuvwrrrrxyz{rrrr|}~
 !"9999#$%&9999'()*9999+,-.9999/012999934569999789:9999;<=>9999?@AB9999CDEF9999GHIJ9999KLMN9999OPQR9999STUV9999WXYZ9999[\]^9999_`ab9999cdef9999ghij9999klmn9999opqr9999stuv9999wxyz9999{|}~9999
'12Wr%W345%Wr%67x!Wr892
b'cdr%WrefgWr%Whij%Wr%klr%WrmnoWr%Wpqr%Wr%str%WruvwWr%Wxyz%Wr%ABr%WrCDEWr%WFGH%Wr%IJr%WrKLMWr%WNOP%Wr%QRr%WrSTUWr%WVWX%Wr%YZ
 $9999(/6>9999HQXa9999eimq9999uy}
&9223372036854775807L`
PROT_EXEC|PROT_WRITE failed.
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.08 Copyright (C) 1996-2011 the UPX Team. All Rights Reserved. $
GCC: (Ubuntu/Linaro 4.6.3-1u)#

```

We get a key message:

`This file is packed with the UPX executable packer http://upx.sf.net`

Install upx & decompress it:

```
$ apt-get install upx
$ upx -d  ./flag
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2013
UPX 3.91        Markus Oberhumer, Laszlo Molnar & John Reiser   Sep 30th 2013

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    887219 <-    335288   37.79%  linux/ElfAMD   flag

Unpacked 1 file.
```

Use `strings` to view the file again:

```shell
$ strings -20 ./flag 
UPX...? sounds like a delivery service :)
I will malloc() and strcpy the flag there. take it.
FATAL: kernel too old
FATAL: cannot determine kernel version
cannot set %fs base address for thread-local storage
unexpected reloc type in static binary
======= Backtrace: =========
======= Memory map: ========
(p->prev_size == offset)
...
```

Get the flag :)

## Point

UPX is a free, portable, extendable, high-performance executable packer for several executable formats.