# random

## Description

```Text
Daddy, teach me how to use random value in programming!

ssh random@pwnable.kr -p2222 (pw:guest)
```

## Analysis

```Shell
λ ssh random@pwnable.kr -p2222
random@pwnable.kr's password:
...

random@pwnable:~$ ls
flag  random  random.c
```

Without the permission to the flag, let’s take a look at the source:

```C
random@pwnable:~$ cat random.c                              
#include <stdio.h>                                          
                                                            
int main(){                                                 
        unsigned int random;                                
        random = rand();        // random value!            
                                                            
        unsigned int key=0;                                 
        scanf("%d", &key);                                  
                                                            
        if( (key ^ random) == 0xdeadbeef ){                 
                printf("Good!\n");                          
                system("/bin/cat flag");                    
                return 0;                                   
        }                                                   
                                                            
        printf("Wrong, maybe you should try 2^32 cases.\n");
        return 0;                                           
}                                                           
```

`random` is a number obtained by calling `rand()`. We need input a number `key`,  if `key ^ random == 0xdeadbeef`, we could get the flag.

In C language, if we didn't set seed by calling `srand()`, the number sequence obtained by calling `rand()` is always the same.

Try to write a demo to get the return value of `rand()` without  setting seed:

```c
random@pwnable:~$ cat /tmp/velscode/test_rand.c
#include <stdio.h>

int main()
{
        printf("%d\n", rand());
        return 0;
}
random@pwnable:~$ /tmp/velscode/test_rand
1804289383
```

We know `a^b^b == a`

so `key ^ random ^ random == 0xdeedbeef ^ random == key`

`0xdeedbeef ^ 1804289383 == -1255736440 == key`

## Solution

Write-up: [exploit.py](exploit.py).

```Shell
velscode@ubuntu:~/code/Pwn/pwnable.kr/random$ python3 exploit.py 
[+] Connecting to pwnable.kr on port 2222: Done
[*] random@pwnable.kr:
    Distro    Ubuntu 16.04
    OS:       linux
    Arch:     amd64
    Version:  4.4.179
    ASLR:     Enabled
[+] Starting remote process bytearray(b'./random') on pwnable.kr: pid 13750
[+] Receiving all data: Done (55B)
[*] Stopped remote process 'random' on pwnable.kr (pid 13750)
[+] Good!
    Mommy, I thought libc random is unpredictable...
[*] Closed connection to 'pwnable.kr'
```

## Point

https://man7.org/linux/man-pages/man3/random.3.html

> ```
> The random() function uses a nonlinear additive feedback random
>        number generator employing a default table of size 31 long
>        integers to return successive pseudo-random numbers in the range
>        from 0 to 2^31 - 1.  The period of this random number generator
>        is very large, approximately 16 * ((2^31) - 1).
> 
>        The srandom() function sets its argument as the seed for a new
>        sequence of pseudo-random integers to be returned by random().
>        These sequences are repeatable by calling srandom() with the same
>        seed value.  If no seed value is provided, the random() function
>        is automatically seeded with a value of 1.
> ```