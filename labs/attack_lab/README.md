# [Attack Lab](http://csapp.cs.cmu.edu/3e/labs.html) [Updated 1/12/16]

Note: This is the 64-bit successor to the 32-bit Buffer Lab. You are given a pair of unique custom-generated x86-64 binary executables, called targets, that have buffer overflow bugs. One target is vulnerable to code injection attacks. The other is vulnerable to return-oriented programming attacks.

You are asked to modify the behavior of the targets by developing exploits based on either code injection or return-oriented programming. This lab is about the stack discipline and the danger of writing code that is vulnerable to buffer overflow attacks.

Here are a pair of Ubuntu 12.4 targets that you can try out for yourself. You'll need to run your targets using the "-q" option so that they don't try to contact a non-existent grading server.

## Source

Here are a pair of Ubuntu 12.4 targets in `source/`, more details in [README](source/README.txt).

```Shell
source
├── README.txt # A file describing the contents of the directory
├── cookie.txt # An 8-digit hex code that you will use as a unique identifier in your attacks
├── ctarget    # An executable program vulnerable to code-injection attacks
├── farm.c     # The source code of your target’s “gadget farm,” which you will use in generating return-oriented programming attacks
├── hex2raw    # A utility to generate attack strings
└── rtarget    # An executable program vulnerable to return-oriented-programming attacks
```

## Part I: Code Injection Attacks

For the first three phases, your exploit strings will attack CTARGET. This program is set up in a way that the stack positions will be consistent from one run to the next and so that data on the stack can be treated as executable code. These features make the program vulnerable to attacks where the exploit strings contain the byte encodings of executable code.

### Level 1

For Phase 1, you will not inject new code. Instead, your exploit string will redirect the program to execute an existing procedure.

Function `getbuf` is called within `CTARGET` by a function `test` having the following `C` code:

```C
void test()
{
    int val;
    val = getbuf();
    printf("No exploit. Getbuf returned 0x%x\n", val);
}
```

When `getbuf` executes its return statement (line 5 of `getbuf`), the program ordinarily resumes execution within function `test` (at line 5 of this function). We want to change this behavior. Within the file `ctarget`, there is code for a function `touch1` having the following `C` representation:

```C
void touch1()
{
    vlevel = 1; /* Part of validation protocol */
    printf("Touch1!: You called touch1()\n");
    validate(1);
    exit(0);
}
```

Your task is to get `CTARGET` to execute the code for `touch1` when `getbuf` executes its return statement, rather than returning to `test`. Note that your exploit string may also corrupt parts of the stack not directly related to this stage, but this will not cause a problem, since `touch1` causes the program to exit directly.

### Level 2

Phase 2 involves injecting a small amount of code as part of your exploit string.

Within the file `ctarget` there is code for a function `touch2` having the following `C` representation:

```C
void touch2(unsigned val)
{
    vlevel = 2; /* Part of validation protocol */
    if (val == cookie) 
    {
        printf("Touch2!: You called touch2(0x%.8x)\n", val);
        validate(2);
    }
    else 
    {
        printf("Misfire: You called touch2(0x%.8x)\n", val);
        fail(2);
    } 
    exit(0);
}
```

Your task is to get `CTARGET` to execute the code for `touch2` rather than returning to `test`. In this case, however, you must make it appear to `touch2` as if you have passed your cookie as its argument.

### Level 3

Phase 3 also involves a code injection attack, but passing a string as argument.

Within the file `ctarget` there is code for functions hexmatch and `touch3` having the following `C` representations:

```C
/* Compare string to hex represention of unsigned value */
int hexmatch(unsigned val, char *sval)
{
    char cbuf[110];
    /* Make position of check string unpredictable */
    char *s = cbuf + random() % 100;
    sprintf(s, "%.8x", val);
    return strncmp(sval, s, 9) == 0;
}

void touch3(char *sval)
{
    vlevel = 3; /* Part of validation protocol */
    if (hexmatch(cookie, sval)) {
        printf("Touch3!: You called touch3(\"%s\")\n", sval);
        validate(3);
    } else {
        printf("Misfire: You called touch3(\"%s\")\n", sval);
        fail(3);
    }
    exit(0);
}
```

Your task is to get `CTARGET` to execute the code for `touch3` rather than returning to `test`. You must make it appear to `touch3` as if you have passed a string representation of your `cookie` as its argument.

### Writeups 

[Writeups](part1/README.md) for Part I.

