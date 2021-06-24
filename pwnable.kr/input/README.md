# input

## Description

```Text
Mom? how can I pass my input to a computer program?

ssh input2@pwnable.kr -p2222 (pw:guest)
```

## Analysis

```Shell
root@pwn:/ctf/work# ssh input2@pwnable.kr -p2222
...
input2@pwnable:~$ ls -al
total 44
drwxr-x---   5 root       input2  4096 Oct 23  2016 .
drwxr-xr-x 115 root       root    4096 Dec 22 08:10 ..
d---------   2 root       root    4096 Jun 30  2014 .bash_history
-r--r-----   1 input2_pwn root      55 Jun 30  2014 flag
-r-sr-x---   1 input2_pwn input2 13250 Jun 30  2014 input
-rw-r--r--   1 root       root    1754 Jun 30  2014 input.c
dr-xr-xr-x   2 root       root    4096 Aug 20  2014 .irssi
drwxr-xr-x   2 root       root    4096 Oct 23  2016 .pwntools-cache
input2@pwnable:~$
```

Without the permission to the flag, let’s take a look at the source:

```C
// input.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
	if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");

	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");
	return 0;
}
```

As we can see, the code contains five parts that need to be solved.

### argv

```C
	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");
```

Described here is that 100 parameters are required, and we have to make sure that `argv['A'] == "\x00"` and `argv['B'] == "\x20\x0a\x0d"`.

```C
#include <stdio.h>
#include <unistd.h>

int main(){
	char *argv[101] = {"/home/input2/input", [1 ... 99] = "A", NULL};
	argv['A'] = "\x00";
	argv['B'] = "\x20\x0a\x0d";

	char *envp[]={0,NULL};
	execve("/home/input2/input",argv,envp);

	return 0;
}
```

```Shell
input2@pwnable:/tmp/xie$ ls
part1  part1.c
input2@pwnable:/tmp/xie$ ./part1
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
```

### stdio

```C
	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
	if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
```

`read(0, buf, 4);` reads from `stdin` and `read(2, buf, 4);` reads from `stderr`.

```C
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(){
	char *argv[101] = {"/home/input2/input", [1 ... 99] = "A", NULL};
	argv['A'] = "\x00";
	argv['B'] = "\x20\x0a\x0d";
	char *envp[]={0,NULL};

	int fd_0[2];
	int fd_2[2];

	pid_t child;
	if (pipe(fd_0)<0||pipe(fd_2)<0)
	{
		perror("error");
	}

	write(fd_0[1],"\x00\x0a\x00\xff",4);
	write(fd_0[1],"\x00\x0a\x02\xff",4);
	dup2(fd_0[0],0);
	dup2(fd_0[0],2);
	execve("/home/input2/input",argv,envp);

	return 0;
}
```

```Shell
input2@pwnable:/tmp/xie$ ls
part1  part1.c	part2  part2.c
input2@pwnable:/tmp/xie$ ./part2
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
Stage 2 clear!
Segmentation fault (core dumped)
input2@pwnable:/tmp/xie$
```

### env

```C
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");
```

Set the environment variable as `"\xde\xad\xbe\xef = \xca\xfe\xba\xbe"`.

```C
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(){
	char *argv[101] = {"/home/input2/input", [1 ... 99] = "A", NULL};
	argv['A'] = "\x00";
	argv['B'] = "\x20\x0a\x0d";

	int fd_0[2];
	int fd_2[2];

	pid_t child;
	if (pipe(fd_0)<0||pipe(fd_2)<0)
	{
		perror("error");
	}

	write(fd_0[1],"\x00\x0a\x00\xff",4);
	write(fd_0[1],"\x00\x0a\x02\xff",4);
	dup2(fd_0[0],0);
	dup2(fd_0[0],2);

	char *envp[2] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe", NULL};
	execve("/home/input2/input",argv,envp);

	return 0;
}
```

```Shell
input2@pwnable:/tmp/xie$ ls
part1  part1.c	part2  part2.c	part3  part3.c
input2@pwnable:/tmp/xie$ ./part3
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
Stage 2 clear!
Stage 3 clear!
input2@pwnable:/tmp/xie$
```

## file

```C
	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");
```

Read a file, the expected content is `\x00\x00\x00\x00`.

```C
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(){
	char *argv[101] = {"/home/input2/input", [1 ... 99] = "A", NULL};
	argv['A'] = "\x00";
	argv['B'] = "\x20\x0a\x0d";

	int fd_0[2];
	int fd_2[2];

	pid_t child;
 
	if (pipe(fd_0)<0||pipe(fd_2)<0)
	{
		perror("error");
	}

	write(fd_0[1],"\x00\x0a\x00\xff",4);
	write(fd_0[1],"\x00\x0a\x02\xff",4);
	dup2(fd_0[0],0);
	dup2(fd_0[0],2);

	char *buff = "\x00\x00\x00\x00";
	FILE *fp = fopen("\x0a", "w");
	fwrite(buf, sizeof(buf) , 1, fp );
	fclose(fp);

	char *envp[2] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe", NULL};
	execve("/home/input2/input",argv,envp);

	return 0;
}
```

```Shell
input2@pwnable:/tmp/xie$ ls
part1  part1.c  part2  part2.c  part3  part3.c  part4  part4.c
input2@pwnable:/tmp/xie$ ./part4
Welcome to pwnable.kr
Let's see if you know how to give input to program
Just give me correct inputs then you will get the flag :)
Stage 1 clear!
Stage 2 clear!
Stage 3 clear!
Stage 4 clear!
^C
input2@pwnable:/tmp/xie
```

## network

```C
	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");
```

The socket here only needs to pass in a `\xde\xad\xbe\xef` in another shell.

```C
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define MAXLINE 100

int main(int argc, char **argv)
{
	int sockfd;

	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(1111);
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	if( (sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
	{
		perror("socket error.");
		exit(1);
	}

	if ( connect(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) < 0 )
	{
		perror("connect error.");
		exit(1);
	}

	char *bufs = ""; strcpy(bufs, "\xde\xad\xbe\xef");
	int len = strlen(bufs);
	send(sockfd, bufs, len, 0);
	close(sockfd);

	return 0;
}
```

## Solution

Write-up: [exploit.c](exploit.c), [socket.c](socket.c).

```Shell
input2@pwnable:/tmp/xie$ gcc exploit.c -o exploit
input2@pwnable:/tmp/xie$ ./exploit
```

And in another shell:

```C
input2@pwnable:/tmp/xie$ gcc socket.c -o socket
input2@pwnable:/tmp/xie$ ./socket
```
