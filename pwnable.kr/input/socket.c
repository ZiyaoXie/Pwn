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
