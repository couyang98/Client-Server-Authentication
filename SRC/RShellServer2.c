#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <openssl/sha.h>
#include <time.h>

#define DEBUG

int
serversock(int UDPorTCP, int portN, int qlen)
{
	struct sockaddr_in svr_addr;	/* my server endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/

	if (portN<0 || portN>65535 || qlen<0)	/* sanity test of parameters */
		return -2;

	bzero((char *)&svr_addr, sizeof(svr_addr));
	svr_addr.sin_family = AF_INET;
	svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
	svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Bind the socket */
	if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
		return -4;

	if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
		return -5;

	return sock;
}

int 
serverTCPsock(int portN, int qlen) 
{
  return serversock(SOCK_STREAM, portN, qlen);
}


int 
serverUDPsock(int portN) 
{
  return serversock(SOCK_DGRAM, portN, 0);
}


void 
usage(char *self)
{
	fprintf(stderr, "Usage: %s port\n", self);
	exit(1);
}

void 
errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void
reaper(int signum)
{
/*
	union wait	status;
*/

	int status;

	while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
		/* empty */;
}

/*------------------------------------------------------------------------
 *  This is a very simplified remote shell, there are some shell command it 
	can not handle properly:

	cd
 *------------------------------------------------------------------------
 */
int
RemoteShellD(int sock, char *user, char *pass, char nonce2[50])
{
#define	BUFSZ		128
#define resultSz	4096
	char cmd[BUFSZ+20];
	char result[resultSz];
	int	cc, len;
	int rc=0;
	FILE *fp;
	char *receiverStr;
	char tmp[BUFSZ+20];

	char uBuff[1024];
	char *tUser;
	char *tPass;
	char passBuff[SHA_DIGEST_LENGTH * 2];

	recv(sock, uBuff, 1024, 0);
	printf("%s\n", uBuff);



	tUser = strtok(uBuff, "; ");
	tPass = strtok(NULL, "; ");

	printf("SENDING AUTH_CHLG\n");
	printf("SERVER NONCE2: %s\n", nonce2);
	write(sock, nonce2, 50);

	unsigned char hash[20];
	SHA1((unsigned char *)tPass, sizeof(tPass), hash);
	for(int j = 0; j < 20; j++) {
		sprintf((char*)&(passBuff[j*2]), "%02x", hash[j]);
	}
	printf("The hex of sha1: %s\n", passBuff);

	if(strcmp(tUser, user) == 0) {
		if(strcmp(passBuff, pass) == 0) {
			printf("AUTH_SUCESS\n");
		} else {
			errmesg("AUTH_FAIL\n");
		}
	} else {
		errmesg("User does not exist!\n");
	}

#ifdef DEBUG
	printf("***** RemoteShellD(sock=%d) called\n", sock);
#endif

	
	//Trying to send the nonces with the command was giving me wonky results, not sure if its cause of the bytes being sent
	//I tried sending nonces seperately but something was off
	//Tried to tokenize cmd, but couldnt work, forgot that cc saves all they bytes sent
	while ((cc = read(sock, cmd, BUFSZ+20)) > 0)	/* received something */
	{	
		if (cmd[cc-1]=='\n')
			cmd[cc-1]=0;
		else cmd[cc] = 0;

#ifdef DEBUG
		printf("***** RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);
#endif

		strcat(cmd, " 2>&1");
#ifdef DEBUG
	printf("***** cmd: `%s`\n", cmd); 
#endif 
		if ((fp=popen(cmd, "r"))==NULL)	/* stream open failed */
			return -1;

		/* stream open successful */

		while ((fgets(result, resultSz, fp)) != NULL)	/* got execution result */
		{
			len = strlen(result);
			printf("***** sending %d bytes result to client: \n`%s` \n", len, result);

			if (write(sock, result, len) < 0)
			{ rc=-1;
			  break;
			}
		}
		fclose(fp);

	}

	if (cc < 0)
		return -1;

	return rc;
}

/*------------------------------------------------------------------------
 * main - Concurrent TCP server 
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	int	msock;			/* master server socket		*/
	int	ssock;			/* slave server socket		*/
	int portN;			/* port number to listen */
	FILE *f;
	char str[100];
	char *user;
	char *pass;
	char nonce2[50];

	struct sockaddr_in fromAddr;	/* the from address of a client	*/
	unsigned int  fromAddrLen;		/* from-address length          */
	int  prefixL, r;

	if (argc==3) {
		portN = atoi(argv[1]);
		f = fopen(argv[2], "r");
	} else {
		usage(argv[0]);
	}

	srand(time(0));
	sprintf(nonce2, "%d", rand() % 100);

	fgets(str, 100, f);
	user = strtok(str, "; ");
	pass = strtok(NULL, "; ");


	msock = serverTCPsock(portN, 5);


	(void) signal(SIGCHLD, reaper);

	while (1) 
	{
		fromAddrLen = sizeof(fromAddr);

		ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);

		if (ssock < 0) {
			if (errno == EINTR)
				continue;
			errmesg("accept error\n");
		}



		switch (fork()) 
		{
			case 0:		/* child */
				close(msock);
				r=RemoteShellD(ssock, user, pass, nonce2);
				close(ssock);
				exit(r);

			default:	/* parent */
				(void) close(ssock);
				break;
			case -1:
				errmesg("fork error\n");
		}
	}
	close(msock);
}
