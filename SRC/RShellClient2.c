#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <string.h>
#include <time.h>

//#define DEBUG

int
clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

/* version that support IPv6 
	else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1) 
*/

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;

	return sock;
}
int 
clientTCPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_STREAM, destination, portN);
}


int 
clientUDPsock(const char *destination, int portN) 
{
  return clientsock(SOCK_DGRAM, destination, portN);
}


#define	LINELEN		128
#define resultSz	4096

void usage(char *self)
{
	fprintf(stderr, "Usage: %s destination port\n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf

 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------
 */
int
TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0; 
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;

#ifdef DEBUG
	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, buf);
#endif /* DEBUG */

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{ 
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;
		
#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n", 
			   sock, buflen, flag, n, &buf[inbytes]);
#endif /* DEBUG */

	  if (n<=0) /* no more bytes to receive */
		break;
	};

#ifdef DEBUG
		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n", 
			   sock, buflen, inbytes, buf);
#endif /* DEBUG */

	return inbytes;
}

int
RemoteShell(char *destination, int portN, char *user)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	char	result[resultSz+1];
	char    nonce2Str[10];
	int	sock;				/* socket descriptor, read count*/
	int nonce2;


	int	outchars, inchars;	/* characters sent and received	*/
	int n;

	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

	printf("SENDING RSHELL_REQ\n");
	send(sock, user, strlen(user), 0);
	printf("SENDING AUTH_RESP\n");
	if ((inchars=recv(sock, result, resultSz, 0))>0) /* got some result */
		{
			result[inchars]=0;	
			nonce2 = atoi(result);

		}
		if (inchars < 0)
				errmesg("socket read failed\n");
		
	printf("We got Server Nonce: %d\n", nonce2);

	while (fgets(buf, sizeof(buf), stdin)) 
	{
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		printf("BUF: %s\n", buf);
		if ((n=write(sock, buf, outchars))!=outchars)	/* send error */
		{
#ifdef DEBUG
			printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s`\n", 
			   destination, portN, n, outchars, buf);
#endif /* DEBUG */
			close(sock);
			return -1;
		}
#ifdef DEBUG
		printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`\n", 
			   destination, portN, n, buf);
#endif /* DEBUG */

		/* Get the result */

		if ((inchars=recv(sock, result, resultSz, 0))>0) /* got some result */
		{
			result[inchars]=0;	
			fputs(result, stdout);			
		}
		if (inchars < 0)
				errmesg("socket read failed\n");
	}

	close(sock);
	return 0;
}

/*------------------------------------------------------------------------
 * main  *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
	char *destination;
	int  portN;
	char *user;
	char *pass;
	char tmp[50];
	char tmp2[50];
	char nonce1[50];

	srand(time(0));

	sprintf(nonce1, "%d", rand() % 100);


	if (argc==5)
	{ 
	  destination = argv[1];
	  portN = atoi(argv[2]);
	  strcpy(tmp, "; ");
	  strcpy(tmp2, "; ");
	  user = argv[3];
	  pass = argv[4];
	}
	else usage(argv[0]);

	printf("%s\n", user);
	printf("%s\n", pass);
	printf("%s\n", nonce1);

	strcat(tmp2, nonce1);
	strcat(pass, tmp2);
	strcat(tmp, pass);
	strcat(user, tmp);

	printf("%s\n", user);

	RemoteShell(destination, portN, user);

	exit(0);
}