all: RShellClient2 RShellServer2

RShellClient2: RShellClient2.c
	gcc -g -o RShellClient2 RShellClient2.c -lssl -lcrypto

RShellServer2: RShellServer2.c
	gcc -g -o RShellServer2 RShellServer2.c -lssl -lcrypto -std=c99

clean:
	-rm -f RShellClient2
	-rm -f RShellServer2
