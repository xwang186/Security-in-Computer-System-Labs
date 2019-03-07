all: 
	gcc -o tlsclient tlsclient.c -lssl -lcrypto 
	gcc -o tlsserver tlsserver.c -lssl -lcrypto
	gcc -o vserver vpntlsserver.c -lssl -lcrypto -lcrypt
	gcc -o vclient vpntlsclient.c -lssl -lcrypto
clean: 
	rm tlsclient tlsserver vpntlsserver

