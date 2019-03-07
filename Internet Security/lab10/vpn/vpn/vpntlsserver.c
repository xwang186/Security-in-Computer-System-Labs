#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <shadow.h>
#include <crypt.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CA_file "./my_cert/server.crt"
#define Key_file "./my_cert/server.key"

int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}

int tunSelected(int tunfd, SSL *ssl){
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    read(tunfd, buff, sizeof(buff));
    SSL_write(ssl, buff, sizeof(buff));
    return 1;
}

int socketSelected (int tunfd, SSL *sockfd){
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);

    SSL_read(sockfd, buff, sizeof(buff));
    write(tunfd, buff, sizeof(buff));
    return 1;

}
int login(char *user, char *passwd)
{
	printf("A new user is connecting:\n");
	printf("Login name: %s\n", user);
	printf("Passwd : %s\n", passwd);
	struct spwd *pw;
	char *epasswd;
	pw = getspnam(user);

	if (pw == NULL) {
		printf("The new user has wrong username, so the connection closed!\n");
	return -1;
	}

	epasswd = crypt(passwd, pw->sp_pwdp);
	if (strcmp(epasswd, pw->sp_pwdp)) {
		printf("The new user has wrong password, so the connection closed!\n");
	return -1;
}
printf("The new user is connected!\n");
return 1;
}
int verifyUser(SSL* ssl){
	   int len1=0;
       printf("Receive a packet!!!\n");
       char username[BUFF_SIZE];
       len1=SSL_read(ssl, username, BUFF_SIZE);
       printf("recv the username!\n");
       //send(sock, recvData, 255, 0);
       username[len1]='\0';
       //char username[255];       
       //strcpy(username,recvData);
       char password[BUFF_SIZE];
       SSL_read(ssl, password, BUFF_SIZE);
       //password[len2]='\0';
       printf("recv the password!\n");
       int m=login(username,password);
       char sendBuf[200];
       if(m==1){
       sprintf(sendBuf, "hi");
       }
       else{
        sprintf(sendBuf,"no");
       }
       SSL_write(ssl,sendBuf,strlen(sendBuf));
       return m;
}
int main () {

   SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;

  // Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  // Step 1: SSL context initialization
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, CA_file , SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, Key_file, SSL_FILETYPE_PEM);
  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);
    int tunfd;
    tunfd  = createTunDevice();
  //SSL* ssl=setupTLSServer();
  struct sockaddr_in sa_client;
  size_t client_len;
  int listen_sock = setupTCPServer();
    while(1){
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    if (fork() == 0) { // The child process
       SSL_set_fd (ssl, sock);
       close (listen_sock);
       printf("Receive a packet!!!\n");
       int err = SSL_accept (ssl);
       CHK_SSL(err);
       printf ("SSL connection established!\n");
       
       if(verifyUser(ssl)<0){
        close(sock);
        exit(2);
       }
       
       //vertigy
       while(1){
        fd_set readFDSet;
     	FD_ZERO(&readFDSet);
	    FD_SET(sock, &readFDSet);
	    FD_SET(tunfd, &readFDSet);
    	select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     	if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);

      if (FD_ISSET(sock,  &readFDSet)) socketSelected(tunfd, ssl);

   }
       close(sock);
       return 0;
    } else { // The parent process
       close(sock);
    	}

}
	
 }
 
