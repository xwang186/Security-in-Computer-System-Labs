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

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
#define SERVER_IP "10.0.2.13" 
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr);printf("Error connecting the server!\n"); exit(2); }
#define CA_DIR "ca_client" 
struct sockaddr_in peerAddr;
struct addrinfo hints, *result;
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
  printf("Error setting the verify locations. \n");
  exit(0);
   }
   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);


   return ssl;
}


int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;

   // Get the IP address from hostname
   hints.ai_family = AF_INET;
   //struct hostent* hp = gethostbyname(hostname);
   int error = getaddrinfo(hostname, NULL, &hints, &result);
   if (error) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    exit(1);
   }

// The result may contain a list of IP address; we take the first one.
struct sockaddr_in* ip = (struct sockaddr_in *) result->ai_addr;
printf("IP Address: %s\n", (char *)inet_ntoa(ip->sin_addr));
freeaddrinfo(result);
   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   server_addr.sin_addr.s_addr = inet_addr ((char *)inet_ntoa(ip->sin_addr));
/*
   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
//   server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
*/
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));

   return sockfd;
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

void tunSelected(int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    read(tunfd, buff, sizeof(buff));
    SSL_write(ssl, buff, sizeof(buff));
}

void socketSelected (int tunfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    SSL_read(ssl, buff, sizeof(buff));
    write(tunfd, buff, sizeof(buff));


}
void logIn(SSL* ssl){
     printf("Please type in your username and password\n");
   printf("Your Username:");
   char username[BUFF_SIZE];
   scanf("%s",username);
   SSL_write(ssl, username,BUFF_SIZE);
   char *password;
  //printf("Your password:");
    password=getpass("Your password:");
    SSL_write(ssl, password, BUFF_SIZE);
    printf("logIn successful!!\n");
}
int main (int argc, char * argv[]) {

   char *hostname = "wang.com";
   int port = 4433;
int tunfd  = createTunDevice();
  
   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);

   /*----------------TLS initialization ----------------*/
   SSL *ssl   = setupTLSClient(hostname);

   /*----------------Create a TCP connection ---------------*/
   int sockfd = setupTCPClient(hostname, port);
   
   /*----------------Check Username and password ---------------*/
   SSL_set_fd(ssl, sockfd);

   
   /*----------------TLS handshake ---------------------*/

   int err = SSL_connect(ssl); CHK_SSL(err);
   printf("SSL connection is successful\n");
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
   
   logIn(ssl);

   char test[BUFF_SIZE];
   SSL_read(ssl, test, BUFF_SIZE);
    printf("Receive the confirm. The VPN Started!!\n");
   //SSL_read(ssl,test,BUFF_SIZE);
   /*----------------Send/Receive data --------------------*/

   //sprintf(sendBuf, "GET / HTTP/1.1\nHost: %s\n\n", hostname);
       
   while (1) {
   fd_set readFDSet;
   FD_ZERO(&readFDSet);
   FD_SET(sockfd, &readFDSet);
   FD_SET(tunfd, &readFDSet);
   select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
   if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
   if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, ssl);
  }
}
 
